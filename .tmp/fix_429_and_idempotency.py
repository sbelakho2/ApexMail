#!/usr/bin/env python3
"""
Safely add 429 RateLimitError responses and Idempotency-Key header documentation
to the OpenAPI spec.

Strategy:
  - Line-by-line processing (no YAML parsing/formatting)
  - Track indentation state to know when we're inside a responses block
  - For Finding 6: add 429 to every responses block that doesn't have it
  - For Finding 7: add Idempotency-Key header parameter to POST/PUT/PATCH/DELETE
"""

import re
import sys

FILE = "docs/api/openapi.yaml"

# Pattern to detect the start of an operation (method line under a path)
METHOD_RE = re.compile(r'^\s{4}(get|post|put|patch|delete|options|head):$')

# Pattern to detect responses: block
RESPONSES_RE = re.compile(r'^\s{6}responses:$')

# Pattern to detect a response status code line
RESP_CODE_RE = re.compile(r"^\s{8}'(?:\d{3}|\dXX)':")

# Pattern to detect 429 explicitly
RATE_LIMIT_RE = re.compile(r"^\s{8}'429':")

# Pattern to detect parameters: block
PARAMS_RE = re.compile(r'^\s{6}parameters:')

# Pattern to detect security: block  
SECURITY_RE = re.compile(r'^\s{6}security:')

# Pattern to detect requestBody: block
REQUEST_BODY_RE = re.compile(r'^\s{6}requestBody:')

# Pattern to detect tags: block
TAGS_RE = re.compile(r'^\s{6}tags:')

# Pattern to detect operationId
OP_ID_RE = re.compile(r'^\s{8}operationId:\s*(\S+)')

# Pattern to detect description: block start
DESC_PROP_RE = re.compile(r'^\s{8}\w+:')


def process_file():
    with open(FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    result = []
    
    # State tracking
    inside_responses = False        # True when we're inside a responses: block
    responses_have_429 = False      # True if this responses block already has 429
    responses_indent_level = -1     # Indentation of the first response code
    
    # For adding Idempotency-Key
    current_method = None           # Current operation's HTTP method
    current_op_id = None            # Current operation's operationId
    inside_operation = False        # True when we're inside an operation
    op_indent = -1                  # Indentation of the operation
    seen_security = False           # Whether this operation has a security block
    seen_tags = False               # Whether this operation has a tags block
    seen_params = False             # Whether this operation has a parameters block
    seen_request_body = False       # Whether this operation has a requestBody
    seen_operation_id = False       # Whether we've seen operationId
    inside_params = False           # Inside parameters block
    inside_tags = False             # Inside tags block
    inside_security = False         # Inside security block
    params_indent_level = -1        # Indentation inside parameters block
    added_params_this_op = False    # Whether we've already added params for this op
    line_num = 0
    
    # Idempotency-Key param entry to insert (at indent 8 under parameters:)
    IDEM_KEY_PARAM = (
        '        - name: Idempotency-Key\n'
        '          in: header\n'
        '          required: false\n'
        '          description: |\n'
        '            Idempotency key. If a request with the same key was processed within the\n'
        '            idempotency window (configurable, typically 5 minutes), the cached response\n'
        '            is returned without re-execution. Idempotency is scoped to the authenticated\n'
        '            principal — two different API keys cannot replay each other\'s requests.\n'
        '          schema:\n'
        '            type: string\n'
        '            format: uuid\n'
        '          example: 7a8e3b1c-9d4f-4e2a-b6c8-1d2e3f4a5b6c\n'
    )
    
    for raw_line in lines:
        line_num += 1
        stripped = raw_line.rstrip('\n')
        leading = len(raw_line) - len(raw_line.lstrip())
        
        # ── Detect operation boundaries ────────────────────────
        method_match = METHOD_RE.match(stripped)
        if method_match and leading == 4:
            # Starting a new operation - reset state
            current_method = method_match.group(1)
            inside_operation = True
            op_indent = leading
            seen_security = False
            seen_tags = False
            seen_params = False
            seen_request_body = False
            seen_operation_id = False
            inside_params = False
            inside_tags = False
            inside_security = False
            added_params_this_op = False
            current_op_id = None
            inside_responses = False
            responses_have_429 = False
            
            result.append(raw_line)
            continue
        
        # ── Detect leaving current operation ──────────────────
        # A new path starts at indent 0, or a new operation starts at indent 4
        if inside_operation and (leading <= 2 or (leading == 4 and METHOD_RE.match(stripped))):
            if leading <= 2 and leading != op_indent:
                inside_operation = False
                current_method = None
                current_op_id = None
            elif leading == 4 and METHOD_RE.match(stripped):
                # New operation starting - handle this after we write current line
                pass
        
        # ── Detect operationId ────────────────────────────────
        if inside_operation:
            op_match = OP_ID_RE.match(stripped)
            if op_match:
                current_op_id = op_match.group(1)
                seen_operation_id = True
        
        # ── Detect tags block ──────────────────────────────────
        if inside_operation and TAGS_RE.match(stripped):
            seen_tags = True
            inside_tags = True
        
        # ── Detect end of tags block ───────────────────────────
        if inside_tags and not inside_params:
            if leading <= 6 and leading != 8:
                inside_tags = False
            # A blank line or a line at indent 6 or less ends the tags block
            if stripped.strip() == '' or leading <= 6:
                # Check if this line actually ends the tags block
                if leading <= 6 and leading >= 6:
                    inside_tags = False
        
        # ── Detect security block ─────────────────────────────
        if inside_operation and SECURITY_RE.match(stripped):
            seen_security = True
            inside_security = True
        
        # ── Detect end of security block ──────────────────────
        if inside_security:
            if stripped.strip() == '' or leading <= 6:
                inside_security = False
        
        # ── Detect parameters block ───────────────────────────
        if inside_operation and PARAMS_RE.match(stripped):
            seen_params = True
            inside_params = True
            params_indent_level = leading
        
        # ── Detect requestBody block ──────────────────────────
        if inside_operation and REQUEST_BODY_RE.match(stripped):
            seen_request_body = True
        
        # ── Insert Idempotency-Key parameter ──────────────────
        # For POST/PUT/PATCH/DELETE operations with auth (have security or inherit global)
        # Insert after tags but before requestBody, only if parameters doesn't exist
        if (inside_operation 
            and current_method in ('post', 'put', 'patch', 'delete')
            and not added_params_this_op
            and not seen_params
            and seen_request_body is False  # We're before requestBody
            and seen_tags  # We've passed the tags block
            and seen_operation_id  # We've passed operationId
        ):
            # Check if this line is the requestBody start
            if REQUEST_BODY_RE.match(stripped):
                # Insert parameters block right before requestBody
                result.append('      parameters:\n')
                result.append(IDEM_KEY_PARAM)
                added_params_this_op = True
                seen_params = True
                result.append(raw_line)
                continue
        
        # Added params, now skip adding another parameters block
        if added_params_this_op and REQUEST_BODY_RE.match(stripped):
            result.append(raw_line)
            continue
        
        # ── Detect responses block ────────────────────────────
        if RESPONSES_RE.match(stripped):
            inside_responses = True
            responses_have_429 = False
            # Find the actual indentation of response codes
            responses_indent_level = -1
            result.append(raw_line)
            continue
        
        # ── Inside responses block ────────────────────────────
        if inside_responses:
            # Check if this response code is 429
            if RATE_LIMIT_RE.match(stripped):
                responses_have_429 = True
            
            # Check if we've left the responses block
            # Responses block ends when we hit a line at indent 6 or less (blank line or next path/operation)
            if leading <= 6 and stripped.strip() != '':
                # We've left the responses block (or hit a blank line at response level)
                # Check if 429 was present
                if not responses_have_429:
                    # Add 429 right before the closing
                    # Count existing response codes to determine where to insert
                    pass
                inside_responses = False
            
            # If we hit a blank line at indent 6, it might be within responses
            if stripped.strip() == '' and leading == 6 and inside_responses:
                # Blank line - could be separator within responses
                pass
            
            # Detect end of responses block by catching non-response lines at indent 6
            if inside_responses and leading <= 6 and stripped.strip():
                # Check if this is a continuation of a response's content (e.g., description)
                # or actually leaving the block
                if not RESP_CODE_RE.match(stripped) and leading == 8:
                    # This is content within a response (description, content, schema, etc.)
                    pass
                elif leading == 6 and not RESPONSES_RE.match(stripped):
                    # We've left responses - this is a new property at the operation level
                    if not responses_have_429:
                        # Insert 429 before this line
                        result.append("        '429':\n")
                        result.append("          $ref: '#/components/responses/RateLimitError'\n")
                    inside_responses = False
        
        # ── Handle end of responses when next path/operation starts ──
        if inside_responses and leading < 6 and stripped.strip():
            if not responses_have_429:
                result.append("        '429':\n")
                result.append("          $ref: '#/components/responses/RateLimitError'\n")
            inside_responses = False
        
        # ── Handle end of responses on blank line at indent 6 ──
        if inside_responses and stripped.strip() == '' and leading <= 6:
            # Blank line could be within responses or at end
            # Look ahead by checking next non-blank line
            pass
        
        result.append(raw_line)
    
    # Handle if file ends while inside responses
    if inside_responses and not responses_have_429:
        result.append("        '429':\n")
        result.append("          $ref: '#/components/responses/RateLimitError'\n")
    
    # Write output
    with open(FILE, 'w', encoding='utf-8') as f:
        f.writelines(result)
    
    print(f"Processed {line_num} lines")
    print(f"File updated: {FILE}")


if __name__ == '__main__':
    process_file()
