#!/usr/bin/env python3
"""
Add Idempotency-Key header parameter to all authenticated mutating operations
in the OpenAPI spec (Finding 7).

Strategy:
  - Line-by-line processing
  - Track operation state
  - Insert Idempotency-Key inline when we encounter the right trigger points

Criteria for adding Idempotency-Key:
  - HTTP method is POST, PUT, PATCH, or DELETE (mutating)
  - NOT public (does NOT have security: [])
  - NOT already having Idempotency-Key parameter

Insertion points:
  - If parameters block exists: add entry at end of parameters block
  - If no parameters but requestBody exists: insert parameters block before requestBody
  - If no parameters and no requestBody: insert parameters block before responses
"""

import re

FILE = "docs/api/openapi.yaml"

# Patterns
METHOD_RE = re.compile(r'^\s{4}(get|post|put|patch|delete|options|head):$')
SECURITY_RE = re.compile(r'^\s{6}security:')
SECURITY_EMPTY_RE = re.compile(r'^\s{8}\[\s*\]$')
SECURITY_AUTH_RE = re.compile(r'^\s{8}-\s+(ApiKeyAuth|SessionCookieAuth|BearerSessionAuth)')
PARAMS_RE = re.compile(r'^\s{6}parameters:')
PARAM_ENTRY_RE = re.compile(r'^\s{8}- name:\s')
REQUEST_BODY_RE = re.compile(r'^\s{6}requestBody:')
RESPONSES_RE = re.compile(r'^\s{6}responses:')
TAGS_RE = re.compile(r'^\s{6}tags:')
OP_ID_RE = re.compile(r'^\s{8}operationId:\s*(\S+)')

# The Idempotency-Key parameter entry (at indent 8, to go inside a parameters block)
IDEM_KEY_ENTRY = (
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

# Full parameters: header + Idempotency-Key entry (for when no parameters block exists)
IDEM_KEY_PARAMS_BLOCK = (
    '      parameters:\n'
    f'{IDEM_KEY_ENTRY}'
)


def process_file():
    with open(FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    result = []

    # ── State variables ──────────────────────────────────────
    inside_operation = False
    current_method = None
    current_op_id = None
    is_public = False         # True if operation has security: []
    has_explicit_auth = False  # True if operation has explicit security block with auth entries
    seen_security_block = False

    # Block tracking
    inside_security = False
    inside_parameters = False
    inside_parameters_content = False  # True when we're past - name: line inside params
    parameters_have_content = False    # True if the parameters block has at least one entry
    already_has_idem_key = False       # True if Idempotency-Key already in parameters
    seen_request_body_line = False     # True when we've passed the requestBody line
    seen_responses_line = False        # True when we've passed the responses line
    idempotency_added = False          # True once we've added Idempotency-Key for this op

    line_num = 0

    for raw_line in lines:
        line_num += 1
        stripped = raw_line.rstrip('\n')
        leading = len(raw_line) - len(raw_line.lstrip())

        # ── Detect operation start (a method line at indent 4) ──
        method_match = METHOD_RE.match(stripped)
        if method_match and leading == 4:
            # Start new operation
            current_method = method_match.group(1)
            inside_operation = True
            current_op_id = None
            is_public = False
            has_explicit_auth = False
            seen_security_block = False
            inside_security = False
            inside_parameters = False
            inside_parameters_content = False
            parameters_have_content = False
            already_has_idem_key = False
            seen_request_body_line = False
            seen_responses_line = False
            idempotency_added = False

            result.append(raw_line)
            continue

        # ── Detect end of operation (new path or sibling method at lower indent) ──
        if inside_operation and leading <= 2 and stripped.strip() and not stripped.startswith(' ' * 6):
            # New path line detected - finalize operation
            if not idempotency_added:
                _insert_idempotency_now(result, current_method, current_op_id,
                                        is_public, already_has_idem_key,
                                        seen_request_body_line, seen_responses_line,
                                        inside_parameters, parameters_have_content)

            inside_operation = False
            current_method = None
            result.append(raw_line)
            continue

        # ── Detect sibling operation (another method at indent 4 within same path) ──
        if inside_operation and leading == 4 and METHOD_RE.match(stripped):
            # Another method in the same path - finalize current op
            if not idempotency_added:
                _insert_idempotency_now(result, current_method, current_op_id,
                                        is_public, already_has_idem_key,
                                        seen_request_body_line, seen_responses_line,
                                        inside_parameters, parameters_have_content)

            # Start new operation
            current_method = METHOD_RE.match(stripped).group(1)
            current_op_id = None
            is_public = False
            has_explicit_auth = False
            seen_security_block = False
            inside_security = False
            inside_parameters = False
            inside_parameters_content = False
            parameters_have_content = False
            already_has_idem_key = False
            seen_request_body_line = False
            seen_responses_line = False
            idempotency_added = False

            result.append(raw_line)
            continue

        # ════════════════════════════════════════════════════════
        # Within an operation — track state
        # ════════════════════════════════════════════════════════
        if inside_operation:
            # ── operationId ──
            op_match = OP_ID_RE.match(stripped)
            if op_match:
                current_op_id = op_match.group(1)

            # ── tags ──
            if TAGS_RE.match(stripped):
                pass  # Just noting we passed tags; no action needed

            # ── security: block ──
            if SECURITY_RE.match(stripped):
                seen_security_block = True
                inside_security = True
                # Check if it's inline security: [] (public operation)
                if 'security: []' in stripped:
                    is_public = True
                    inside_security = False
                result.append(raw_line)
                continue

            # Inside security block - check for auth entries or end
            if inside_security:
                # Check for auth entry (indent 8 starting with '- ApiKeyAuth:' etc.)
                if leading == 8:
                    if stripped.strip().startswith('- ') and stripped.strip() != '- []':
                        has_explicit_auth = True
                    elif stripped.strip() == '- []':
                        is_public = True
                elif leading <= 6 and stripped.strip():
                    # End of security block (next property at indent 6)
                    inside_security = False
                elif stripped.strip() == '':
                    # blank line ends security block
                    inside_security = False

            # ── parameters: block ──
            if PARAMS_RE.match(stripped):
                inside_parameters = True
                inside_parameters_content = False
                parameters_have_content = False
                already_has_idem_key = False
                result.append(raw_line)
                continue

            # Inside parameters block
            if inside_parameters:
                # Check for parameter entries (indent 8, starts with '- name:')
                if leading == 8 and stripped.strip().startswith('- name:'):
                    inside_parameters_content = True
                    parameters_have_content = True
                    if 'Idempotency-Key' in stripped:
                        already_has_idem_key = True
                    result.append(raw_line)
                    continue

                # Parameter content lines (indent 10-12, continuation of an entry)
                if leading >= 10 and inside_parameters_content and stripped.strip():
                    result.append(raw_line)
                    continue

                # End of parameters block: blank line at indent 6 or 8, or next property at indent 6
                if leading <= 6 and stripped.strip():
                    # Next property at indent 6 (requestBody or responses)
                    # Before adding it, insert Idempotency-Key if needed
                    inside_parameters = False
                    inside_parameters_content = False

                    if not idempotency_added and _should_add_idem(current_method, is_public, already_has_idem_key):
                        result.append(IDEM_KEY_ENTRY)
                        idempotency_added = True
                        print(f"  Added Idempotency-Key (existing params): {current_method.upper()} {current_op_id or ''}")

                    result.append(raw_line)
                    continue

                if stripped.strip() == '':
                    # Blank line - could be end of parameters or just spacing
                    inside_parameters = False
                    inside_parameters_content = False

                    if not idempotency_added and _should_add_idem(current_method, is_public, already_has_idem_key):
                        result.append(IDEM_KEY_ENTRY)
                        idempotency_added = True
                        print(f"  Added Idempotency-Key (existing params, blank line): {current_method.upper()} {current_op_id or ''}")

                    result.append(raw_line)
                    continue

            # ── requestBody: — insertion point if no parameters block ──
            if REQUEST_BODY_RE.match(stripped):
                seen_request_body_line = True
                # Insert parameters block before requestBody if needed
                if not idempotency_added and not inside_parameters and _should_add_idem(current_method, is_public, already_has_idem_key):
                    result.append(IDEM_KEY_PARAMS_BLOCK)
                    idempotency_added = True
                    print(f"  Added Idempotency-Key (before requestBody): {current_method.upper()} {current_op_id or ''}")

                result.append(raw_line)
                continue

            # ── responses: — insertion point if no parameters and no requestBody ──
            if RESPONSES_RE.match(stripped):
                seen_responses_line = True
                # Insert parameters block before responses if needed
                if not idempotency_added and not inside_parameters and _should_add_idem(current_method, is_public, already_has_idem_key):
                    result.append(IDEM_KEY_PARAMS_BLOCK)
                    idempotency_added = True
                    print(f"  Added Idempotency-Key (before responses): {current_method.upper()} {current_op_id or ''}")

                result.append(raw_line)
                continue

        # ── Default: append line ──
        result.append(raw_line)

    # Finalize if still inside an operation at EOF
    if inside_operation and not idempotency_added:
        _insert_idempotency_now(result, current_method, current_op_id,
                                is_public, already_has_idem_key,
                                seen_request_body_line, seen_responses_line,
                                inside_parameters, parameters_have_content)

    # Count modifications
    modified_count = sum(1 for line in result
                         if 'Idempotency-Key' in line and '- name:' in line)

    with open(FILE, 'w', encoding='utf-8') as f:
        f.writelines(result)

    print(f"\nProcessed {line_num} lines")
    print(f"Operations with Idempotency-Key header parameter: {modified_count}")
    print(f"File updated: {FILE}")


def _should_add_idem(method, is_public, already_has):
    """Check if Idempotency-Key should be added for this operation."""
    if method not in ('post', 'put', 'patch', 'delete'):
        return False
    if is_public:
        return False
    if already_has:
        return False
    return True


def _insert_idempotency_now(result, method, op_id, is_public, already_has,
                             seen_request_body, seen_responses,
                             inside_parameters, params_have_content):
    """Insert Idempotency-Key based on current state (at operation end)."""
    if not _should_add_idem(method, is_public, already_has):
        return

    label = f"{method.upper()} {op_id or ''}"

    if inside_parameters:
        # Still inside parameters block - append to end
        result.append(IDEM_KEY_ENTRY)
        print(f"  Added Idempotency-Key (end of params block): {label}")
    elif seen_request_body:
        # Should insert before requestBody - find last requestBody line and insert before
        for i in range(len(result) - 1, -1, -1):
            line = result[i]
            if REQUEST_BODY_RE.match(line.rstrip('\n')):
                result.insert(i, IDEM_KEY_PARAMS_BLOCK)
                print(f"  Added Idempotency-Key (before requestBody, fallback): {label}")
                return
        print(f"  WARNING: Could not find requestBody for {label}")
    elif seen_responses:
        # Insert before responses
        for i in range(len(result) - 1, -1, -1):
            line = result[i]
            if RESPONSES_RE.match(line.rstrip('\n')):
                result.insert(i, IDEM_KEY_PARAMS_BLOCK)
                print(f"  Added Idempotency-Key (before responses, fallback): {label}")
                return
        print(f"  WARNING: Could not find responses for {label}")
    else:
        print(f"  WARNING: No insertion point found for {label}")


if __name__ == '__main__':
    process_file()
