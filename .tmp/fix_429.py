#!/usr/bin/env python3
"""
Add '429' RateLimitError reference to every responses block that doesn't have it.

Strategy: Find each `responses:` block, check if `'429':` is already inside it,
and if not, add it right before the closing of the block.

The closing of a responses block is detected by:
  - A new path line (starts with non-whitespace, ends with ':')
  - A new operation line (starts with 4 spaces, matches 'get|post|put|patch|delete:')
  - A blank line followed by something at indent < 6
  - End of file

A simpler heuristic: insert 429 after the last response code in the block 
(i.e., after the line matching `^\s{8}'\w+':` that is the last one before
a non-blank line at indent < 6 or a blank line followed by indent < 6).
"""

import re
import os

FILE = "docs/api/openapi.yaml"
BACKUP = FILE + ".bak"

# Restore from backup first
if os.path.exists(BACKUP):
    os.system(f"cp {BACKUP} {FILE}")

with open(FILE, 'r', encoding='utf-8') as f:
    content = f.read()
    lines = content.split('\n')

# Track state
result = []
i = 0
n = len(lines)

while i < n:
    line = lines[i]
    stripped = line
    
    # Check if this is a responses: line (at indent 6)
    if re.match(r'^\s{6}responses:\s*$', stripped):
        result.append(line)
        i += 1
        
        # Collect the entire responses block
        resp_lines = []
        resp_end_idx = i
        
        while i < n:
            curr = lines[i]
            leading = len(curr) - len(curr.lstrip())
            stripped_content = curr.strip()
            
            # End of responses block detection:
            # 1. Blank line followed by something at indent < 6
            # 2. Line at indent < 6 (starts a new operation or path property)
            # 3. Line at indent 4 (new operation) 
            # 4. Line at indent 0 (new path)
            
            if i >= resp_end_idx:
                # Check if this line ends the responses block
                if leading <= 6 and stripped_content:
                    if leading == 0:
                        # New path - definitely end of responses
                        break
                    elif leading == 4 and re.match(r'^\s{4}(get|post|put|patch|delete|options|head):\s*$', curr):
                        # New operation - end of responses
                        break
                    elif leading == 6 and not re.match(r"^\s{8}", curr) and not re.match(r"^\s{6}\s", curr):
                        # Line at indent 6 that's not continuing response content
                        # Could be a new property at operation level
                        if not re.match(r"^\s{8}", curr):  # not a response code
                            # Check the pattern - could be description: or security: etc at indent 6
                            pass
            
            # More robust: track response code entries
            resp_lines.append(curr)
            i += 1
            
            # Check if next line would be end of responses
            if i < n:
                nxt = lines[i]
                nxt_lead = len(nxt) - len(nxt.lstrip())
                nxt_stripped = nxt.strip()
                
                # End conditions:
                # 1. Indent 0: new path
                # 2. Indent 4 and matches HTTP method: new operation
                # 3. Indent 6, non-blank, not a response code ('XXX'), not blank
                if nxt_lead == 0:
                    break
                if nxt_lead == 4 and re.match(r'^\s{4}(get|post|put|patch|delete|options|head):\s*$', nxt):
                    break
                if nxt_lead < 6 and nxt_stripped:
                    break
                if nxt_lead == 6 and nxt_stripped and not re.match(r"^\s*'", nxt):
                    break
        
        # Now we have all the response lines. Check if 429 exists.
        has_429 = any(re.match(r"^\s{8}'429':\s*$", l) for l in resp_lines)
        
        if has_429:
            # Already has 429, just pass through
            for rl in resp_lines:
                result.append(rl)
        else:
            # Find the last response code line and insert 429 after it
            # Last response code is the last line matching `^\s{8}'XXX':`
            last_resp_idx = -1
            for j in range(len(resp_lines) - 1, -1, -1):
                if re.match(r"^\s{8}'\d+'?:?\s*$", resp_lines[j]) or re.match(r"^\s{8}'\d{3}':", resp_lines[j]):
                    last_resp_idx = j
                    break
            
            if last_resp_idx >= 0:
                # Insert 429 right after the last response code line
                for k in range(last_resp_idx + 1):
                    result.append(resp_lines[k])
                result.append("        '429':")
                result.append("          $ref: '#/components/responses/RateLimitError'")
                for k in range(last_resp_idx + 1, len(resp_lines)):
                    result.append(resp_lines[k])
            else:
                # No response codes found - shouldn't happen, but pass through
                for rl in resp_lines:
                    result.append(rl)
    else:
        result.append(line)
        i += 1

output = '\n'.join(result)
with open(FILE, 'w', encoding='utf-8') as f:
    f.write(output)

print(f"Done. Processed {len(lines)} lines.")
print(f"Output written to {FILE}")

# Count how many 429 entries now exist
new_count = output.count("'429':")
print(f"Total '429' entries: {new_count}")
