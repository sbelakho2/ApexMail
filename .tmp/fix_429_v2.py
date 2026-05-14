#!/usr/bin/env python3
"""
Add 429 RateLimitError to every responses block missing it.

Approach: parse the file as a tree of indentation-based blocks.
For each `responses:` block, find its child entries (response codes).
If '429' is not among them, insert it.
"""

import re
import os

FILE = "docs/api/openapi.yaml"
BACKUP = FILE + ".bak"

# Restore from backup first
if os.path.exists(BACKUP):
    with open(BACKUP, 'r', encoding='utf-8') as f:
        orig = f.read()
    with open(FILE, 'w', encoding='utf-8') as f:
        f.write(orig)

with open(FILE, 'r', encoding='utf-8') as f:
    lines = f.readlines()

output = []
i = 0
n = len(lines)

while i < n:
    line = lines[i]
    leading = len(line) - len(line.lstrip())
    stripped = line.strip()
    
    # Look for `responses:` at indent 6
    if stripped == 'responses:' and leading == 6:
        output.append(line)
        i += 1
        
        # Collect all content that belongs to this responses block
        # All child lines should have indent > 6
        # The block ends when we hit a line with indent <= 6 (non-blank)
        # or indent 0/4/6 for next path/operation/property
        block_lines = []
        has_429 = False
        
        while i < n:
            curr_lead = len(lines[i]) - len(lines[i].lstrip())
            curr_strip = lines[i].strip()
            
            # Blank lines at indent 4, 6 could be separators between responses blocks
            # and the next operation/path. They're ambiguous.
            # Better rule: block ends when we hit a non-blank line at indent <= 6
            # OR a blank line at indent <= 2 (clear boundary)
            
            if curr_strip:
                if curr_lead <= 6:
                    # This line is at the same or lesser indent than `responses:`
                    # It ends the responses block
                    break
                
                # Check if this response code is 429
                if re.match(r"^\s{8}'429':", lines[i]):
                    has_429 = True
            
            block_lines.append(lines[i])
            i += 1
        
        # Now block_lines contains all lines of the responses block
        if not has_429:
            # Need to insert 429
            # Find where to put it: after the last response code entry
            # A response code entry starts with `'XXX':` at indent 8
            # Its content follows at indent 10+ until the next `'XXX':` or end of block
            
            # Find indices of all response code lines
            resp_code_indices = []
            for j, bl in enumerate(block_lines):
                if re.match(r"^\s{8}'\d{3}':", bl):
                    resp_code_indices.append(j)
            
            if resp_code_indices:
                # Insert after the last response code entry
                last_idx = resp_code_indices[-1]
                
                # The last response code entry includes all lines from last_idx
                # to the end of block_lines (or until next response code, but there's none)
                # We insert after last_idx but we need to handle its content
                
                # Find where the last response code's content ends
                # It ends at the end of block_lines, or before the next response code
                # Since last_idx is the LAST response code, it includes everything after it
                
                for j in range(last_idx + 1):
                    output.append(block_lines[j])
                # Insert 429
                output.append("        '429':\n")
                output.append("          $ref: '#/components/responses/RateLimitError'\n")
                for j in range(last_idx + 1, len(block_lines)):
                    output.append(block_lines[j])
            else:
                # No response codes? Unlikely but handle gracefully
                for bl in block_lines:
                    output.append(bl)
        else:
            for bl in block_lines:
                output.append(bl)
    else:
        output.append(line)
        i += 1

with open(FILE, 'w', encoding='utf-8') as f:
    f.writelines(output)

count = 0
for line in output:
    if re.search(r"'429':", line):
        count += 1
print(f"Done. Total '429' references: {count}")
