#!/usr/bin/env python3
"""
Add 429 RateLimitError to every responses block missing it.

Correctly handles multi-line response entries (code line + content).
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
        block_lines = []
        has_429 = False
        
        while i < n:
            curr = lines[i]
            curr_lead = len(curr) - len(curr.lstrip())
            curr_strip = curr.strip()
            
            if curr_strip:
                if curr_lead <= 6:
                    # Non-blank line at same or lesser indent ends the block
                    break
            
            # Track if we see 429
            if re.match(r"^\s{8}'429':", curr):
                has_429 = True
            
            block_lines.append(curr)
            i += 1
        
        if not has_429:
            # Find the boundary between the last response code entry and the end
            # Each response code entry = key line + its content lines
            # A response code key line matches `^\s{8}'\d{3}':`
            # Its content follows at indent > 8 until the next key line
            
            # Find all response code key line indices
            key_indices = []
            for j, bl in enumerate(block_lines):
                if re.match(r"^\s{8}'\d{3}':", bl):
                    key_indices.append(j)
            
            if key_indices:
                last_key_idx = key_indices[-1]
                
                # The last response code entry spans from last_key_idx to end of block
                # We need to find where its content ends (it ends at block end)
                
                # Strategy: find the start of content for the last entry
                # Content starts after the key line and continues until:
                # - Another key line (doesn't exist since it's the last)
                # - End of block
                
                # So we insert 429 right after the last response code entry
                # which means after block_lines ends
                
                # But wait - if there are trailing blank lines in block, 429 should go before them
                # Find last non-blank line in block
                last_content_idx = len(block_lines) - 1
                while last_content_idx >= last_key_idx and block_lines[last_content_idx].strip() == '':
                    last_content_idx -= 1
                
                # Output everything up to and including last content line
                for j in range(last_content_idx + 1):
                    output.append(block_lines[j])
                # Insert 429
                output.append("        '429':\n")
                output.append("          $ref: '#/components/responses/RateLimitError'\n")
                # Output any trailing blank lines
                for j in range(last_content_idx + 1, len(block_lines)):
                    output.append(block_lines[j])
            else:
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

# Verify key spots
with open(FILE, 'r', encoding='utf-8') as f:
    content = f.read()

count = content.count("'429':")
print(f"Done. Total '429' references: {count}")

# Check the problematic area (auth/register)
lines_check = content.split('\n')
for idx, ln in enumerate(lines_check):
    if 'auth/register' in ln:
        # Print 10 lines from here
        for j in range(idx, min(idx+12, len(lines_check))):
            print(f"  {j}: {lines_check[j]}")
        break
