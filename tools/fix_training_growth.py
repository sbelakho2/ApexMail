#!/usr/bin/env python3
"""
Fix inconsistent Growth plan limits in train_agent.jsonl

Canonical Growth plan values (from plans.ts):
- API calls: 5,000,000 (not 1,000,000)
- Team members: 25 (not 10)
"""

import re

INPUT_FILE = '/Users/sabelakhoua/IdeaProjects/ApexMail/data/train_agent.jsonl'

with open(INPUT_FILE, 'r') as f:
    lines = f.readlines()

fixed_count = 0
fixed_lines = []

for line in lines:
    modified = False
    original = line
    
    # Check if this is a Growth plan context
    if 'Plan: Growth ($150/mo)' in line:
        # Fix API calls limit: 1,000,000 -> 5,000,000
        if '/1,000,000' in line and 'API calls this month:' in line:
            line = re.sub(r'(API calls this month: [0-9,]+)/1,000,000', r'\1/5,000,000', line)
        
        # Fix team members limit: X/10 -> X/25 for Growth plan
        # In JSONL, newlines are escaped as \n (literal backslash-n)
        if 'Team members:' in line:
            line = re.sub(r'Team members: (\d+)/10(\\\\n)', r'Team members: \1/25\2', line)
        
        if line != original:
            modified = True
            fixed_count += 1
    
    fixed_lines.append(line)

with open(INPUT_FILE, 'w') as f:
    f.writelines(fixed_lines)

print(f"Fixed {fixed_count} lines with incorrect Growth plan limits")
