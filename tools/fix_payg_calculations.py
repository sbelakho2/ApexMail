#!/usr/bin/env python3
"""
Fix incorrect PAYG calculations in training data.
"""

import json
import re

from common_paths import data_path

def calculate_payg(emails):
    """Calculate correct PAYG cost based on canonical pricing."""
    total = 0
    remaining = emails
    
    # Tier 1: 0-10k at $0.001
    tier1 = min(remaining, 10000)
    total += tier1 * 0.001
    remaining -= tier1
    
    # Tier 2: 10k-100k at $0.0008
    if remaining > 0:
        tier2 = min(remaining, 90000)  # 100k - 10k
        total += tier2 * 0.0008
        remaining -= tier2
    
    # Tier 3: 100k-1M at $0.0005
    if remaining > 0:
        tier3 = min(remaining, 900000)  # 1M - 100k
        total += tier3 * 0.0005
        remaining -= tier3
    
    # Tier 4: 1M+ at $0.0003
    if remaining > 0:
        total += remaining * 0.0003
    
    return total

def fix_payg_calculations():
    filepath = str(data_path("train_agent.jsonl"))
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    fixed_count = 0
    fixed_lines = []
    
    for i, line in enumerate(lines, 1):
        modified = line
        
        try:
            data = json.loads(line)
            text = data.get('text', '')
            
            # Fix the specific 50,000 email PAYG calculation error
            # User asks about 50,000 but response calculates 10,000
            if '50,000 emails' in text and 'All 10,000 fall' in text:
                # Correct calculation for 50,000 emails:
                # - First 10,000 at $0.001 = $10.00
                # - Next 40,000 at $0.0008 = $32.00
                # - Total = $42.00
                correct_response = (
                    "For exactly **50,000 emails** on Pay-As-You-Go:\\n\\n"
                    "| Tier | Emails | Rate | Cost |\\n"
                    "|------|--------|------|------|\\n"
                    "| 0–10k | 10,000 | $0.001 | $10.00 |\\n"
                    "| 10k–100k | 40,000 | $0.0008 | $32.00 |\\n"
                    "\\n**Total: $42.00**\\n\\n"
                    "No base fee — you only pay for what you send. PAYG is great for variable or infrequent sending."
                )
                
                # Replace the incorrect assistant response
                old_response_pattern = r"For exactly \*\*50,000 emails\*\*.*?no base fee\. PAYG is great for low or variable volume\."
                modified = re.sub(old_response_pattern, correct_response, text, flags=re.DOTALL)
                
                if modified != text:
                    data['text'] = modified
                    modified = json.dumps(data, ensure_ascii=False) + '\n'
                    fixed_count += 1
                    print(f"Line {i}: Fixed 50,000 emails PAYG calculation")
        
        except json.JSONDecodeError:
            pass
        
        fixed_lines.append(modified)
    
    # Write back
    with open(filepath, 'w') as f:
        f.writelines(fixed_lines)
    
    print(f"\nTotal fixed: {fixed_count} lines with incorrect PAYG calculations")
    return fixed_count

if __name__ == '__main__':
    fix_payg_calculations()
