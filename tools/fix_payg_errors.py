#!/usr/bin/env python3
"""
Fix PAYG calculation errors in training data.

PAYG tiers:
- 0-10K: $0.001/email ($1.00/1K)
- 10K-100K: $0.0008/email ($0.80/1K)
- 100K-1M: $0.0005/email ($0.50/1K)
- 1M+: $0.0003/email ($0.30/1K)

50,000 emails = 10K × $0.001 + 40K × $0.0008 = $10 + $32 = $42
"""

import json
import re
import sys

from common_paths import data_path

def fix_payg_errors(filepath: str) -> int:
    """Fix known PAYG calculation errors. Returns count of fixes."""
    fixes = 0
    fixed_lines = []
    
    with open(filepath) as f:
        for i, line in enumerate(f, 1):
            data = json.loads(line)
            text = data.get('text', '')
            original_text = text
            
            # Fix 1: "First 50,000 emails: 10,000 × $0.001 = **$10**\n\nTotal cost: **$10**"
            # Should be "$42"
            text = re.sub(
                r'First 50,000 emails: 10,000 × \$0\.001 = \*\*\$10\*\*\s*\n\nTotal cost: \*\*\$10\*\*',
                r'''First 10K: 10,000 × $0.001 = **$10**
Next 40K: 40,000 × $0.0008 = **$32**

Total cost: **$42**''',
                text
            )
            
            # Fix 2: "10,000 × $0.001 = **$10**\n\nThe first 50,000 emails are at the $0.001/email tier"
            text = re.sub(
                r'10,000 × \$0\.001 = \*\*\$10\*\*\s*\n\nThe first 50,000 emails are at the \$0\.001/email tier\. Simple and straightforward!',
                r'''PAYG tiers apply:
- First 10,000: 10,000 × $0.001 = **$10**
- Next 40,000: 40,000 × $0.0008 = **$32**

Total for 50,000 emails: **$42**''',
                text
            )
            
            # Fix 3: "$10 + (15,000 × $0.0008) = **$22**" for 50,000 emails
            # This is wrong because 50K - 10K = 40K, not 15K
            text = re.sub(
                r'\$10 \+ \(15,000 × \$0\.0008\) = \*\*\$22\*\*',
                r'$10 + (40,000 × $0.0008) = **$42**',
                text
            )
            
            # Fix 4: "First 50,000 emails × $1.00/1K = **$10.00**" - misleading
            # The $1.00/1K rate only applies to first 10K
            text = re.sub(
                r'First 50,000 emails × \$1\.00/1K = \*\*\$10\.00\*\*\s*\n- Next 64,200 emails × \$0\.80/1K = \*\*\$51\.36\*\*',
                r'First 10,000 emails × $1.00/1K = **$10.00**\n- Next 64,200 emails × $0.80/1K = **$51.36**',
                text
            )
            
            if text != original_text:
                fixes += 1
                print(f"Fixed line {i}")
            
            data['text'] = text
            fixed_lines.append(json.dumps(data, ensure_ascii=False))
    
    # Write back
    with open(filepath, 'w') as f:
        f.write('\n'.join(fixed_lines) + '\n')
    
    return fixes

def main():
    filepath = str(data_path("train_agent.jsonl"))
    
    print("Fixing PAYG calculation errors...")
    fixes = fix_payg_errors(filepath)
    print(f"\nFixed {fixes} lines with PAYG errors")
    
    if fixes > 0:
        print("\n✅ Training data updated")
    else:
        print("\n⚠️ No fixes applied (patterns may have changed)")

if __name__ == '__main__':
    main()
