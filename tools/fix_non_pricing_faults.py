#!/usr/bin/env python3
"""Fix non-pricing faults in training data.

Found issues:
1. "980 out of 1,000 emails" should be "980 out of 3,000 emails" (4 occurrences)
2. "20 emails left" should be "2,020 emails left" (corresponding fix)
3. Stale team member limits (old Starter=3, Pro=5, Growth=10)
4. Stale overage scenario with 25K limit (lines 533, 596) - Starter is now 50K
5. Inconsistent .io infrastructure domains - standardized to .ee (48 fixes)
   - spf.apexmail.io → spf.apexmail.ee
   - track.apexmail.io → track.apexmail.ee
   - dkim.apexmail.io → dkim.apexmail.ee
   - bounce.apexmail.io → bounce.apexmail.ee
   - dmarc@apexmail.io → dmarc@apexmail.ee
   - "via apexmail.io" → "via apexmail.ee"
6. Unclosed bold markdown (line 1181): "**Starter plan has 5 team members" → "**Starter plan** has 5 team members"
"""

import json
import re
from pathlib import Path

FIXES = [
    # Stale Free plan limit in assistant response
    (r'(\*\*)?980 out of 1,000 emails(\*\*)?', r'\g<1>980 out of 3,000 emails\g<2>'),
    (r'You have only \*\*20 emails left\*\*', 'You have only **2,020 emails left**'),
    (r'only \*\*20 emails\*\* left', 'only **2,020 emails** left'),
    
    # Stale team member limits (old: Starter=3, Pro=5, Growth=10 | new: Starter=5, Pro=10, Growth=25)
    # Pattern: "more than 3 team...Pro supports 5" -> "more than 5 team...Pro supports 10"
    (r'more than 3 team members, the Pro plan \(\$65/mo\) supports 5, and Growth \(\$150/mo\) supports 10',
     'more than 5 team members, the Pro plan ($65/mo) supports 10, and Growth ($150/mo) supports 25'),
    
    # Starter allows 3 team -> 5 team
    (r'Starter.*allows up to \*\*3 team members\*\*', 'Starter plan allows up to **5 team members**'),
    (r'Starter plan includes 3 team members', 'Starter plan includes 5 team members'),
    (r'Starter.*3 team member', 'Starter plan has 5 team member'),
    
    # Pro supports 5 team -> 10 team (standalone mentions)
    (r'Pro plan \(\$65/mo\) supports 5 team', 'Pro plan ($65/mo) supports 10 team'),
    (r'Pro supports 5 team', 'Pro supports 10 team'),
    
    # Growth supports 10 team -> 25 team (standalone mentions)  
    (r'Growth \(\$150/mo\) supports 10 team', 'Growth ($150/mo) supports 25 team'),
    (r'Growth supports 10 team', 'Growth supports 25 team'),
    
    # ============================================================
    # STALE OVERAGE SCENARIO (lines 533, 596)
    # The examples show 27,800/50,000 usage but claim "2,800 overage over 25,000 limit"
    # This is broken - Starter is 50K, not 25K. Fix by updating to 52,800/50,000
    # so the 2,800 overage is accurate (52,800 - 50,000 = 2,800)
    # ============================================================
    
    # Account context: email usage
    (r'Email usage this month: 27,800/50,000', 'Email usage this month: 52,800/50,000'),
    
    # Recent events: sent with overage
    (r'27,800 sent \(2,800 overage\)', '52,800 sent (2,800 overage)'),
    
    # Recent events: delivered count and percentage (52,200/52,800 = 98.86% ≈ 98.9%)
    (r'27,200 delivered \(97\.8%\)', '52,200 delivered (98.9%)'),
    
    # Open issues: stale 25K limit
    (r'over 25,000 limit', 'over 50,000 limit'),
    
    # Open issues: wrong math ($1.40 should be $1.12 for 2,800 emails)
    (r'\$0\.40/1,000 = \$1\.40 overage', r'$0.40/1,000 = $1.12 overage'),
    
    # Assistant response: "sending over 25K" advice
    (r'sending over 25K', 'sending over 50K'),
    
    # Assistant response: sent count
    (r'\*\*Sent:\*\* 27,800 emails', '**Sent:** 52,800 emails'),
    
    # ============================================================
    # INCONSISTENT DOMAIN: .io infrastructure should be .ee
    # All ApexMail domains use .ee (api.apexmail.ee, app.apexmail.ee)
    # Infrastructure subdomains should match
    # ============================================================
    
    # SPF include domain
    (r'spf\.apexmail\.io', 'spf.apexmail.ee'),
    
    # Tracking domain
    (r'track\.apexmail\.io', 'track.apexmail.ee'),
    
    # DKIM domain
    (r'dkim\.apexmail\.io', 'dkim.apexmail.ee'),
    
    # Bounce domain
    (r'bounce\.apexmail\.io', 'bounce.apexmail.ee'),
    
    # DKIM selector pattern
    (r'apexmail\._domainkey\.apexmail\.io', 'apexmail._domainkey.apexmail.ee'),
    
    # DMARC rua email
    (r'dmarc@apexmail\.io', 'dmarc@apexmail.ee'),
    
    # Gmail "via" label
    (r'via apexmail\.io', 'via apexmail.ee'),
    
    # ============================================================
    # MARKDOWN FORMATTING FIXES
    # ============================================================
    
    # Unclosed bold on line 1181: "1. **Starter plan has 5 team members"
    # Should be: "1. **Starter plan** has 5 team members"
    (r'1\. \*\*Starter plan has 5 team members', '1. **Starter plan** has 5 team members'),
]

def fix_line(line: str) -> tuple[str, list]:
    """Apply fixes and return (fixed_line, list_of_fixes_applied)."""
    fixes_applied = []
    for pattern, replacement in FIXES:
        if re.search(pattern, line):
            line = re.sub(pattern, replacement, line)
            fixes_applied.append(pattern)
    return line, fixes_applied

def main():
    project_root = Path(__file__).resolve().parents[1]
    data_file = project_root / 'data/train_agent.jsonl'
    
    print("=== Non-Pricing Fault Scanner ===\n")
    
    # First pass: scan for issues
    issues_found = []
    with open(data_file, 'r') as f:
        for i, line in enumerate(f, 1):
            for pattern, _ in FIXES:
                if re.search(pattern, line):
                    issues_found.append((i, pattern))
    
    print(f"Found {len(issues_found)} issues:")
    for line_num, pattern in issues_found:
        print(f"  Line {line_num}: matches '{pattern[:50]}...'")
    
    if not issues_found:
        print("No issues found!")
        return
    
    # Second pass: apply fixes
    print(f"\nApplying fixes...")
    
    lines = data_file.read_text().splitlines()
    total_fixes = 0
    
    for i, line in enumerate(lines):
        fixed_line, fixes = fix_line(line)
        if fixes:
            lines[i] = fixed_line
            total_fixes += len(fixes)
            print(f"  Fixed line {i+1}: {len(fixes)} fix(es)")
    
    # Write back
    data_file.write_text('\n'.join(lines) + '\n')
    
    print(f"\nTotal fixes applied: {total_fixes}")
    print("File updated successfully!")

if __name__ == '__main__':
    main()
