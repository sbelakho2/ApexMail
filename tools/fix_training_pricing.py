#!/usr/bin/env python3
"""
Fix training data pricing to match docs/pricing.md canonical values.

Canonical prices:
  Free:       $0/mo,   3,000 emails
  Starter:    $25/mo,  50,000 emails
  Pro:        $65/mo,  150,000 emails
  Growth:     $150/mo, 500,000 emails
  Scale:      $350/mo, 2,000,000 emails
  Enterprise: $800/mo, 5,000,000 emails
  Dedicated IP add-on: $30/mo (not $49, not $50)
  Scale included IPs: 3 (at no extra cost)

Wrong values found in training data:
  - plan_price: 399 → should be 350 for Scale
  - ip_cost_per_month: 49 → should be 30
  - $399 bill references → $350
  - $49 IP references → $30
  - Wrong pricing table: Starter $29/25K, Pro $59/50K, Growth $129/100K, 
    Scale $399/500K, Enterprise $1,299/2M → all wrong
  - Free 1,000 emails → 3,000
  - Scale team limit 25 → 50, API 5M → 20M, email 500K → 2M
"""

import json
import re
import sys

JSONL_PATH = "data/train_agent.jsonl"

# Track changes for reporting
changes = []

def fix_line(line: str) -> str:
    original = line
    
    # Fix dedicated IP price: $49 → $30 (in various contexts)
    line = line.replace("ip_cost_per_month: 49", "ip_cost_per_month: 30")
    line = line.replace('ip_cost_per_month\\": 49', 'ip_cost_per_month\\": 30')
    line = line.replace('"ip_cost_per_month": 49', '"ip_cost_per_month": 30')
    
    # Fix Scale plan price: 399 → 350 in plan_price context
    line = line.replace('"plan_price": 399', '"plan_price": 350')
    line = line.replace("plan_price: 399", "plan_price: 350")
    line = line.replace('plan_price\\": 399', 'plan_price\\": 350')
    
    # Fix dedicated IP dollar amounts in narrative text
    # $49/month for IP → $30/month
    line = line.replace("$49/month", "$30/month")
    line = line.replace("$49/mo", "$30/mo")
    line = line.replace("$49.00", "$30.00")
    line = line.replace("extra $49", "extra $30")
    line = line.replace("$49 per", "$30 per")
    line = line.replace("$49 each", "$30 each")
    line = line.replace("$49 is for", "$30 is for")
    
    # Fix IP cost in billing breakdown tables
    # Scale has 3 IPs INCLUDED — no extra charge
    line = line.replace("Dedicated IPs (3 \\u00d7 $49) | $147/mo", "Dedicated IPs (3 included) | $0 (included in plan)")
    line = line.replace("Dedicated IPs (3 × $49) | $147/mo", "Dedicated IPs (3 included) | $0 (included in plan)")
    line = line.replace("3 \\u00d7 $49", "3 included")
    line = line.replace("3 × $49", "3 included")
    line = line.replace("3 \\u00d7 $30", "3 included")
    line = line.replace("3 × $30", "3 included")
    
    # Fix ip_cost in tool response JSON from 147 to 0 (included)
    line = line.replace('"ip_cost": 147', '"ip_cost": 0')
    line = line.replace('"ip_cost_per_month": 30, "ip_cost": 147', '"ip_cost_per_month": 0, "ip_cost": 0')
    
    # Fix $50 IP references (legacy price)
    line = line.replace("dedicated IP | $50.00", "dedicated IP | $30.00")
    line = line.replace("extra $50", "extra $30")
    
    # Fix Scale plan bill: $399 → $350 in narrative
    line = line.replace("$399/month", "$350/month")
    line = line.replace("$399/mo", "$350/mo")
    line = line.replace("bill should be exactly $399", "bill should be exactly $350")
    line = line.replace("$399.00", "$350.00")
    
    # Fix wrong pricing table entries that appear in assistant responses
    # Starter $29/25K → $25/50K
    line = line.replace("Starter | $29/mo | 25,000", "Starter | $25/mo | 50,000")
    line = line.replace("Starter | $29 | 25,000", "Starter | $25 | 50,000")
    # Pro $59/50K → $65/150K 
    line = line.replace("Pro | $59/mo | 50,000", "Pro | $65/mo | 150,000")
    line = line.replace("Pro | $59 | 50,000", "Pro | $65 | 150,000")
    # Growth $129/100K → $150/500K
    line = line.replace("Growth | $129/mo | 100,000", "Growth | $150/mo | 500,000")
    line = line.replace("Growth | $129 | 100,000", "Growth | $150 | 500,000")
    # Scale $399/500K → $350/2M
    line = line.replace("Scale | $399/mo | 500,000", "Scale | $350/mo | 2,000,000")
    line = line.replace("Scale | $399 | 500,000", "Scale | $350 | 2,000,000")
    # Enterprise $1,299/2M → $800/5M
    line = line.replace("Enterprise | $1,299/mo | 2,000,000", "Enterprise | $800/mo | 5,000,000")
    line = line.replace("Enterprise | $1,299 | 2,000,000", "Enterprise | $800 | 5,000,000")
    # Free 1,000 → 3,000
    line = line.replace("Free | $0/mo | 1,000", "Free | $0/mo | 3,000")
    line = line.replace("Free | $0 | 1,000", "Free | $0 | 3,000")
    
    # Fix Scale account context in system prompt / tool responses
    # email_limit: 500000 → 2000000 for Scale
    # (Only fix in contexts clearly about Scale plan)
    # These are in the account context block that says plan: Scale
    
    # Fix overage rate: $0.50/1K → $0.40/1K for Growth
    line = line.replace("Growth overage: $0.50/1K", "Growth overage: $0.40/1K")
    
    # Fix Scale total that includes IPs wrongly billed
    # Scale $399 + 3×$49 = $546 → Scale $350 (3 IPs included)
    line = line.replace("$546", "$350")
    line = line.replace("$546.00", "$350.00")
    
    # Fix $147 IP charge narrative (Scale IPs are included)
    line = line.replace("$147 for dedicated IPs is likely the part that feels higher than expected", 
                        "your 3 dedicated IPs are included in your Scale plan at no extra cost")
    line = line.replace("$147 for 3 dedicated IPs might be the unexpected part",
                        "your 3 dedicated IPs are included in your Scale plan at no extra cost")
    line = line.replace("The $147 for 3 dedicated IPs may be the unexpected part",
                        "your 3 dedicated IPs are included in the Scale plan")
    line = line.replace("$147 for dedicated IPs", "$0 (3 IPs included in Scale)")
    line = line.replace("$147/mo", "$0 (included)")
    line = line.replace("$147", "$0")
    
    # Fix the account context for Scale plan (wrong limits)  
    # email_limit 500,000 → 2,000,000 and api_calls limit 5,000,000 → 20,000,000
    # team 25 → 50
    line = line.replace("Email usage this month: 425,000/500,000", 
                        "Email usage this month: 425,000/2,000,000")
    line = line.replace("API calls this month: 3,200,000/5,000,000",
                        "API calls this month: 3,200,000/20,000,000")
    line = line.replace("Team members: 18/25",
                        "Team members: 18/50")
    
    # Fix tool response email_limit and api_call_limit for Scale
    line = line.replace('"email_limit": 500000, "api_calls": 3200000, "api_call_limit": 5000000',
                        '"email_limit": 2000000, "api_calls": 3200000, "api_call_limit": 20000000')
    line = line.replace('"email_limit": 500000, "api_calls": 3200000, "api_limit": 5000000',
                        '"email_limit": 2000000, "api_calls": 3200000, "api_limit": 20000000')
    
    # Fix the assistant's "within limits" text to reflect correct limits
    line = line.replace("425K of 500K emails, 3.2M of 5M API calls",
                        "425K of 2M emails, 3.2M of 20M API calls")
    line = line.replace("425K/500K emails, 3.2M/5M API calls",
                        "425K/2M emails, 3.2M/20M API calls")
    
    if line != original:
        changes.append("Fixed pricing in line")
    
    return line


def main():
    with open(JSONL_PATH, "r") as f:
        lines = f.readlines()
    
    print(f"Processing {len(lines)} lines...")
    
    fixed_lines = []
    for i, line in enumerate(lines):
        fixed_lines.append(fix_line(line))
    
    with open(JSONL_PATH, "w") as f:
        f.writelines(fixed_lines)
    
    print(f"Applied fixes to {len(changes)} lines")
    
    # Verify
    with open(JSONL_PATH, "r") as f:
        content = f.read()
    
    issues = []
    if "$49" in content:
        count = content.count("$49")
        issues.append(f"  WARNING: Still {count} occurrences of '$49'")
    if "plan_price: 399" in content or '"plan_price": 399' in content:
        issues.append("  WARNING: Still has plan_price 399")
    if "ip_cost_per_month: 49" in content or '"ip_cost_per_month": 49' in content:
        issues.append("  WARNING: Still has ip_cost_per_month 49")
    if "$147" in content:
        count = content.count("$147")
        issues.append(f"  WARNING: Still {count} occurrences of '$147'")
    if "500,000/500,000" in content or "425,000/500,000" in content:
        count = content.count("500,000")
        issues.append(f"  WARNING: Still {count} occurrences of '500,000' (Scale email limit should be 2,000,000)")
    
    if issues:
        print("\nRemaining issues:")
        for issue in issues:
            print(issue)
    else:
        print("\nAll known pricing issues fixed!")


if __name__ == "__main__":
    main()
