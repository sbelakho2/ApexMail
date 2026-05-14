#!/usr/bin/env python3
"""
Comprehensive audit of AI training data against canonical pricing from plans.ts
"""

import json
import re
import sys
from collections import defaultdict

from common_paths import data_path
from audit_output import emit

# Canonical limits from docs/pricing.md and billing-service/src/plans.rs
CANONICAL = {
    'Free': {'email': 30000, 'api': 300000, 'team': 1, 'domains': 1, 'price': 0},
    'Starter': {'email': 50000, 'api': 500000, 'team': 5, 'domains': 5, 'price': 25},
    'Pro': {'email': 150000, 'api': 2000000, 'team': 10, 'domains': 25, 'price': 65},
    'Growth': {'email': 500000, 'api': 5000000, 'team': 25, 'domains': 100, 'price': 150},
    'Scale': {'email': 2000000, 'api': 20000000, 'team': 50, 'domains': -1, 'price': 350},
    'Enterprise': {'email': 5000000, 'api': -1, 'team': -1, 'domains': -1, 'price': 3000},
}

# PAYG pricing tiers
PAYG_TIERS = [
    (10000, 0.001),      # $0.001 for 0-10k
    (100000, 0.0008),    # $0.0008 for 10k-100k
    (1000000, 0.0005),   # $0.0005 for 100k-1M
    (float('inf'), 0.0003),  # $0.0003 for 1M+
]

def audit_training_data():
    issues = []
    plan_counts = defaultdict(int)
    
    filepath = str(data_path("train_agent.jsonl"))
    
    with open(filepath, encoding='utf-8') as f:
        for i, line in enumerate(f, 1):
            try:
                data = json.loads(line)
                text = data.get('text', '')
                
                # Find plan in customer context
                plan_match = re.search(r'Plan: (\w+) \(\$([\d,]+)/mo\)', text)
                if plan_match:
                    plan = plan_match.group(1)
                    price = int(plan_match.group(2).replace(',', ''))
                    
                    if plan in CANONICAL:
                        plan_counts[plan] += 1
                        canon = CANONICAL[plan]
                        
                        # Check price
                        if price != canon['price']:
                            issues.append(f"Line {i}: {plan} price ${price} should be ${canon['price']}")
                        
                        # Check email limit in context
                        email_match = re.search(r'Email usage this month: [\d,]+/([\d,]+)', text)
                        if email_match:
                            found = int(email_match.group(1).replace(',', ''))
                            expected = canon['email']
                            if expected != -1 and found != expected:
                                issues.append(f"Line {i}: {plan} email limit {found:,} should be {expected:,}")
                        
                        # Check API limit in context
                        api_match = re.search(r'API calls this month: [\d,]+/([\d,]+)', text)
                        if api_match:
                            found = int(api_match.group(1).replace(',', ''))
                            expected = canon['api']
                            if expected != -1 and found != expected:
                                issues.append(f"Line {i}: {plan} API limit {found:,} should be {expected:,}")
                        
                        # Check team limit
                        team_match = re.search(r'Team members: (\d+)/(\d+)', text)
                        if team_match:
                            found = int(team_match.group(2))
                            expected = canon['team']
                            if expected != -1 and found != expected:
                                issues.append(f"Line {i}: {plan} team limit {found} should be {expected}")
                
                # Check pricing table consistency
                if '| Free       | $0       | 30,000' not in text and 'Pricing' in text:
                    if '| Free' in text:
                        free_row = re.search(r'\| Free\s+\|\s+\$(\d+)\s+\|\s+([\d,]+)', text)
                        if free_row:
                            if free_row.group(1) != '0' or free_row.group(2).replace(',', '') != '30000':
                                issues.append(f"Line {i}: Pricing table has wrong Free plan values")
                
                # Check assistant responses for wrong limit references
                # Look for usage percentages with wrong denominators
                wrong_100k = re.search(r'Emails: [\d,]+\s*/\s*100,000', text)
                if wrong_100k and 'Plan: Growth' in text:
                    issues.append(f"Line {i}: Growth plan assistant response shows /100,000 email limit (should be /500,000)")
                
                wrong_1m_api = re.search(r'API calls: [\d,]+\s*/\s*1,000,000', text)
                if wrong_1m_api and 'Plan: Growth' in text:
                    issues.append(f"Line {i}: Growth plan assistant response shows /1,000,000 API limit (should be /5,000,000)")
                    
            except json.JSONDecodeError:
                issues.append(f"Line {i}: Invalid JSON")
    
    emit("=" * 60)
    emit("TRAINING DATA AUDIT REPORT")
    emit("=" * 60)
    emit(f"\nTotal training examples analyzed: {i}")
    emit(f"\nPlan distribution:")
    for plan, count in sorted(plan_counts.items()):
        emit(f"  {plan}: {count}")
    
    emit(f"\n{'=' * 60}")
    emit(f"ISSUES FOUND: {len(issues)}")
    emit("=" * 60)
    
    if issues:
        # Group by issue type
        email_issues = [x for x in issues if 'email limit' in x]
        api_issues = [x for x in issues if 'API limit' in x]
        team_issues = [x for x in issues if 'team limit' in x]
        price_issues = [x for x in issues if 'price' in x]
        other_issues = [x for x in issues if x not in email_issues + api_issues + team_issues + price_issues]
        
        if email_issues:
            emit(f"\n📧 Email Limit Issues ({len(email_issues)}):")
            for issue in email_issues[:10]:
                emit(f"  {issue}")
            if len(email_issues) > 10:
                emit(f"  ... and {len(email_issues)-10} more")
                
        if api_issues:
            emit(f"\n🔌 API Limit Issues ({len(api_issues)}):")
            for issue in api_issues[:10]:
                emit(f"  {issue}")
            if len(api_issues) > 10:
                emit(f"  ... and {len(api_issues)-10} more")
                
        if team_issues:
            emit(f"\n👥 Team Limit Issues ({len(team_issues)}):")
            for issue in team_issues[:10]:
                emit(f"  {issue}")
            if len(team_issues) > 10:
                emit(f"  ... and {len(team_issues)-10} more")
                
        if price_issues:
            emit(f"\n💰 Price Issues ({len(price_issues)}):")
            for issue in price_issues[:10]:
                emit(f"  {issue}")
            if len(price_issues) > 10:
                emit(f"  ... and {len(price_issues)-10} more")
                
        if other_issues:
            emit(f"\n⚠️ Other Issues ({len(other_issues)}):")
            for issue in other_issues[:10]:
                emit(f"  {issue}")
            if len(other_issues) > 10:
                emit(f"  ... and {len(other_issues)-10} more")
    else:
        emit("\n✅ No issues found!")
    
    return issues

if __name__ == '__main__':
    raise SystemExit(1 if audit_training_data() else 0)
