#!/usr/bin/env python3
"""
COMPREHENSIVE AI Training Data Audit
Checks: plan limits, pricing tables, assistant responses, feature gates, API references,
PAYG pricing, overage rates, and factual accuracy.
"""

import json
import re
from collections import defaultdict

from common_paths import data_path
from audit_output import emit

# Canonical limits from plans.ts
CANONICAL = {
    'Free': {'email': 3000, 'api': 50000, 'team': 1, 'domains': 1, 'price': 0, 'retention': 7, 'contacts': 500},
    'Starter': {'email': 50000, 'api': 500000, 'team': 5, 'domains': 5, 'price': 25, 'retention': 30, 'contacts': 10000},
    'Pro': {'email': 150000, 'api': 2000000, 'team': 10, 'domains': 25, 'price': 65, 'retention': 60, 'contacts': 50000},
    'Growth': {'email': 500000, 'api': 5000000, 'team': 25, 'domains': 100, 'price': 150, 'retention': 90, 'contacts': 200000},
    'Scale': {'email': 2000000, 'api': 20000000, 'team': 50, 'domains': -1, 'price': 350, 'retention': 365, 'contacts': 500000},
    'Enterprise': {'email': 5000000, 'api': -1, 'team': -1, 'domains': -1, 'price': 800, 'retention': 730, 'contacts': -1},
}

# Dedicated IPs by plan
DEDICATED_IPS = {
    'Free': 0, 'Starter': 0, 'Pro': 0,  # Pro has add-on only
    'Growth': 1, 'Scale': 3, 'Enterprise': 10
}

# Feature minimum plan requirements
FEATURE_GATES = {
    'a/b testing': 'Pro',
    'send-time optimi': 'Pro',
    'custom tracking domain': 'Pro',
    'audit log': 'Growth',
    'sso': 'Scale',
    'saml': 'Scale', 
    'inbound email': 'Scale',
    'hipaa': 'Enterprise',
    'soc2': 'Enterprise',
    'white-label': 'Enterprise',
    'byoip': 'Enterprise',
}

PLAN_ORDER = ['Free', 'Starter', 'Pro', 'Growth', 'Scale', 'Enterprise']

def plan_index(plan):
    return PLAN_ORDER.index(plan) if plan in PLAN_ORDER else -1

def audit_training_data():
    issues = []
    warnings = []
    plan_counts = defaultdict(int)
    
    filepath = str(data_path("train_agent.jsonl"))
    
    with open(filepath) as f:
        lines = f.readlines()
    
    total_lines = len(lines)
    
    for i, line in enumerate(lines, 1):
        try:
            data = json.loads(line)
            text = data.get('text', '')
            
            # Find plan in customer context
            plan_match = re.search(r'Plan: (\w+) \(\$(\d+)/mo\)', text)
            if plan_match:
                plan = plan_match.group(1)
                price = int(plan_match.group(2))
                
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
            
            # Check pricing table in system prompt
            pricing_table_match = re.search(r'\| Free\s+\| \$(\d+)\s+\| ([\d,]+)\s+\| ([\d,]+)\s+\| (\d+)\s+\| (\d+)', text)
            if pricing_table_match:
                free_price = int(pricing_table_match.group(1))
                free_email = int(pricing_table_match.group(2).replace(',', ''))
                free_api = int(pricing_table_match.group(3).replace(',', ''))
                if free_price != 0:
                    issues.append(f"Line {i}: Pricing table Free price ${free_price} should be $0")
                if free_email != 3000:
                    issues.append(f"Line {i}: Pricing table Free email {free_email:,} should be 3,000")
                if free_api != 50000:
                    issues.append(f"Line {i}: Pricing table Free API {free_api:,} should be 50,000")
            
            # Check PAYG pricing references
            if '$0.001' in text and '0-10k' not in text.lower() and '0 - 10' not in text.lower():
                # Make sure $0.001 isn't being misattributed
                pass  # This is fine
            
            # Check for wrong overage pricing
            if '$0.90' in text and 'per 1,000' in text and 'Resend' not in text:
                issues.append(f"Line {i}: Wrong overage rate $0.90/1K found (should be $0.40/1K)")
            
            # Check for wrong PAYG pricing
            if '$0.0001' in text:
                issues.append(f"Line {i}: Wrong PAYG rate $0.0001 found")
            
            # Check for PAYG calculation errors (question about X emails but answer calculates Y)
            payg_q_match = re.search(r'(\d{1,3}(?:,\d{3})*) emails.*PAYG|PAYG.*(\d{1,3}(?:,\d{3})*) emails', text)
            if payg_q_match and '|im_start|>assistant' in text:
                asked_emails = payg_q_match.group(1) or payg_q_match.group(2)
                if asked_emails:
                    assistant_text = text.split('|im_start|>assistant')[-1]
                    # Check if answer calculates a different number
                    calc_match = re.search(r'All\s+([\d,]+)\s+fall', assistant_text)
                    if calc_match:
                        calculated = calc_match.group(1).replace(',', '')
                        asked = asked_emails.replace(',', '')
                        if calculated != asked and int(calculated) < int(asked):
                            issues.append(f"Line {i}: PAYG math error - asked about {asked_emails} emails but calculated {calc_match.group(1)}")
            
            # Check assistant responses for wrong limits
            # Pattern: "Emails: X / Y" in responses (outside of context block)
            if '|im_start|>assistant' in text:
                assistant_text = text.split('|im_start|>assistant')[-1]
                
                # Check for plan-specific wrong limits in responses
                if plan_match:
                    plan = plan_match.group(1)
                    if plan in CANONICAL:
                        canon = CANONICAL[plan]
                        
                        # Look for email limit mentions
                        response_email = re.search(r'Emails?[:\s]+([\d,]+)\s*/\s*([\d,]+)', assistant_text)
                        if response_email:
                            resp_limit = int(response_email.group(2).replace(',', ''))
                            if canon['email'] != -1 and resp_limit != canon['email']:
                                issues.append(f"Line {i}: {plan} assistant response shows {resp_limit:,} email limit (should be {canon['email']:,})")
                        
                        # Look for API limit mentions
                        response_api = re.search(r'API calls?[:\s]+([\d,]+)\s*/\s*([\d,]+)', assistant_text)
                        if response_api:
                            resp_limit = int(response_api.group(2).replace(',', ''))
                            if canon['api'] != -1 and resp_limit != canon['api']:
                                issues.append(f"Line {i}: {plan} assistant response shows {resp_limit:,} API limit (should be {canon['api']:,})")
            
            # Check feature availability claims
            lower_text = text.lower()
            for feature, min_plan in FEATURE_GATES.items():
                if feature in lower_text:
                    # Check if the response incorrectly says feature is available on a lower plan
                    if plan_match:
                        customer_plan = plan_match.group(1)
                        if plan_index(customer_plan) < plan_index(min_plan):
                            # Customer is on lower plan - check if response incorrectly claims feature is available
                            if f'{feature} is available' in lower_text or f'{feature} is included' in lower_text:
                                if f'not available' not in lower_text and f'upgrade' not in lower_text:
                                    warnings.append(f"Line {i}: Possible incorrect feature availability claim for '{feature}' on {customer_plan} (requires {min_plan})")
            
            # Check API endpoint references
            if 'api.apexmail' in text:
                if 'https://api.apexmail.ee/v1' not in text:
                    # Check for wrong versions or typos
                    if 'api.apexmail.ee/v2' in text:
                        issues.append(f"Line {i}: Wrong API version v2 (should be v1)")
                    if 'api.apexmail.com' in text:
                        issues.append(f"Line {i}: Wrong domain apexmail.com (should be apexmail.ee)")
            
            # Check company info
            if 'bel consulting' in lower_text:
                if 'tallinn' not in lower_text or 'estonia' not in lower_text:
                    warnings.append(f"Line {i}: Company location may be incomplete (should mention Tallinn, Estonia)")
                if '2022' not in text:
                    warnings.append(f"Line {i}: Company founding year missing or wrong (should be 2022)")
            
            # Check for WRONG claims about PAYG base fees (should be $0)
            # Only flag if it claims there IS a base fee, not if it correctly says "no base fee"
            if 'payg' in lower_text:
                # Check for incorrect base fee claims (not "no base fee" context)
                if re.search(r'payg.*\$\d+.*base fee', lower_text) and 'no base fee' not in lower_text:
                    issues.append(f"Line {i}: PAYG incorrectly claims there is a base fee (should be $0)")
            
        except json.JSONDecodeError:
            issues.append(f"Line {i}: Invalid JSON")
    
    # Print report
    emit("=" * 70)
    emit("COMPREHENSIVE TRAINING DATA AUDIT REPORT")
    emit("=" * 70)
    emit(f"\nTotal training examples: {total_lines}")
    emit(f"\nPlan distribution:")
    for plan in PLAN_ORDER:
        if plan in plan_counts:
            emit(f"  {plan:12}: {plan_counts[plan]:4} examples")
    
    payg_count = sum(1 for line in lines if 'PAYG' in line and 'Plan: ' not in line[:200])
    emit(f"  {'PAYG':12}: ~{payg_count:4} references")
    
    emit(f"\n{'=' * 70}")
    emit(f"CRITICAL ISSUES: {len(issues)}")
    emit("=" * 70)
    
    if issues:
        # Group by type
        email_issues = [x for x in issues if 'email' in x.lower()]
        api_issues = [x for x in issues if 'api' in x.lower() and 'email' not in x.lower()]
        team_issues = [x for x in issues if 'team' in x.lower()]
        price_issues = [x for x in issues if 'price' in x.lower()]
        table_issues = [x for x in issues if 'table' in x.lower()]
        response_issues = [x for x in issues if 'response' in x.lower()]
        other_issues = [x for x in issues if x not in email_issues + api_issues + team_issues + price_issues + table_issues + response_issues]
        
        for category, items in [
            ('📧 Email Limit', email_issues),
            ('🔌 API Limit', api_issues),
            ('👥 Team Limit', team_issues),
            ('💰 Price', price_issues),
            ('📊 Pricing Table', table_issues),
            ('💬 Assistant Response', response_issues),
            ('⚠️  Other', other_issues),
        ]:
            if items:
                emit(f"\n{category} Issues ({len(items)}):")
                for item in items[:5]:
                    emit(f"  {item}")
                if len(items) > 5:
                    emit(f"  ... and {len(items)-5} more")
    else:
        emit("\n✅ No critical issues found!")
    
    if warnings:
        emit(f"\n{'=' * 70}")
        emit(f"WARNINGS: {len(warnings)}")
        emit("=" * 70)
        for w in warnings[:10]:
            emit(f"  {w}")
        if len(warnings) > 10:
            emit(f"  ... and {len(warnings)-10} more")
    
    emit(f"\n{'=' * 70}")
    emit("SUMMARY")
    emit("=" * 70)
    emit(f"Total examples:    {total_lines}")
    emit(f"Critical issues:   {len(issues)}")
    emit(f"Warnings:          {len(warnings)}")
    emit(f"Status:            {'✅ PASS' if len(issues) == 0 else '❌ FAIL'}")
    
    return issues, warnings

if __name__ == '__main__':
    audit_training_data()
