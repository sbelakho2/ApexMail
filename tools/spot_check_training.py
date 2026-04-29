#!/usr/bin/env python3
"""
Final spot check of training data quality.
Checks:
1. Pricing table consistency
2. Company info
3. Feature descriptions
4. Sample responses quality
"""

import json
import re
from collections import defaultdict

from common_paths import data_path


TRAIN_AGENT_FILE = str(data_path("train_agent.jsonl"))

def check_pricing_tables():
    """Verify pricing tables match canonical values."""
    print("=" * 60)
    print("CHECKING PRICING TABLES")
    print("=" * 60)
    
    canonical = {
        'Free': {'price': 0, 'emails': '3,000', 'api': '50,000', 'team': 1, 'domains': 1},
        'Starter': {'price': 25, 'emails': '50,000', 'api': '500,000', 'team': 5, 'domains': 5},
        'Pro': {'price': 65, 'emails': '150,000', 'api': '2,000,000', 'team': 10, 'domains': 25},
        'Growth': {'price': 150, 'emails': '500,000', 'api': '5,000,000', 'team': 25, 'domains': 100},
        'Scale': {'price': 350, 'emails': '2,000,000', 'api': '20,000,000', 'team': 50, 'domains': 'Unlimited'},
        'Enterprise': {'price': 800, 'emails': '5,000,000', 'api': 'Unlimited', 'team': 'Unlimited', 'domains': 'Unlimited'},
    }
    
    issues = []
    tables_checked = 0
    
    with open(TRAIN_AGENT_FILE) as f:
        for i, line in enumerate(f, 1):
            data = json.loads(line)
            text = data.get('text', '')
            
            # Look for pricing tables
            if '| Plan' in text and '| Price' in text:
                tables_checked += 1
                
                for plan, values in canonical.items():
                    # Check price
                    price_match = re.search(rf'\|\s*{plan}\s*\|\s*\$(\d+)', text)
                    if price_match:
                        found_price = int(price_match.group(1))
                        if found_price != values['price']:
                            issues.append(f"Line {i}: {plan} price ${found_price} should be ${values['price']}")
    
    print(f"Pricing tables checked: {tables_checked}")
    if issues:
        for issue in issues:
            print(f"  ❌ {issue}")
    else:
        print("  ✅ All pricing tables correct")
    
    return len(issues) == 0

def check_company_info():
    """Verify company information is consistent."""
    print("\n" + "=" * 60)
    print("CHECKING COMPANY INFO")
    print("=" * 60)
    
    issues = []
    system_prompts_with_company = 0
    
    with open(TRAIN_AGENT_FILE) as f:
        for i, line in enumerate(f, 1):
            data = json.loads(line)
            text = data.get('text', '')
            
            # Check system prompt header
            if 'Bel Consulting OÜ, Tallinn, Estonia, founded 2022' in text:
                system_prompts_with_company += 1
            elif 'ApexMail Agent' in text:
                # System prompt exists but company info might be wrong
                if 'founded 2023' in text or 'founded 2024' in text:
                    issues.append(f"Line {i}: Wrong founding year")
                elif 'Bel Consulting' in text and 'Tallinn' not in text:
                    issues.append(f"Line {i}: Missing Tallinn location")
    
    print(f"System prompts with correct company info: {system_prompts_with_company}")
    if issues:
        for issue in issues[:5]:
            print(f"  ❌ {issue}")
        if len(issues) > 5:
            print(f"  ... and {len(issues) - 5} more")
    else:
        print("  ✅ All company info correct")
    
    return len(issues) == 0

def check_key_features():
    """Verify key features by plan section exists and is consistent."""
    print("\n" + "=" * 60)
    print("CHECKING KEY FEATURES BY PLAN")
    print("=" * 60)
    
    # Key feature gates to verify
    expected_features = {
        'Growth': ['1 dedicated IP included', 'audit logs'],
        'Scale': ['3 dedicated IPs', 'SSO/SAML', '365-day retention'],
        'Enterprise': ['10 dedicated IPs', 'HIPAA/SOC2', '730-day retention'],
    }
    
    features_found = defaultdict(int)
    issues = []
    
    with open(TRAIN_AGENT_FILE) as f:
        for i, line in enumerate(f, 1):
            data = json.loads(line)
            text = data.get('text', '')
            
            if '## Key features by plan' in text:
                features_found['sections'] += 1
                
                # Check each expected feature
                for plan, features in expected_features.items():
                    for feature in features:
                        if feature.lower() in text.lower():
                            features_found[f"{plan}:{feature}"] += 1
    
    print(f"Key features sections found: {features_found['sections']}")
    
    for plan, features in expected_features.items():
        for feature in features:
            key = f"{plan}:{feature}"
            if features_found[key] > 0:
                print(f"  ✅ {plan}: {feature} ({features_found[key]} mentions)")
            else:
                print(f"  ❌ {plan}: {feature} NOT FOUND")
                issues.append(f"{plan} missing {feature}")
    
    return len(issues) == 0

def sample_responses():
    """Show sample responses from each plan type."""
    print("\n" + "=" * 60)
    print("SAMPLE RESPONSES BY PLAN")
    print("=" * 60)
    
    samples = {}
    
    with open(TRAIN_AGENT_FILE) as f:
        for i, line in enumerate(f, 1):
            data = json.loads(line)
            text = data.get('text', '')
            
            plan_match = re.search(r'Plan: (\w+) \(\$\d+/mo\)', text)
            if plan_match:
                plan = plan_match.group(1)
                if plan not in samples:
                    # Extract first assistant response
                    assist_match = re.search(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
                    if assist_match:
                        samples[plan] = {
                            'line': i,
                            'response': assist_match.group(1)[:200]
                        }
    
    for plan in ['Free', 'Starter', 'Pro', 'Growth', 'Scale', 'Enterprise']:
        if plan in samples:
            print(f"\n{plan} (Line {samples[plan]['line']}):")
            print(f"  {samples[plan]['response'][:150]}...")
        else:
            print(f"\n{plan}: No example found!")

def main():
    print("\n" + "🔍" * 30)
    print(" FINAL TRAINING DATA SPOT CHECK")
    print("🔍" * 30 + "\n")
    
    all_ok = True
    all_ok &= check_pricing_tables()
    all_ok &= check_company_info()
    all_ok &= check_key_features()
    sample_responses()
    
    print("\n" + "=" * 60)
    if all_ok:
        print("✅ ALL SPOT CHECKS PASSED!")
    else:
        print("⚠️ SOME ISSUES FOUND - Review above")
    print("=" * 60)

if __name__ == '__main__':
    main()
