#!/usr/bin/env python3
"""
Audit feature limits and capabilities in training data.
"""

import json
import re
from collections import defaultdict

# Canonical feature limits from plans.ts and pricing.md
FEATURE_LIMITS = {
    'Free': {
        'dedicated_ips': 0,
        'webhooks': False,
        'contacts': 500,
        'retention_days': 7,
        'team_members': 1,
        'domains': 1,
        'ab_testing': False,
        'sso': False,
        'audit_logs': False,
    },
    'Starter': {
        'dedicated_ips': 0,
        'webhooks': True,
        'contacts': 10000,
        'retention_days': 30,
        'team_members': 5,
        'domains': 5,
        'ab_testing': False,
        'sso': False,
        'audit_logs': False,
    },
    'Pro': {
        'dedicated_ips': 0,  # Available as add-on
        'webhooks': True,
        'contacts': 50000,
        'retention_days': 60,
        'team_members': 10,
        'domains': 25,
        'ab_testing': True,
        'sso': False,
        'audit_logs': False,
    },
    'Growth': {
        'dedicated_ips': 1,
        'webhooks': True,
        'contacts': 200000,
        'retention_days': 90,
        'team_members': 25,
        'domains': 100,
        'ab_testing': True,
        'sso': False,
        'audit_logs': True,
    },
    'Scale': {
        'dedicated_ips': 3,
        'webhooks': True,
        'contacts': 500000,
        'retention_days': 365,
        'team_members': 50,
        'domains': -1,  # Unlimited
        'ab_testing': True,
        'sso': True,
        'audit_logs': True,
    },
    'Enterprise': {
        'dedicated_ips': 10,
        'webhooks': True,
        'contacts': -1,  # Unlimited
        'retention_days': 730,
        'team_members': -1,  # Unlimited
        'domains': -1,  # Unlimited
        'ab_testing': True,
        'sso': True,
        'audit_logs': True,
    },
}

def audit_features():
    issues = []
    warnings = []
    
    filepath = '/Users/sabelakhoua/IdeaProjects/ApexMail/data/train_agent.jsonl'
    
    with open(filepath) as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        try:
            data = json.loads(line)
            text = data.get('text', '')
            
            # Only check assistant responses for feature accuracy
            # System prompts correctly list features per plan - we only audit AI responses
            if '|im_start|>assistant' not in text:
                continue
            
            # Extract just the assistant's response
            assistant_text = text.split('|im_start|>assistant')[-1]
            lower = assistant_text.lower()
            
            # Find plan in context
            plan_match = re.search(r'Plan: (\w+) \(\$\d+/mo\)', text)
            if not plan_match:
                continue
            
            plan = plan_match.group(1)
            if plan not in FEATURE_LIMITS:
                continue
            
            limits = FEATURE_LIMITS[plan]
            
            # Check dedicated IP statements
            if 'dedicated ip' in lower:
                # Check if response incorrectly claims dedicated IPs
                if limits['dedicated_ips'] == 0 and plan != 'Pro':
                    # Check for incorrect availability claims
                    if re.search(r'(your|you have|included|free|get)\s+\d+\s+dedicated ip', lower):
                        issues.append(f"Line {i}: {plan} incorrectly claims dedicated IPs (should be 0)")
                
                # Check correct counts
                if limits['dedicated_ips'] > 0:
                    ip_count = re.search(r'(\d+)\s+dedicated ip', lower)
                    if ip_count and int(ip_count.group(1)) != limits['dedicated_ips']:
                        reported = int(ip_count.group(1))
                        if 'included' in lower or 'free' in lower:
                            if reported != limits['dedicated_ips']:
                                warnings.append(f"Line {i}: {plan} mentions {reported} dedicated IPs (should be {limits['dedicated_ips']})")
            
            # Check A/B testing availability
            if 'a/b test' in lower or 'ab test' in lower:
                if not limits['ab_testing']:
                    # Check for incorrect availability
                    if 'available' in lower and 'not available' not in lower and 'upgrade' not in lower:
                        warnings.append(f"Line {i}: {plan} may incorrectly claim A/B testing availability")
            
            # Check SSO/SAML availability
            if 'sso' in lower or 'saml' in lower:
                if not limits['sso']:
                    if 'available' in lower and 'not available' not in lower and 'upgrade' not in lower:
                        warnings.append(f"Line {i}: {plan} may incorrectly claim SSO availability")
            
            # Check retention claims
            retention_match = re.search(r'(\d+)[- ]day retention', lower)
            if retention_match:
                reported = int(retention_match.group(1))
                if reported != limits['retention_days']:
                    # Only flag if it's in the context or a factual claim
                    if 'your' in lower or 'plan' in lower:
                        warnings.append(f"Line {i}: {plan} mentions {reported}-day retention (should be {limits['retention_days']})")
                        
        except json.JSONDecodeError:
            pass
    
    print("=" * 70)
    print("FEATURE LIMITS AUDIT")
    print("=" * 70)
    
    print(f"\nCritical Issues: {len(issues)}")
    for issue in issues[:10]:
        print(f"  {issue}")
    if len(issues) > 10:
        print(f"  ... and {len(issues)-10} more")
    
    print(f"\nWarnings: {len(warnings)}")
    for w in warnings[:10]:
        print(f"  {w}")
    if len(warnings) > 10:
        print(f"  ... and {len(warnings)-10} more")
    
    print(f"\nStatus: {'✅ PASS' if len(issues) == 0 else '❌ FAIL'}")
    
    return issues, warnings

if __name__ == '__main__':
    audit_features()
