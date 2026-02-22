#!/usr/bin/env python3
"""Fix remaining old prices in JSONL — pass 2."""
import json

# Additional replacements for the agent JSONL prompt format
AGENT_REPLACEMENTS = [
    ('**Starter ($29)**: Webhooks, 3 domains, 3 team members, email support, 30-day retention. NO A/B testing, NO dedicated IP.',
     '**Starter ($25)**: Webhooks (5), 5 domains, 5 team members, email support, 30-day retention. NO A/B testing, NO dedicated IP. 10,000 contacts.'),
    ('**Pro ($59)**: Custom tracking domain, 5 domains, 5 team members, email support, 60-day retention. NO A/B testing, NO dedicated IP.',
     '**Pro ($65)**: A/B testing, send-time optimization (AI), custom tracking domain, 25 domains, 10 team members, email support, 60-day retention. Dedicated IP available as add-on ($30/mo). 50,000 contacts.'),
    ('**Growth ($129)**: A/B testing, send-time optimization (AI), 1 dedicated IP, 10 domains, 10 team members, audit logs, priority support, 90-day retention.',
     '**Growth ($150)**: 1 dedicated IP included, 100 domains, 25 team members, audit logs, priority support, 90-day retention. 200,000 contacts.'),
    ('**Scale ($399)**: 3 dedicated IPs, SSO, unlimited domains, 25 team members, phone support, subaccounts, SLA 10% credit, 365-day retention.',
     '**Scale ($350)**: 3 dedicated IPs, SSO/SAML, unlimited domains, 50 team members, phone support, subaccounts (10), inbound receiving, SLA 99.9% (10% credit), 365-day retention. 500,000 contacts.'),
    ('**Enterprise ($1,299)**: 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 25% credit, 730-day retention.',
     '**Enterprise ($800)**: 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 99.9% (25% credit), 730-day retention. Unlimited contacts.'),
    # train.jsonl format
    ('**Enterprise ($1,299):** 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, 730-day retention.',
     '**Enterprise ($800):** 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 99.9% (25% credit), 730-day retention. Unlimited contacts.'),
]

# Also catch assistant response text with old prices
RESPONSE_REPLACEMENTS = [
    # Common assistant response patterns
    ('Starter plan ($29', 'Starter plan ($25'),
    ('Starter ($29)', 'Starter ($25)'),
    ('Pro plan ($59', 'Pro plan ($65'),
    ('Pro ($59)', 'Pro ($65)'),
    ('Growth plan ($129', 'Growth plan ($150'),
    ('Growth ($129)', 'Growth ($150)'),
    ('Scale plan ($399', 'Scale plan ($350'),
    ('Scale ($399)', 'Scale ($350)'),
    ('Enterprise plan ($1,299', 'Enterprise plan ($800'),
    ('Enterprise ($1,299)', 'Enterprise ($800)'),
    ('$29/month', '$25/month'),
    ('$29/mo', '$25/mo'),
    ('$59/month', '$65/month'),
    ('$59/mo', '$65/mo'),
    ('$129/month', '$150/month'),
    ('$129/mo', '$150/mo'),
    ('$399/month', '$350/month'),
    ('$399/mo', '$350/mo'),
    ('$1,299/month', '$800/month'),
    ('$1,299/mo', '$800/mo'),
    ('$1299/month', '$800/month'),
    ('$1299/mo', '$800/mo'),
    # Email limits in responses  
    ('1,000 emails/month', '3,000 emails/month'),
    ('25,000 emails/month', '50,000 emails/month'),
    ('100,000 emails/month', '500,000 emails/month'),
    # Overages in responses
    ('$0.50 per 1,000', '$0.40 per 1,000'),
    ('$0.50/1,000', '$0.40/1,000'),
    # Dedicated IP in responses
    ('$49 per month', '$30 per month'),
    ('$49/month', '$30/month'),
]

def process_file(path, replacements):
    with open(path) as f:
        lines = f.readlines()
    
    total_changes = 0
    new_lines = []
    for line in lines:
        obj = json.loads(line.rstrip('\n'))
        text = obj['text']
        orig = text
        
        for old, new in replacements:
            text = text.replace(old, new)
        
        if text != orig:
            total_changes += 1
            obj['text'] = text
            new_lines.append(json.dumps(obj, ensure_ascii=False) + '\n')
        else:
            new_lines.append(line)
    
    with open(path, 'w') as f:
        f.writelines(new_lines)
    
    return total_changes, len(lines)

all_replacements = AGENT_REPLACEMENTS + RESPONSE_REPLACEMENTS

for path in ['data/train_agent.jsonl', 'apps/ai/training/data/train.jsonl']:
    changes, total = process_file(path, all_replacements)
    print(f'{path}: {changes}/{total} lines changed in pass 2')

# Verify
import re
for path in ['data/train_agent.jsonl', 'apps/ai/training/data/train.jsonl']:
    with open(path) as f:
        content = f.read()
    
    old_checks = [
        ('Starter ($29)', 'Starter ($29)'),
        ('Pro ($59)', 'Pro ($59)'),
        ('Growth ($129)', 'Growth ($129)'),
        ('Scale ($399)', 'Scale ($399)'),
        ('Enterprise ($1,299)', 'Enterprise ($1,299)'),
        ('$0.50 per 1,000', '$0.50 overage'),
        ('$49/month', '$49/month IP'),
    ]
    print(f'\n{path}:')
    clean = True
    for check, label in old_checks:
        if check in content:
            count = content.count(check)
            print(f'  REMAINING: {label} ({count}x)')
            clean = False
    if clean:
        print(f'  CLEAN - all old prices removed')
