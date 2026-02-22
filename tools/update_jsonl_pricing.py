#!/usr/bin/env python3
"""Bulk-update pricing in JSONL training data files."""

import json
import re
import sys

# Plain text replacements (applied to the decoded text inside JSON strings)
PLAIN_REPLACEMENTS = [
    # Overages
    ('Email overages: $0.50/1 000 extra', 'Email overages: $0.40/1,000 extra'),
    ('Email overages: $0.50/1,000 extra', 'Email overages: $0.40/1,000 extra'),
    ('$0.50 per 1,000 extra emails', '$0.40 per 1,000 extra emails'),
    ('$0.50/1 000 extra', '$0.40/1,000 extra'),
    ('Overages on plans: $0.50', 'Overages on plans: $0.40'),
    ('Overage: emails $0.50 per 1,000', 'Overage: emails $0.40 per 1,000'),
    ('overage $0.50', 'overage $0.40'),

    # Dedicated IP
    ('Add-on: $49/month', 'Add-on: $30/month'),
    ('Dedicated IP add-on: $49/month', 'Dedicated IP add-on: $30/month'),
    ('$49/mo dedicated IP', '$30/mo dedicated IP'),
    ('$49/month', '$30/month'),
    ('Must send >50K emails/month. Provisioning', 'Requires avg 500+ emails/day. Provisioning'),

    # Plan features - Free
    ('Basic sending, 1 domain, email support, 7-day retention. NO webhooks, NO custom tracking domain.',
     'Basic sending, 1 domain, community support, 7-day retention. NO webhooks, NO custom tracking domain. 500 contacts.'),
    ('Basic sending, 1 domain, NO webhooks, 7-day retention. 100 contacts.',
     'Basic sending, 1 domain, NO webhooks, 7-day retention. 500 contacts.'),

    # Plan features - Starter
    ('**Starter ($29):** Webhooks, 3 domains, 3 team members, email support, 30-day retention. NO A/B testing. NO dedicated IP.',
     '**Starter ($25):** Webhooks (5), 5 domains, 5 team members, email support, 30-day retention. NO A/B testing. NO dedicated IP. 10,000 contacts.'),
    ('**Starter ($29)**: Webhooks, 3 domains, 3 team members, email support, 30-day retention. NO A/B testing, NO dedicated IP. 5,000 contacts.',
     '**Starter ($25)**: Webhooks (5), 5 domains, 5 team members, email support, 30-day retention. NO A/B testing, NO dedicated IP. 10,000 contacts.'),

    # Plan features - Pro
    ('**Pro ($59):** Custom tracking domain, 5 domains, 5 team members, email support, 60-day retention. NO A/B testing. NO dedicated IP.',
     '**Pro ($65):** A/B testing, send-time optimisation (AI), custom tracking domain, 25 domains, 10 team members, email support, 60-day retention. Dedicated IP available as add-on ($30/mo). 50,000 contacts.'),
    ('**Pro ($59)**: Custom tracking domain, 5 domains, 5 team members, email support, 60-day retention. NO A/B testing, NO dedicated IP. 10,000 contacts.',
     '**Pro ($65)**: A/B testing, send-time optimization (AI), custom tracking domain, 25 domains, 10 team members, email support, 60-day retention. Dedicated IP available as add-on ($30/mo). 50,000 contacts.'),

    # Plan features - Growth
    ('**Growth ($129):** A/B testing, send-time optimisation (AI), 1 dedicated IP, 10 domains, 10 team members, audit logs, priority support, 90-day retention.',
     '**Growth ($150):** 1 dedicated IP included, 100 domains, 25 team members, audit logs, priority support, 90-day retention. 200,000 contacts.'),
    ('**Growth ($129)**: A/B testing, send-time optimization (AI), 1 dedicated IP, 10 domains, 10 team members, audit logs, priority support, 90-day retention. 25,000 contacts.',
     '**Growth ($150)**: 1 dedicated IP included, 100 domains, 25 team members, audit logs, priority support, 90-day retention. 200,000 contacts.'),

    # Plan features - Scale
    ('**Scale ($399):** 3 dedicated IPs, SSO/SAML, unlimited domains, 25 team members, phone support, subaccounts, inbound receiving, SLA 99.9%, 365-day retention.',
     '**Scale ($350):** 3 dedicated IPs, SSO/SAML, unlimited domains, 50 team members, phone support, subaccounts (10), inbound receiving, SLA 99.9% (10% credit), 365-day retention. 500,000 contacts.'),
    ('**Scale ($399)**: 3 dedicated IPs, SSO/SAML, unlimited domains, 25 team members, phone support, subaccounts, inbound receiving, SLA 99.9% (10% credit), 365-day retention. 100,000 contacts.',
     '**Scale ($350)**: 3 dedicated IPs, SSO/SAML, unlimited domains, 50 team members, phone support, subaccounts (10), inbound receiving, SLA 99.9% (10% credit), 365-day retention. 500,000 contacts.'),

    # Plan features - Enterprise
    ('**Enterprise ($1,299):** 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 99.9%, 730-day retention.',
     '**Enterprise ($800):** 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 99.9% (25% credit), 730-day retention. Unlimited contacts.'),
    ('**Enterprise ($1,299)**: 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 99.9% (25% credit cap), 730-day retention. Unlimited contacts.',
     '**Enterprise ($800)**: 10 dedicated IPs, BYOIP, HIPAA/SOC2, white-label, unlimited team, dedicated CSM, SLA 99.9% (25% credit cap), 730-day retention. Unlimited contacts.'),

    # A/B testing notes
    ('A/B testing is available ONLY from Growth ($129) and above. NOT on Free, Starter, or Pro.',
     'A/B testing is available from Pro ($65) and above. NOT on Free or Starter.'),
    ('Send-time optimisation is available ONLY from Growth ($129) and above.',
     'Send-time optimisation is available from Pro ($65) and above.'),
    ('Send-time optimization is available ONLY from Growth ($129) and above.',
     'Send-time optimization is available from Pro ($65) and above.'),
    ('SSO is available from Scale ($399) and above.',
     'SSO is available from Scale ($350) and above.'),
    ('Dedicated IPs: Growth 1 included, Scale 3 included, Enterprise 10 included. Add-on: $49/month.',
     'Dedicated IPs: Pro add-on ($30/mo), Growth 1 included, Scale 3 included, Enterprise 10 included.'),
    ('Priority support: available from Growth ($129) and above.',
     'Priority support: available from Growth ($150) and above.'),
]

# Regex replacements for the pricing table rows
REGEX_REPLACEMENTS = [
    (r'\| Free\s+\| \$0\s+\| 1,000\s+\| 10,000\s+\| 1\s+\| 1\s+\| 100\s+\|',
     '| Free       | $0       | 3,000       | 50,000       | 1    | 1          | 500         |'),
    (r'\| Free\s+\| \$0\s+\| 1,000\s+\| 10,000\s+\| 1\s+\| 1\s+\|',
     '| Free       | $0       | 3,000       | 50,000       | 1    | 1          |'),
    (r'\| Starter\s+\| \$29\s+\| 25,000\s+\| 250,000\s+\| 3\s+\| 3\s+\| 5,000\s+\|',
     '| Starter    | $25      | 50,000      | 500,000      | 5    | 5          | 10,000      |'),
    (r'\| Starter\s+\| \$29\s+\| 25,000\s+\| 250,000\s+\| 3\s+\| 3\s+\|',
     '| Starter    | $25      | 50,000      | 500,000      | 5    | 5          |'),
    (r'\| Pro\s+\| \$59\s+\| 50,000\s+\| 500,000\s+\| 5\s+\| 5\s+\| 10,000\s+\|',
     '| Pro        | $65      | 150,000     | 2,000,000    | 10   | 25         | 50,000      |'),
    (r'\| Pro\s+\| \$59\s+\| 50,000\s+\| 500,000\s+\| 5\s+\| 5\s+\|',
     '| Pro        | $65      | 150,000     | 2,000,000    | 10   | 25         |'),
    (r'\| Growth\s+\| \$129\s+\| 100,000\s+\| 1,000,000\s+\| 10\s+\| 10\s+\| 25,000\s+\|',
     '| Growth     | $150     | 500,000     | 5,000,000    | 25   | 100        | 200,000     |'),
    (r'\| Growth\s+\| \$129\s+\| 100,000\s+\| 1,000,000\s+\| 10\s+\| 10\s+\|',
     '| Growth     | $150     | 500,000     | 5,000,000    | 25   | 100        |'),
    (r'\| Scale\s+\| \$399\s+\| 500,000\s+\| 5,000,000\s+\| 25\s+\| Unlimited\s+\| 100,000\s+\|',
     '| Scale      | $350     | 2,000,000   | 20,000,000   | 50   | Unlimited  | 500,000     |'),
    (r'\| Scale\s+\| \$399\s+\| 500,000\s+\| 5,000,000\s+\| 25\s+\| Unlimited\s+\|',
     '| Scale      | $350     | 2,000,000   | 20,000,000   | 50   | Unlimited  |'),
    (r'\| Enterprise\s+\| \$1,299\s+\| 2,000,000\s+\| 20,000,000\s+\| Unlimited\s+\| Unlimited\s+\| Unlimited\s+\|',
     '| Enterprise | $800     | 5,000,000   | Unlimited    | Unlimited | Unlimited | Unlimited |'),
    (r'\| Enterprise\s+\| \$1,299\s+\| 2,000,000\s+\| 20,000,000\s+\| Unlimited\s+\| Unlimited\s+\|',
     '| Enterprise | $800     | 5,000,000   | Unlimited    | Unlimited | Unlimited |'),
]


def process_file(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    total_changes = 0
    new_lines = []
    for line in lines:
        original = line
        # Parse JSON to get the text, modify, re-encode
        try:
            obj = json.loads(line.rstrip('\n'))
        except json.JSONDecodeError:
            new_lines.append(line)
            continue

        text = obj.get('text', '')
        orig_text = text

        # Apply plain replacements
        for old, new in PLAIN_REPLACEMENTS:
            text = text.replace(old, new)

        # Apply regex replacements
        for pattern, replacement in REGEX_REPLACEMENTS:
            text = re.sub(pattern, replacement, text)

        if text != orig_text:
            total_changes += 1
            obj['text'] = text
            new_lines.append(json.dumps(obj, ensure_ascii=False) + '\n')
        else:
            new_lines.append(line)

    with open(path, 'w') as f:
        f.writelines(new_lines)

    return total_changes, len(lines)


def verify_file(path):
    issues = []
    with open(path) as f:
        content = f.read()

    # Check for old prices in table context
    if '| $29 ' in content:
        issues.append('$29 in table still present')
    if '| $59 ' in content:
        issues.append('$59 in table still present')
    if '| $129 ' in content:
        issues.append('$129 in table still present')
    if '| $399 ' in content:
        issues.append('$399 in table still present')
    if '| $1,299 ' in content:
        issues.append('$1,299 in table still present')
    if '$49/month' in content:
        issues.append('$49/month dedicated IP still present')
    if '$0.50 per 1,000' in content or '$0.50/1,000' in content or '$0.50/1 000' in content:
        issues.append('$0.50 overage still present')
    if 'Growth ($129)' in content:
        issues.append('Growth ($129) still present')
    if 'Scale ($399)' in content:
        issues.append('Scale ($399) still present')
    if 'Enterprise ($1,299)' in content:
        issues.append('Enterprise ($1,299) still present')
    if 'Starter ($29)' in content:
        issues.append('Starter ($29) still present')
    if 'Pro ($59)' in content:
        issues.append('Pro ($59) still present')

    # Check new prices are present
    checks = []
    if '| $25 ' in content:
        checks.append('$25 Starter OK')
    if '| $65 ' in content:
        checks.append('$65 Pro OK')
    if '| $150 ' in content:
        checks.append('$150 Growth OK')
    if '| $350 ' in content:
        checks.append('$350 Scale OK')
    if '| $800 ' in content:
        checks.append('$800 Enterprise OK')

    return issues, checks


if __name__ == '__main__':
    files = [
        'data/train_agent.jsonl',
        'apps/ai/training/data/train.jsonl',
    ]
    for path in files:
        changes, total = process_file(path)
        print(f'{path}: {changes}/{total} lines modified')

        issues, checks = verify_file(path)
        if issues:
            print(f'  ISSUES: {issues}')
        if checks:
            print(f'  VERIFIED: {checks}')
        if not issues and checks:
            print(f'  CLEAN')
