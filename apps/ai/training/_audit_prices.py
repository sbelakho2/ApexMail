#!/usr/bin/env python3
"""One-shot audit: check for wrong prices, wrong features, wrong SDKs in JSONL."""
import re

CHECKS = [
    # Wrong plan prices (close to correct but wrong)
    (r'Starter.{0,30}\$19[^,0-9]', 'Starter should be $25, not $19'),
    (r'Starter.{0,30}\$39[^,0-9]', 'Starter should be $25, not $39'),
    (r'\bPro\b.{0,30}\$49[^,0-9]', 'Pro should be $65, not $49'),
    (r'\bPro\b.{0,30}\$99[^,0-9]', 'Pro should be $65, not $99'),
    (r'Growth.{0,30}\$99[^,0-9]', 'Growth should be $150, not $99'),
    (r'Growth.{0,30}\$129', 'Growth should be $150, not $129'),
    (r'Scale.{0,30}\$299', 'Scale should be $350, not $299'),
    (r'Scale.{0,30}\$499', 'Scale should be $350, not $499'),
    (r'Enterprise.{0,30}\$999', 'Enterprise should be $800, not $999'),
    (r'Enterprise.{0,30}\$2,499', 'Enterprise should be $800'),
    # Wrong email limits
    (r'Starter.{0,40}20,000\s*email', 'Starter limit is 50,000 not 20,000'),
    (r'Starter.{0,40}25,000\s*email', 'Starter limit is 50,000 not 25,000'),
    (r'\bPro\b.{0,40}50,000\s*email', 'Pro limit is 150,000 not 50,000'),
    (r'\bPro\b.{0,40}100,000\s*email', 'Pro limit is 150,000 not 100,000'),
    (r'Growth.{0,40}100,000\s*email', 'Growth limit is 500,000 not 100,000'),
    (r'Growth.{0,40}200,000\s*email', 'Growth limit is 500,000 not 200,000'),
    (r'Scale.{0,40}250,000\s*email', 'Scale limit is 2,000,000 not 250,000'),
    (r'Scale.{0,40}1,000,000\s*email', 'Scale limit is 2,000,000 not 1,000,000'),
    # Wrong dedicated IP price
    (r'dedicated.{0,20}\$49', 'Dedicated IP is $30/mo, not $49'),
    (r'dedicated.{0,20}\$50', 'Dedicated IP is $30/mo, not $50'),
    # Wrong SLA 
    (r'SLA.{0,20}99\.5%', 'SLA is 99.9%, not 99.5%'),
    # Wrong overage
    (r'overage.{0,30}\$0\.25', 'Overage is $0.40/1K, not $0.25'),
    (r'overage.{0,30}\$0\.50', 'Overage is $0.40/1K, not $0.50'),
    (r'overage.{0,30}\$1\.00', 'Overage is $0.40/1K, not $1.00'),
    # Wrong features on wrong plans
    (r'(?:Free|Starter).{0,30}A/B test', 'A/B testing is Pro+ only'),
    (r'(?:Free|Starter).{0,30}custom tracking', 'Custom tracking domain is Pro+ only'),
    (r'(?:Free|Starter|Pro|Growth).{0,20}SSO', 'SSO is Scale+ only'),
]

files = [
    'data/train_agent.jsonl',
    'apps/ai/training/data/train.jsonl',
]

for filepath in files:
    print(f"\n{'='*60}")
    print(f"  {filepath}")
    print(f"{'='*60}")
    found = 0
    with open(filepath) as f:
        for i, line in enumerate(f, 1):
            for pattern, msg in CHECKS:
                matches = list(re.finditer(pattern, line, re.IGNORECASE))
                for m in matches:
                    # Get context
                    start = max(0, m.start() - 30)
                    end = min(len(line), m.end() + 30)
                    ctx = line[start:end].replace('\n', '\\n')
                    print(f"  Line {i}: {msg}")
                    print(f"    Context: ...{ctx}...")
                    found += 1
    if found == 0:
        print("  ✅ All clean")
    else:
        print(f"\n  ⚠ {found} potential issues found")
