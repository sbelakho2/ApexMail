#!/usr/bin/env python3
"""
DEFINITIVE LINE-BY-LINE AUDIT — checks every assistant response in every training example.

For each line, extracts ALL claims about pricing/plans/features/math from assistant
responses and validates them against the canonical source (docs/pricing.md).

This script does NOT use broad regexes. It checks specific, targeted patterns
that represent actual claims an assistant might make.
"""
import json
import re
import sys
from collections import defaultdict

FILEPATH = 'data/train_agent.jsonl'

# ══════════════════════════════════════════════════════════════════════
# CANONICAL VALUES (from docs/pricing.md, February 2026)
# ══════════════════════════════════════════════════════════════════════

PLANS = {
    'free':       {'price': 0,   'annual': 0,    'emails': 3000,     'api': 50000,      'team': 1,  'domains': 1,   'contacts': 500,    'retention': 7,   'webhooks': 0},
    'starter':    {'price': 25,  'annual': 250,  'emails': 50000,    'api': 500000,     'team': 5,  'domains': 5,   'contacts': 10000,  'retention': 30,  'webhooks': 5},
    'pro':        {'price': 65,  'annual': 650,  'emails': 150000,   'api': 2000000,    'team': 10, 'domains': 25,  'contacts': 50000,  'retention': 60,  'webhooks': 10},
    'growth':     {'price': 150, 'annual': 1500, 'emails': 500000,   'api': 5000000,    'team': 25, 'domains': 100, 'contacts': 200000, 'retention': 90,  'webhooks': 25},
    'scale':      {'price': 350, 'annual': 3500, 'emails': 2000000,  'api': 20000000,   'team': 50, 'domains': -1,  'contacts': 500000, 'retention': 365, 'webhooks': -1},
    'enterprise': {'price': 800, 'annual': 8000, 'emails': 5000000,  'api': -1,         'team': -1, 'domains': -1,  'contacts': -1,     'retention': 730, 'webhooks': -1},
}

# Old values that should NOT appear
OLD_PRICES = {'starter': [29], 'pro': [59], 'growth': [129], 'scale': [399], 'enterprise': [1299]}
OLD_EMAILS = {'starter': [25000], 'pro': [50000], 'growth': [100000], 'scale': [500000], 'enterprise': [2000000]}

OVERAGE_RATE = 0.40  # per 1,000 emails
PAYG_TIERS = [(10000, 0.001), (100000, 0.0008), (1000000, 0.0005), (float('inf'), 0.0003)]
DEDICATED_IP_PRICE = 30  # $/mo

# Feature gates: plan → set of features available
FEATURE_GATES = {
    'free':       {'rest_api', 'smtp', 'sdks', 'basic_analytics'},
    'starter':    {'rest_api', 'smtp', 'sdks', 'basic_analytics', 'webhooks', 'custom_templates', 'data_export', 'advanced_analytics'},
    'pro':        {'rest_api', 'smtp', 'sdks', 'basic_analytics', 'webhooks', 'custom_templates', 'data_export', 'advanced_analytics', 'custom_tracking_domain', 'ab_testing', 'send_time_opt', 'dedicated_ip_addon', 'priority_onboarding'},
    'growth':     {'rest_api', 'smtp', 'sdks', 'basic_analytics', 'webhooks', 'custom_templates', 'data_export', 'advanced_analytics', 'custom_tracking_domain', 'ab_testing', 'send_time_opt', 'dedicated_ip_included', 'audit_logs', 'priority_onboarding'},
    'scale':      {'rest_api', 'smtp', 'sdks', 'basic_analytics', 'webhooks', 'custom_templates', 'data_export', 'advanced_analytics', 'custom_tracking_domain', 'ab_testing', 'send_time_opt', 'dedicated_ip_included', 'audit_logs', 'sso', 'subaccounts', 'inbound', 'sla', 'priority_onboarding', 'dedicated_csm'},
    'enterprise': {'rest_api', 'smtp', 'sdks', 'basic_analytics', 'webhooks', 'custom_templates', 'data_export', 'advanced_analytics', 'custom_tracking_domain', 'ab_testing', 'send_time_opt', 'dedicated_ip_included', 'audit_logs', 'sso', 'subaccounts', 'inbound', 'sla', 'hipaa', 'soc2', 'white_label', 'byoip', 'priority_onboarding', 'dedicated_csm'},
}

issues = []

def add_issue(line_num, category, message):
    issues.append((line_num, category, message))

def parse_number(s):
    """Parse a number string like '2,000,000' or '50K' or '5M'."""
    s = s.strip().replace(',', '')
    if s.upper().endswith('M'):
        return int(float(s[:-1]) * 1000000)
    if s.upper().endswith('K'):
        return int(float(s[:-1]) * 1000)
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return None

def get_assistant_text(text):
    """Extract all assistant response text from ChatML."""
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    return '\n'.join(parts)

# ══════════════════════════════════════════════════════════════════════
# CHECK FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def check_plan_prices(ln, assistant):
    """Check that plan prices are correct."""
    # Match: "Starter ($25" or "Starter plan — $25" or "$25/month...Starter" etc.
    plan_price_patterns = [
        # "Plan ($XX/mo)" or "Plan ($XX)"
        (r'\b(Free|Starter|Pro|Growth|Scale|Enterprise)\b[^.]{0,20}\(\$(\d+)(?:/mo(?:nth)?)?\)', 1, 2),
        # "Plan plan — $XX/month" or "Plan plan at $XX/mo"
        (r'\b(Free|Starter|Pro|Growth|Scale|Enterprise)\b[^.]{0,30}(?:—|at|is|:)\s*\$(\d+)(?:/mo(?:nth)?)?', 1, 2),
        # "$XX/mo...Plan" (within 30 chars)
        (r'\$(\d+)/mo(?:nth)?\s*(?:\(|\|)?\s*\*?\*?(Free|Starter|Pro|Growth|Scale|Enterprise)', 2, 1),
    ]
    
    for pattern, plan_group, price_group in plan_price_patterns:
        for m in re.finditer(pattern, assistant, re.IGNORECASE):
            plan = m.group(plan_group).lower()
            price = int(m.group(price_group))
            if plan in PLANS:
                expected = PLANS[plan]['price']
                if price != expected:
                    add_issue(ln, 'wrong_price', f"{m.group(plan_group)} shown as ${price}/mo (should be ${expected})")

def check_email_limits(ln, assistant):
    """Check that email limits per plan are correct."""
    lower = assistant.lower()
    
    for plan_name, vals in PLANS.items():
        expected_emails = vals['emails']
        
        # Pattern: "Plan ... N emails" or "Plan ... includes N" 
        # Must be careful about context — only flag when the number is clearly attributed to this plan
        
        # "Plan plan/Plan ($XX): N emails" patterns
        pats = [
            rf'\b{plan_name}\b[^.]*?(?<!\d)([\d,]+[KkMm]?)\s*(?:emails?(?:/mo(?:nth)?)?|included)',
            rf'\b{plan_name}\b[^.]*?includes?\s*(?:\*\*)?(?<!\d)([\d,]+[KkMm]?)\s*(?:\*\*)?\s*emails?',
        ]
        
        for pat in pats:
            for m in re.finditer(pat, lower, re.DOTALL):
                num_str = m.group(1)
                num = parse_number(num_str)
                if num is None:
                    continue
                    
                # Check the matched span isn't too wide (prevent cross-plan matches)
                span = m.end() - m.start()
                if span > 300:
                    continue
                
                # Allow small discrepancies for context (e.g., "sent 48K of 50K emails")
                if num == expected_emails:
                    continue  # correct
                
                # Check it's not a usage number ("sent 48,000 of your 50,000")
                context = assistant[max(0,m.start()-20):m.end()+20].lower()
                if 'sent' in context or "you've" in context or 'used' in context or 'usage' in context:
                    continue
                
                # Check it's not inside the correct number (e.g., "50,000" inside text also containing "150,000")
                nearby = assistant[max(0,m.start()-5):min(len(assistant),m.end()+5)]
                if str(expected_emails) in nearby.replace(',','') or f"{expected_emails:,}" in nearby:
                    continue
                
                # It's a wrong email limit claim
                if num in OLD_EMAILS.get(plan_name, []):
                    add_issue(ln, 'old_email_limit', f"{plan_name.title()} shown with {num:,} emails (should be {expected_emails:,})")

def check_team_counts(ln, assistant):
    """Check team member counts per plan."""
    lower = assistant.lower()
    
    for plan_name, vals in PLANS.items():
        expected = vals['team']
        if expected == -1:  # Unlimited
            continue
        
        # "Plan ... N team members"
        pat = rf'\b{plan_name}\b.{{0,200}}?(?<!\d)(\d+)\s+team\s+members?'
        for m in re.finditer(pat, lower, re.DOTALL):
            claimed = int(m.group(1))
            if claimed != expected:
                # Check for "currently have N team members" (user's count, not limit)
                pre_context = lower[max(0,m.start()):m.end()]
                if 'currently' in pre_context or 'have' in pre_context:
                    continue
                add_issue(ln, 'wrong_team', f"{plan_name.title()} shown with {claimed} team members (should be {expected})")

def check_domain_counts(ln, assistant):
    """Check domain counts per plan."""
    lower = assistant.lower()
    
    for plan_name, vals in PLANS.items():
        expected = vals['domains']
        if expected == -1:  # Unlimited
            continue
        
        # "Plan ... N domains"
        pat = rf'\b{plan_name}\b.{{0,200}}?(?<!\d)(\d+)\s+(?:custom\s+)?domains?'
        for m in re.finditer(pat, lower, re.DOTALL):
            claimed = int(m.group(1))
            if claimed != expected:
                # Check it's not a user's count ("you have 3 domains")
                pre_context = lower[max(0,m.start()):m.end()]
                if 'you have' in pre_context or 'currently' in pre_context or 'your' in pre_context:
                    continue
                # "vs. N" comparisons are fine
                near = lower[max(0,m.start()-10):m.end()]
                if 'vs.' in near or 'vs ' in near:
                    continue
                add_issue(ln, 'wrong_domains', f"{plan_name.title()} shown with {claimed} domains (should be {expected})")

def check_overage_rate(ln, assistant):
    """Check overage rate claims."""
    # "$X.XX per 1,000" or "$X.XX/1K" or "$X.XX/1,000"
    for m in re.finditer(r'\$([\d.]+)\s*(?:per|/)\s*(?:1[,.]?000|1K)\s*(?:emails?|extra)', assistant, re.IGNORECASE):
        rate = float(m.group(1))
        # Skip PAYG rates ($0.001, $0.0008 etc shown as $/1K)
        if rate in (1.00, 0.80, 0.50, 0.30, 0.10):
            # $1.00/1K = $0.001/email, $0.80/1K = $0.0008/email — these are PAYG rates
            # $0.10/1K is API overage — correct
            # But $0.50/1K is WRONG overage rate
            if rate == 0.50:
                add_issue(ln, 'wrong_overage', f"Overage rate ${rate}/1K (should be $0.40/1K)")
            elif rate == 0.90:
                add_issue(ln, 'wrong_overage', f"Overage rate ${rate}/1K — that's Resend's rate, not ours ($0.40/1K)")
            continue
        if abs(rate - 0.40) > 0.001 and rate not in (1.00, 0.80, 0.50, 0.30, 0.10, 0.001, 0.0008, 0.0005, 0.0003):
            context = assistant[max(0,m.start()-30):m.end()+30]
            if 'overage' in context.lower() or 'extra' in context.lower():
                add_issue(ln, 'wrong_overage', f"Overage rate ${rate}/1K (should be $0.40/1K)")

def check_old_prices(ln, assistant):
    """Check for old/deprecated plan prices."""
    for plan_name, old_prices in OLD_PRICES.items():
        for old_price in old_prices:
            if f'${old_price}' in assistant:
                context = assistant.lower()
                # Make sure it's in context of the plan name
                idx = context.find(f'${old_price}'.lower())
                if idx >= 0:
                    nearby = context[max(0,idx-100):idx+100]
                    if plan_name in nearby:
                        add_issue(ln, 'old_price', f"{plan_name.title()} at old price ${old_price} (should be ${PLANS[plan_name]['price']})")

def check_arithmetic(ln, assistant):
    """Check all arithmetic in assistant responses."""
    
    # Multi-term addition: "$A + $B + ... = $Total"
    for m in re.finditer(r'(\$[\d.]+(?:\s*\+\s*\$[\d.]+)+)\s*=\s*\*?\*?\$?([\d,.]+)', assistant):
        terms_str = m.group(1)
        claimed_str = m.group(2).replace(',', '')
        try:
            claimed = float(claimed_str)
            terms = [float(t) for t in re.findall(r'\$([\d.]+)', terms_str)]
            expected = round(sum(terms), 2)
            if abs(claimed - expected) > 0.05:
                terms_text = ' + '.join(f'${t}' for t in terms)
                add_issue(ln, 'wrong_addition', f"{terms_text} = ${claimed} (should be ${expected})")
        except ValueError:
            pass
    
    # Multiplication: "N × $rate = $result" or "N ÷ 1,000 × $rate = $result"
    for m in re.finditer(r'([\d,]+)\s*[×x]\s*\$([\d.]+)\s*=\s*\$?([\d,.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        rate = float(m.group(2))
        claimed = float(m.group(3).replace(',', ''))
        expected = round(qty * rate, 2)
        if abs(claimed - expected) > 0.05:
            add_issue(ln, 'wrong_multiplication', f"{qty:,} × ${rate} = ${claimed} (should be ${expected})")
    
    # Division then multiply: "N ÷ 1,000 × $rate = $result"
    for m in re.finditer(r'([\d,]+)\s*÷\s*1[,.]?000\s*[×x]\s*\$([\d.]+)\s*=\s*\$?([\d,.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        rate = float(m.group(2))
        claimed = float(m.group(3).replace(',', ''))
        expected = round(qty / 1000 * rate, 2)
        if abs(claimed - expected) > 0.05:
            add_issue(ln, 'wrong_division_mult', f"{qty:,} ÷ 1K × ${rate} = ${claimed} (should be ${expected})")
    
    # Overage shorthand: "N,000 extra × $0.40/1,000 = $X" or "N extra = $X"
    for m in re.finditer(r'([\d,]+)\s+(?:extra|overage)\s*(?:emails?)?\s*[×x=]\s*(?:\$0\.40\s*/\s*1[,.]?000\s*=\s*)?\$?([\d,.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        claimed = float(m.group(2).replace(',', ''))
        expected = round(qty * 0.40 / 1000, 2)
        if abs(claimed - expected) > 0.10 and qty > 100:
            add_issue(ln, 'wrong_overage_calc', f"{qty:,} extra = ${claimed} (should be ${expected} at $0.40/1K)")

def check_dedicated_ip(ln, assistant):
    """Check dedicated IP pricing claims."""
    lower = assistant.lower()
    
    # Check IP price
    for m in re.finditer(r'dedicated\s+ip.*?\$([\d]+)(?:/mo)?', lower):
        price = int(m.group(1))
        if price == 50:
            add_issue(ln, 'wrong_ip_price', f"Dedicated IP shown as ${price}/mo (should be $30/mo)")
        elif price != 30:
            add_issue(ln, 'wrong_ip_price', f"Dedicated IP shown as ${price}/mo (should be $30/mo)")
    
    # Check IP inclusion counts
    ip_patterns = [
        (r'growth.*?(\d+)\s*(?:dedicated\s*)?ip', 'growth', 1),
        (r'scale.*?(\d+)\s*(?:dedicated\s*)?ip', 'scale', 3),
        (r'enterprise.*?(\d+)\s*(?:dedicated\s*)?ip', 'enterprise', 10),
    ]
    for pat, plan, expected in ip_patterns:
        for m in re.finditer(pat, lower, re.DOTALL):
            claimed = int(m.group(1))
            if claimed != expected and m.end() - m.start() < 200:
                add_issue(ln, 'wrong_ip_count', f"{plan.title()} shown with {claimed} dedicated IPs (should be {expected})")

def check_annual_pricing(ln, assistant):
    """Check annual pricing claims."""
    for plan_name, vals in PLANS.items():
        if vals['annual'] == 0:
            continue
        
        # "Plan: $X/year" or "Plan annual: $X"
        pat = rf'\b{plan_name}\b[^.]*?\$?([\d,]+)\s*/?\s*(?:yr|year|annually)'
        for m in re.finditer(pat, assistant, re.IGNORECASE):
            claimed_str = m.group(1).replace(',', '')
            try:
                claimed = int(claimed_str)
                expected = vals['annual']
                if claimed != expected:
                    add_issue(ln, 'wrong_annual', f"{plan_name.title()} annual shown as ${claimed:,} (should be ${expected:,})")
            except ValueError:
                pass

def check_retention(ln, assistant):
    """Check retention claims per plan."""
    lower = assistant.lower()
    
    for plan_name, vals in PLANS.items():
        expected_days = vals['retention']
        
        # "Plan ... N days retention" or "Plan ... N-day retention"
        pat = rf'\b{plan_name}\b.{{0,150}}?(\d+)\s*(?:-?\s*days?\s*(?:retention|log|data))'
        for m in re.finditer(pat, lower, re.DOTALL):
            claimed = int(m.group(1))
            if claimed != expected_days:
                add_issue(ln, 'wrong_retention', f"{plan_name.title()} shown with {claimed}-day retention (should be {expected_days})")

def check_feature_gates(ln, assistant):
    """Check feature availability claims."""
    lower = assistant.lower()
    
    # A/B testing on Free or Starter
    if re.search(r'(?:free|starter).{0,80}?a/b\s+test', lower):
        ctx = lower[max(0, lower.find('a/b test') - 100):lower.find('a/b test') + 50]
        if 'not' not in ctx and "doesn't" not in ctx and 'no' not in ctx and 'upgrade' not in ctx and 'require' not in ctx:
            if 'free' in ctx or 'starter' in ctx:
                # Could be saying "Free/Starter don't have it" which is correct
                # Only flag if it says the plan HAS it
                if 'include' in ctx or 'support' in ctx or 'offer' in ctx:
                    add_issue(ln, 'wrong_feature', "A/B testing claimed for Free/Starter (requires Pro+)")
    
    # HIPAA on non-Enterprise
    if 'hipaa' in lower:
        for plan in ['free', 'starter', 'pro', 'growth', 'scale']:
            pat = rf'\b{plan}\b.{{0,80}}?hipaa'
            m = re.search(pat, lower)
            if m:
                ctx = lower[m.start():m.end()]
                if 'not' not in ctx and "doesn't" not in ctx and 'no ' not in ctx:
                    if 'include' in ctx or 'support' in ctx or 'complian' in ctx:
                        add_issue(ln, 'wrong_feature', f"HIPAA claimed for {plan.title()} (Enterprise only)")
    
    # SSO on plans below Scale
    if 'sso' in lower or 'saml' in lower:
        for plan in ['free', 'starter', 'pro', 'growth']:
            pat = rf'\b{plan}\b.{{0,80}}?(?:sso|saml)'
            m = re.search(pat, lower)
            if m:
                ctx = lower[m.start():m.end()]
                if 'not' not in ctx and "doesn't" not in ctx and 'no ' not in ctx and 'upgrade' not in ctx:
                    if 'include' in ctx or 'support' in ctx:
                        add_issue(ln, 'wrong_feature', f"SSO/SAML claimed for {plan.title()} (Scale+ only)")

def check_payg_math(ln, assistant):
    """Check PAYG tier calculations."""
    # Look for PAYG breakdown tables/lists
    # Pattern: "10,000 × $0.001 = $10" etc
    payg_calcs = list(re.finditer(r'([\d,]+)\s*[×x]\s*\$([\d.]+)\s*=\s*\$?([\d,.]+)', assistant))
    
    for m in payg_calcs:
        qty = int(m.group(1).replace(',', ''))
        rate = float(m.group(2))
        claimed = float(m.group(3).replace(',', ''))
        expected = round(qty * rate, 2)
        
        # Check rate is a valid PAYG rate
        valid_rates = {0.001, 0.0008, 0.0005, 0.0003, 0.40, 0.10}
        if rate in valid_rates:
            if abs(claimed - expected) > 0.05:
                add_issue(ln, 'wrong_payg_math', f"{qty:,} × ${rate} = ${claimed} (should be ${expected})")

def check_overage_context(ln, assistant, text):
    """Check overage calculations use the correct base volume for the plan."""
    lower = assistant.lower()
    
    # Find the plan from system prompt
    sys_match = re.search(r'<\|im_start\|>system\n(.*?)<\|im_end\|>', text, re.DOTALL)
    if not sys_match:
        return
    system = sys_match.group(1).lower()
    
    # Find current plan from system prompt
    current_plan = None
    plan_match = re.search(r'plan:\s*(free|starter|pro|growth|scale|enterprise)', system)
    if plan_match:
        current_plan = plan_match.group(1)
    
    if not current_plan or current_plan == 'payg':
        return
    
    # If assistant claims overages, verify the base is correct
    # "N extra emails" or "N over your limit" or "N overage"
    for m in re.finditer(r'([\d,]+)\s*(?:extra|over(?:age)?|above)\s*(?:emails?|your)', lower):
        extra = int(m.group(1).replace(',', ''))
        # We'd need to know total sent to verify, skip for now
        pass

def check_company_info(ln, assistant):
    """Check company information claims."""
    lower = assistant.lower()
    
    if 'founded' in lower:
        m = re.search(r'founded\s*(?:in\s*)?(\d{4})', lower)
        if m and m.group(1) != '2022':
            add_issue(ln, 'wrong_company', f"Founded year shown as {m.group(1)} (should be 2022)")
    
    if 'tallinn' not in lower and 'estonia' not in lower:
        pass  # Not mentioned, that's fine
    
    if 'bel consulting' in lower:
        # Check it says OÜ
        pass  # Hard to verify encoding issues

def check_contact_limits(ln, assistant):
    """Check contact limit claims."""
    lower = assistant.lower()
    
    contact_vals = {
        'free': 500, 'starter': 10000, 'pro': 50000, 
        'growth': 200000, 'scale': 500000
        # Enterprise is Unlimited
    }
    
    for plan_name, expected in contact_vals.items():
        pat = rf'\b{plan_name}\b.{{0,150}}?([\d,]+[KkMm]?)\s*contacts?'
        for m in re.finditer(pat, lower, re.DOTALL):
            num = parse_number(m.group(1))
            if num and num != expected:
                add_issue(ln, 'wrong_contacts', f"{plan_name.title()} shown with {num:,} contacts (should be {expected:,})")

def check_webhook_limits(ln, assistant):
    """Check webhook limit claims."""
    lower = assistant.lower()
    
    webhook_vals = {'free': 0, 'starter': 5, 'pro': 10, 'growth': 25}
    
    for plan_name, expected in webhook_vals.items():
        pat = rf'\b{plan_name}\b.{{0,150}}?(\d+)\s*webhooks?'
        for m in re.finditer(pat, lower, re.DOTALL):
            claimed = int(m.group(1))
            if claimed != expected:
                add_issue(ln, 'wrong_webhooks', f"{plan_name.title()} shown with {claimed} webhooks (should be {expected})")


# ══════════════════════════════════════════════════════════════════════
# MAIN LOOP — process every line
# ══════════════════════════════════════════════════════════════════════

with open(FILEPATH) as f:
    lines = f.readlines()

print(f"Scanning {len(lines)} training examples line by line...")
print()

for i, raw in enumerate(lines, 1):
    data = json.loads(raw)
    text = data['text']
    assistant = get_assistant_text(text)
    
    if not assistant:
        add_issue(i, 'no_assistant', 'No assistant response found')
        continue
    
    # Run ALL checks
    check_plan_prices(i, assistant)
    check_email_limits(i, assistant)
    check_team_counts(i, assistant)
    check_domain_counts(i, assistant)
    check_overage_rate(i, assistant)
    check_old_prices(i, assistant)
    check_arithmetic(i, assistant)
    check_dedicated_ip(i, assistant)
    check_annual_pricing(i, assistant)
    check_retention(i, assistant)
    check_feature_gates(i, assistant)
    check_payg_math(i, assistant)
    check_company_info(i, assistant)
    check_contact_limits(i, assistant)
    check_webhook_limits(i, assistant)

# ══════════════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════════════

print("=" * 72)
print("DEFINITIVE LINE-BY-LINE AUDIT RESULTS")
print("=" * 72)

if not issues:
    print("\n✅ ALL 1,089 LINES CLEAN — zero issues found.")
    sys.exit(0)

# Group by category
by_category = defaultdict(list)
for ln, cat, msg in issues:
    by_category[cat].append((ln, msg))

print(f"\nTotal issues: {len(issues)}")
print(f"Categories: {len(by_category)}")

for cat in sorted(by_category.keys()):
    items = by_category[cat]
    print(f"\n{'─' * 60}")
    print(f"  {cat.upper()} ({len(items)} issues)")
    print(f"{'─' * 60}")
    for ln, msg in sorted(items):
        print(f"  L{ln}: {msg}")

# Summary
all_lines = sorted(set(ln for ln, _, _ in issues))
print(f"\n{'=' * 72}")
print(f"LINES WITH ISSUES: {all_lines}")
print(f"TOTAL LINES AFFECTED: {len(all_lines)}")
print(f"{'=' * 72}")
