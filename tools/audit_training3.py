#!/usr/bin/env python3
"""Comprehensive audit of train_agent.jsonl - correct format."""
import json, re, sys

with open("data/train_agent.jsonl", "r") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# Parse each line and extract text content
all_texts = []  # (line_num, text)
for i, line in enumerate(lines, 1):
    try:
        obj = json.loads(line.strip())
        text = obj.get("text", "")
        if text:
            all_texts.append((i, text))
    except Exception as e:
        print(f"Line {i}: PARSE ERROR: {e}")

print(f"Total entries: {len(all_texts)}")
print("=" * 120)

def search_all(pattern, label, flags=re.IGNORECASE):
    print(f"\n{'='*80}")
    print(f"SEARCH: {label}")
    print(f"{'='*80}")
    count = 0
    for line_num, text in all_texts:
        for m in re.finditer(pattern, text, flags):
            start = max(0, m.start()-150)
            end = min(len(text), m.end()+150)
            ctx = text[start:end].replace("\n", "\\n")
            print(f"  L{line_num}: ...{ctx}...")
            count += 1
            if count > 50:
                print("  ... (truncated, too many matches)")
                return count
    print(f"  => {count} matches")
    return count

# ============================================================================
# 1. CHECK ALL PRICES
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 1: PRICING AUDIT")
print("#"*80)

# Correct prices
search_all(r'\$25\s*/?\s*(?:mo|month|per\s*month)', 'Starter $25/mo (CORRECT)')
search_all(r'\$65\s*/?\s*(?:mo|month|per\s*month)', 'Pro $65/mo (CORRECT)')
search_all(r'\$150\s*/?\s*(?:mo|month|per\s*month)', 'Growth $150/mo (CORRECT)')
search_all(r'\$350\s*/?\s*(?:mo|month|per\s*month)', 'Scale $350/mo (CORRECT)')
search_all(r'\$800\s*/?\s*(?:mo|month|per\s*month)', 'Enterprise $800/mo (CORRECT)')

# OLD/WRONG prices
search_all(r'\$29\s*/?\s*(?:mo|month|per\s*month)', 'OLD WRONG: Starter $29/mo')
search_all(r'\$59\s*/?\s*(?:mo|month|per\s*month)', 'OLD WRONG: Pro $59/mo')
search_all(r'\$129\s*/?\s*(?:mo|month|per\s*month)', 'OLD WRONG: Growth $129/mo')
search_all(r'\$399\s*/?\s*(?:mo|month|per\s*month)', 'OLD WRONG: Scale $399/mo')
search_all(r'\$1,?299\s*/?\s*(?:mo|month|per\s*month)', 'OLD WRONG: Enterprise $1299/mo')

# Find ALL dollar-per-month amounts to catch any we missed
search_all(r'\$[\d,]+\s*/?\s*(?:mo|month|per\s*month)\b', 'ALL $/mo amounts')

# Dedicated IP add-on price
search_all(r'dedicated\s*IP.*?\$\d+', 'Dedicated IP pricing')
search_all(r'\$\d+.*?dedicated\s*IP', 'Dedicated IP pricing (reversed)')
search_all(r'\$30\s*/?\s*(?:mo|month)', '$30/mo (correct dedicated IP add-on)')
search_all(r'\$20\s*/?\s*(?:mo|month)|dedicated.*?\$20|\$20.*?dedicated', 'WRONG: $20 dedicated IP')
search_all(r'\$50\s*/?\s*(?:mo|month)|dedicated.*?\$50|\$50.*?dedicated', 'Check: $50/mo')

# Overage pricing
search_all(r'\$0\.40', 'Overage $0.40/1K (CORRECT)')
search_all(r'overage.*?\$[\d.]+', 'Overage pricing mentions')
search_all(r'\$[\d.]+.*?overage', 'Overage pricing mentions (reversed)')

# PAYG pricing
search_all(r'\$0\.001', 'PAYG $0.001 (CORRECT)')
search_all(r'\$0\.0003', 'PAYG $0.0003 (CORRECT)')
search_all(r'pay.as.you.go|PAYG', 'PAYG mentions')

# ============================================================================
# 2. EMAIL VOLUMES
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 2: EMAIL VOLUME AUDIT")
print("#"*80)

# Correct volumes
search_all(r'3,000\s*(?:emails?|messages?)', '3,000 emails (Free - CORRECT)')
search_all(r'50,000\s*(?:emails?|messages?)', '50,000 emails (Starter - CORRECT)')
search_all(r'150,000\s*(?:emails?|messages?)', '150,000 emails (Pro - CORRECT)')
search_all(r'500,000\s*(?:emails?|messages?)', '500,000 emails (Growth - CORRECT)')
search_all(r'2,000,000\s*(?:emails?|messages?)', '2,000,000 emails (Scale - CORRECT)')
search_all(r'5,000,000\s*(?:emails?|messages?)', '5,000,000 emails (Enterprise - CORRECT)')

# Also check shorthand
search_all(r'(?:3K|3k)\s*(?:emails?|messages?)', '3K emails')
search_all(r'(?:50K|50k)\s*(?:emails?|messages?)', '50K emails')
search_all(r'(?:150K|150k)\s*(?:emails?|messages?)', '150K emails')
search_all(r'(?:500K|500k)\s*(?:emails?|messages?)', '500K emails')
search_all(r'(?:2M|2m)\s*(?:emails?|messages?)', '2M emails')
search_all(r'(?:5M|5m)\s*(?:emails?|messages?)', '5M emails')

# Wrong volumes
search_all(r'(?:1,000|1K|1k)\s*(?:emails?|messages?)\s*/\s*(?:mo|month)', 'WRONG: 1K emails/mo')
search_all(r'(?:10,000|10K|10k)\s*(?:emails?|messages?)\s*/\s*(?:mo|month)', 'Check: 10K emails/mo')
search_all(r'(?:100,000|100K|100k)\s*(?:emails?|messages?)\s*/\s*(?:mo|month)', 'Check: 100K emails/mo')
search_all(r'(?:250,000|250K|250k)\s*(?:emails?|messages?)', 'Check: 250K emails')
search_all(r'(?:1,000,000|1M|1m)\s*(?:emails?|messages?)', 'Check: 1M emails')

# ============================================================================
# 3. PLAN LIMITS (domains, team members, retention)
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 3: PLAN LIMITS AUDIT")
print("#"*80)

# Domains per plan  
search_all(r'(?:1|one)\s*domain.*?(?:free|Free)', '1 domain Free')
search_all(r'(?:free|Free).*?(?:1|one)\s*domain', '1 domain Free (reversed)')
search_all(r'(?:5|five)\s*domains?.*?(?:starter|Starter)', '5 domains Starter')
search_all(r'(?:starter|Starter).*?(?:5|five)\s*domains?', '5 domains Starter (reversed)')
search_all(r'(?:25|twenty.five)\s*domains?.*?(?:pro|Pro)', '25 domains Pro')
search_all(r'(?:pro|Pro).*?(?:25|twenty.five)\s*domains?', '25 domains Pro (reversed)')
search_all(r'(?:100|one\s*hundred)\s*domains?.*?(?:growth|Growth)', '100 domains Growth')
search_all(r'unlimited\s*domains?', 'Unlimited domains')

# Team members
search_all(r'(?:1|one)\s*(?:team\s*member|user|seat).*?(?:free|Free)', '1 team member Free')
search_all(r'(?:5|five)\s*(?:team\s*members?|users?|seats?).*?(?:starter|Starter)', '5 team members Starter')
search_all(r'(?:10|ten)\s*(?:team\s*members?|users?|seats?).*?(?:pro|Pro)', '10 team members Pro')
search_all(r'(?:25|twenty.five)\s*(?:team\s*members?|users?|seats?).*?(?:growth|Growth)', '25 team members Growth')
search_all(r'(?:50|fifty)\s*(?:team\s*members?|users?|seats?).*?(?:scale|Scale)', '50 team members Scale')

# Retention
search_all(r'7[\s-]*day\s*(?:retention|log|data|history)', '7-day retention (Free)')
search_all(r'30[\s-]*day\s*(?:retention|log|data|history)', '30-day retention (Starter)')
search_all(r'60[\s-]*day\s*(?:retention|log|data|history)', '60-day retention (Pro)')
search_all(r'90[\s-]*day\s*(?:retention|log|data|history)', '90-day retention (Growth)')
search_all(r'365[\s-]*day\s*(?:retention|log|data|history)', '365-day retention (Scale)')

# ============================================================================
# 4. FEATURES BY PLAN
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 4: FEATURE AVAILABILITY AUDIT")
print("#"*80)

# SSO/SAML - should be Scale+ NOT Enterprise-only
search_all(r'SSO', 'All SSO mentions')
search_all(r'SAML', 'All SAML mentions')

# HIPAA - Enterprise only
search_all(r'HIPAA', 'All HIPAA mentions')

# SOC 2
search_all(r'SOC\s*2', 'All SOC 2 mentions')

# BYOIP - Enterprise only
search_all(r'BYOIP', 'All BYOIP mentions')

# White-label - Enterprise only
search_all(r'white[\s-]*label', 'All white-label mentions')

# Audit logs - Growth+
search_all(r'audit\s*log', 'All audit log mentions')

# A/B testing - Pro+
search_all(r'A/B\s*test', 'All A/B testing mentions')

# Dedicated IP
search_all(r'dedicated\s*IP', 'All dedicated IP mentions')

# Inbound email - All plans
search_all(r'inbound\s*(?:email|mail|processing|routing|pars)', 'All inbound email mentions')

# Send-time optimization - All plans
search_all(r'send[\s-]*time\s*optim', 'All send-time optimization mentions')

# ============================================================================
# 5. ARCHITECTURE
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 5: ARCHITECTURE AUDIT")
print("#"*80)

search_all(r'AWS', 'All AWS mentions')
search_all(r'Hetzner', 'All Hetzner mentions')
search_all(r'self[\s-]*host', 'Self-hosted mentions')
search_all(r'port\s*3000', 'API port 3000')
search_all(r'port\s*4100', 'Billing port 4100')
search_all(r'PostgreSQL|Postgres', 'PostgreSQL/Postgres')
search_all(r'Redis', 'Redis mentions')

# ============================================================================
# 6. DEDICATED IPs COUNTS
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 6: DEDICATED IP COUNTS")
print("#"*80)

search_all(r'(?:1|one)\s*dedicated\s*IP', '1 dedicated IP')
search_all(r'(?:2|two)\s*dedicated\s*IP', '2 dedicated IPs')
search_all(r'(?:3|three)\s*dedicated\s*IP', '3 dedicated IPs')
search_all(r'(?:5|five)\s*dedicated\s*IP', '5 dedicated IPs')
search_all(r'(?:10|ten)\s*dedicated\s*IP', '10 dedicated IPs')

# ============================================================================
# 7. SUBACCOUNTS
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 7: SUBACCOUNTS")
print("#"*80)

search_all(r'subaccount', 'All subaccount mentions')
search_all(r'sub[\s-]*account', 'All sub-account mentions')

# ============================================================================
# 8. SLA
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 8: SLA")
print("#"*80)

search_all(r'SLA\s*\d', 'SLA with numbers')
search_all(r'99\.\d+%', 'Uptime percentages')
search_all(r'99\.9', '99.9% mentions')

# ============================================================================
# 9. SUPPORT TIERS
# ============================================================================
print("\n\n" + "#"*80)
print("# SECTION 9: SUPPORT TIERS")
print("#"*80)

search_all(r'community\s*support', 'Community support')
search_all(r'email\s*support', 'Email support')
search_all(r'priority\s*support', 'Priority support')
search_all(r'phone\s*support', 'Phone support')
search_all(r'dedicated\s*(?:account\s*)?manager', 'Dedicated account manager')

print("\n\nAUDIT COMPLETE")
