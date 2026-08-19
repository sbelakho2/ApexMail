#!/usr/bin/env python3
"""
COMPREHENSIVE TRAINING DATA FIX SCRIPT
=======================================
Fixes 68+ errors across 42 lines in data/train_agent.jsonl.

Uses shared library (tools/lib/) for pricing constants and utilities.

Error categories:
A. Starter domain/team limits: 3→5 domains, 3→5 team (18 lines)
B. Pro domain/team limits: 5→25 domains, 5→10 team (14 lines)
C. Pro email limit: 50K→150K in assistant responses (12 lines)
D. Math/calculation rewrites: wrong arithmetic, wrong overage rates (10 lines)
E. Miscellaneous: wrong rates (€1.50/1K), contradictions
"""

import json
import re
import sys
from pathlib import Path

# Add tools/ to path for shared imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_paths import DATA_DIR
from lib.fix_utils import edit_assistant_text, iter_jsonl, write_jsonl
from lib.pricing import PLANS


# ── File paths (derived from shared common_paths) ─────────────────────────
FILEPATH = DATA_DIR / "train_agent.jsonl"
BACKUP_PATH = DATA_DIR / "train_agent.jsonl.bak2"


def fix_assistant_text(line_num, text):
    """Apply all fixes to assistant responses only. Returns (fixed_text, fixes_applied)."""
    fixes = []
    original_text = text

    edited = edit_assistant_text(text, _fix_assistant_part)

    if edited != original_text:
        fixes.append(f"L{line_num}: Text replacements applied")

    return edited, fixes


def _fix_assistant_part(part):
    """Apply fixes to a single assistant message body."""
    # ─── FIX A: Starter 3 domains → 5 ────────────────────────────
    # Pattern: "3 domains" near Starter context
    if re.search(r'(?:starter|Starter).*?3 domains', part, re.I | re.DOTALL) or \
       re.search(r'3 domains.*?(?:starter|Starter)', part, re.I | re.DOTALL):
        part = re.sub(r'(?<=Starter.*?)3 domains', '5 domains', part, flags=re.DOTALL)
    # More generic: "3 domains" in listing format for Starter
    part = re.sub(r'(Webhooks, )3 domains', r'\g<1>5 domains', part)
    part = re.sub(r'(Starter.*?)3 domains', lambda m: m.group(0).replace('3 domains', '5 domains'), part, flags=re.I|re.DOTALL)

    # "3 team members" near Starter context
    if 'starter' in part.lower():
        part = re.sub(r'(up to \*?\*?)3 team members', r'\g<1>5 team members', part)
        part = re.sub(r'(allows up to \*?\*?)3 team members', r'\g<1>5 team members', part)

    # Table: "Starter ... 3 domains"
    part = re.sub(r'(\|\s*\*?\*?Starter\*?\*?\s*\|[^|]*\|[^|]*\|[^|]*?)3 domains', r'\g<1>5 domains', part)

    # ─── FIX B: Pro 5 domains → 25, 5 team → 10 ─────────────────
    # "Pro ... 5 domains" → "Pro ... 25 domains"
    part = re.sub(r'(\|\s*\*?\*?Pro\*?\*?\s*\|[^|]*\|[^|]*\|[^|]*?)5 domains', r'\g<1>25 domains', part)

    # "Pro includes ... 5 domains (vs. 3)" → "25 domains (vs. 5)"
    part = re.sub(r'(\bPro\b.*?)5 domains \(vs\.\s*3\)', lambda m: m.group(1) + '25 domains (vs. 5)', part, flags=re.I)
    part = re.sub(r'(\bPro\b.*?)5 team members \(vs\.\s*3\)', lambda m: m.group(1) + '10 team members (vs. 5)', part, flags=re.I)

    # "Pro ($65/mo) supports 5 team members"
    part = re.sub(r'(Pro.*?supports\s+)5(\s+team members)', r'\g<1>10\2', part, flags=re.I)
    # "Growth ($150/mo) supports 10" → "supports 25"
    part = re.sub(r'(Growth.*?supports\s+)10\b', r'\g<1>25', part, flags=re.I)

    # Generic: in plan comparison lists
    part = re.sub(r'(- Pro:\s*)5 domains', r'\g<1>25 domains', part)
    part = re.sub(r'(- Starter:\s*)3 domains', r'\g<1>5 domains', part)

    # Feature lists: "5 domains, 5 team members, custom tracking domain"
    lines_list = part.split('\n')
    in_pro_section = False
    in_starter_section = False
    fixed_lines = []
    for ln in lines_list:
        if re.search(r'\bPro\b.*?€65', ln, re.I) or re.search(r'^\*?\*?Pro', ln):
            in_pro_section = True
            in_starter_section = False
        elif re.search(r'\bStarter\b.*?\$25', ln, re.I) or re.search(r'^\*?\*?Starter', ln):
            in_starter_section = True
            in_pro_section = False
        elif re.search(r'\b(?:Growth|Scale|Enterprise|Free)\b', ln, re.I):
            in_pro_section = False
            in_starter_section = False

        if in_pro_section:
            ln = re.sub(r'\b5 domains\b', '25 domains', ln)
            ln = re.sub(r'\b5 team members\b', '10 team members', ln)
        if in_starter_section:
            ln = re.sub(r'\b3 domains\b', '5 domains', ln)
            ln = re.sub(r'\b3 team members\b', '5 team members', ln)

        fixed_lines.append(ln)
    part = '\n'.join(fixed_lines)

    # ─── FIX C: Pro email limit 50K → 150K ──────────────────────
    part = re.sub(r'(Pro\s*\(\$65(?:/mo)?\).*?)\b50,000 emails\b', lambda m: m.group(1) + '150,000 emails', part, flags=re.I)
    part = re.sub(r'(Pro\s*\(\$65(?:/mo)?\)\s*(?:for|includes|with)\s*)50,000\s*emails', r'\g<1>150,000 emails', part, flags=re.I)
    part = re.sub(r'(Pro plan at \$65(?:/month)?\s*includes\s*)50,000\s*emails', r'\g<1>150,000 emails', part, flags=re.I)
    part = re.sub(r'(Pro\s*\(\$65(?:/mo)?\)\s*(?:which gives you|for)\s*)50,000\s*emails', r'\g<1>150,000 emails', part, flags=re.I)
    part = re.sub(r'(Pro.*?)\b50,000 included\b', lambda m: m.group(1) + '150,000 included', part, flags=re.I)
    if re.search(r'Pro plan.*?\$65', part, re.I):
        part = re.sub(r'Includes 50,000 emails/month \(you\'d use 80%\)',
                     'Includes 150,000 emails/month (you\'d use 27%)', part)
        part = re.sub(r'50,000 emails of headroom', '110,000 emails of headroom', part)

    # ─── FIX D: Wrong overage rate ($1.50/1K) ───────────────────
    part = re.sub(r'\$1\.50/1K', '$0.40/1K', part)

    return part


# ═════════════════════════════════════════════════════════════════════════
# Full-response rewrites (line-specific)
# ═════════════════════════════════════════════════════════════════════════

def rewrite_response_l42_l603(text):
    """Fix L42/L603: Starter 35K emails bill. No overages since 35K < 50K."""
    old = """On the **Starter plan ($25/month)**, you get 50,000 emails included.

**Calculation:**
- Overage: 35,000 - 25,000 = **10,000 extra emails**
- Cost: 10,000 ÷ 1,000 × $0.40 = **$5.00**
- Total: $25 + $5 = **$34.00**

Tip: If your volume stays around 35K, the Pro plan ($65) includes 50K emails with no overages. But at 35K, Starter + overages ($34) is still cheaper."""

    new = """On the **Starter plan ($25/month)**, you get 50,000 emails included.

Since 35,000 is **within your 50,000 email limit**, there are **no overages** this month.

**Total bill: $25.00**

You're at **70% usage** — plenty of headroom. If your volume starts exceeding 50K regularly, the **Pro plan ($65/mo)** gives you 150,000 emails/month plus features like custom tracking domains and A/B testing."""

    return text.replace(old, new)


def rewrite_response_l689_l851(text):
    """Fix L689/L851: Starter vs Pro for 30K emails."""
    old = """Let's compare for **30,000 emails/month**:

**Starter ($25/month):**
- 25,000 included → 5,000 overage
- Overage: 5,000 ÷ 1,000 × $0.40 = $2.50
- Total: **$31.50/month**
- 3 domains, 3 team members, analytics, data export

**Pro ($65/month):**
- 50,000 included → no overage
- Total: **$65.00/month**
- 5 domains, 5 team members, custom tracking domain, 60-day retention

**Price difference:** $27.50/month more for Pro.

**Recommendation:** Go with **Starter at $31.50** if you just need basic sending. Choose **Pro at $65** if you need custom tracking domains, more team seats, or expect to grow past 40K/month soon (where Starter overages make Pro cheapest)."""

    new = """Let's compare for **30,000 emails/month**:

**Starter ($25/month):**
- 50,000 included → no overage at 30K
- Total: **$25.00/month**
- 5 domains, 5 team members, webhooks, analytics, data export

**Pro ($65/month):**
- 150,000 included → no overage
- Total: **$65.00/month**
- 25 domains, 10 team members, custom tracking domain, A/B testing, 60-day retention

**Price difference:** $40.00/month more for Pro.

**Recommendation:** Go with **Starter at $25** if you just need basic sending. Choose **Pro at $65** if you need custom tracking domains, A/B testing, more domains (25 vs 5), or expect to grow past 50K/month soon."""

    return text.replace(old, new)


def rewrite_response_l310_l1044(text):
    """Fix L310/L1044: Cost for 40K emails. Starter has 50K, no overages."""
    old = """For **40,000 emails/month**, here are your best options:

**Option 1: Pro plan — $65/month**
- Includes 50,000 emails/month (you'd use 80%)
- 50,000 emails of headroom for growth
- Custom tracking domain, 5 domains

**Option 2: Starter plan — $25/month + overages**
- Includes 50,000 emails. You'd go over by 15,000
- Overage: 15,000 ÷ 1,000 × $0.40 = **$7.50**
- Total: $25 + $7.50 = **$36.50/month**

**Option 3: Pay-As-You-Go**
- First 10K: $0.001 × 10,000 = $10
- Next 30K: $0.0008 × 30,000 = $24
- Total: **$34/month**

**Recommendation:** The **Pro plan at $65** is the most predictable and includes features like custom tracking domains. PAYG is cheaper at $34 but doesn't include a custom tracking domain. The Starter+overage option is the cheapest at $36.50 but you lose domain capacity (3 vs 5)."""

    new = """For **40,000 emails/month**, here are your best options:

**Option 1: Starter plan — $25/month**
- Includes 50,000 emails/month — 40K is within your limit (80% usage)
- No overages at this volume
- 5 domains, 5 team members, webhooks

**Option 2: Pro plan — $65/month**
- Includes 150,000 emails/month — massive headroom for growth
- Custom tracking domain, A/B testing, 25 domains, 10 team members

**Option 3: Pay-As-You-Go**
- First 10K: $0.001 × 10,000 = $10
- Next 30K: $0.0008 × 30,000 = $24
- Total: **$34/month**

**Recommendation:** **Starter at $25** is the best value — 40K fits well within the 50K limit with no overages. Choose **Pro at $65** if you need custom tracking domains, A/B testing, or expect to grow past 50K/month. PAYG at $34 is $9 more than Starter and doesn't include webhooks or templates."""

    return text.replace(old, new)


def rewrite_response_l104_l341(text):
    """Fix L104/L341: PAYG value comparison for 74.2K emails."""
    old = """Let's analyze your **Pay-As-You-Go** costs:

Your current month: **74,200 emails** ≈ **$61** (10K × $0.001 = $10 + 64.2K × $0.0008 = $51.36)

**Compare to monthly plans:**
- **Starter ($25/mo):** 50,000 emails — you'd need overages for 49,200 extra = $24.60 → **$53.60 total** ✅ Cheaper
- **Pro ($65/mo):** 50,000 emails — you'd need overages for 24,200 extra = $12.10 → **$71.10 total** ❌ More expensive
- **Growth ($150/mo):** 500,000 emails — **$150** ❌ More expensive

At your current volume, PAYG at ~$61/mo is a decent deal. However, if you're growing (52K last month → 74K this month), the **Starter plan at $25** plus overages might save you about $7/mo. If you expect to regularly exceed 50K emails, consider upgrading to Pro."""

    new = """Let's analyze your **Pay-As-You-Go** costs:

Your current month: **74,200 emails** ≈ **$61.36** (10K × $0.001 = $10 + 64.2K × $0.0008 = $51.36)

**Compare to monthly plans:**
- **Starter ($25/mo):** 50,000 emails — you'd need overages for 24,200 extra at $0.40/1K = $9.68 → **$34.68 total** ✅ Much cheaper
- **Pro ($65/mo):** 150,000 emails — 74.2K is well within the limit → **$65.00 total** ❌ More expensive, but massive headroom
- **Growth ($150/mo):** 500,000 emails — **$150** ❌ More expensive

At your current volume, **Starter at ~$35/mo** is actually the cheapest option — even cheaper than PAYG at $61. If you're growing (52K last month → 74K this month) and expect to regularly exceed 100K, consider **Pro at $65** which comfortably covers up to 150K with no overages."""

    return text.replace(old, new)


def rewrite_response_l533_l596(text):
    """Fix L533/L596: Starter overage math (2.8K ÷ 1K × $0.40 = $1.12, not $1.40)."""
    text = text.replace(
        '2,800 ÷ 1,000 × $0.40 = **$1.40**',
        '2,800 ÷ 1,000 × $0.40 = **$1.12**'
    )
    text = text.replace(
        'Pro ($65/mo)** which gives you 50,000 emails/month — nearly double the capacity',
        'Pro ($65/mo)** which gives you 150,000 emails/month — triple the capacity'
    )
    return text


def rewrite_response_l783_l964(text):
    """Fix L783/L964: Growth 142K emails. Growth has 500K, no overages."""
    old_calc = """- Overage: 142,000 - 100,000 = **42,000 extra emails**
- Cost: 42,000 ÷ 1,000 × $0.40 = **$21.00**"""

    new_calc = """Since 142,000 is **well within your 500,000 email limit**, there are **no overages** this month.
- Extra cost: **$0.00**"""

    text = text.replace(old_calc, new_calc)
    text = text.replace('$150 + $21 = **$171.00**', '**$150.00**')
    text = text.replace('Total: $150 + $21.00 = **$171.00**', 'Total: **$150.00**')
    text = re.sub(r'\$150\s*\+\s*\$21(?:\.00)?\s*=\s*\*?\*?\$171(?:\.00)?\*?\*?', '**$150.00**', text)
    return text


def rewrite_response_l226_l612(text):
    """Fix L226/L612: 45K on Starter - no overages since 45K < 50K."""
    text = text.replace(
        "If you send 45,000 emails, you'd go over by 35,000",
        "Since 45,000 is within your 50,000 email limit, you have **no overages**"
    )
    text = text.replace(
        '35,000 overage × $1.50/1K = **$52.50**',
        'You still have 5,000 emails remaining in your allocation.'
    )
    text = re.sub(
        r'Total.*?\$77\.50.*?\n?',
        'Total: **$25.00/month** (no overages)\n',
        text
    )
    text = text.replace(
        'the Pro plan ($65/mo) includes 50,000 emails',
        'the Pro plan ($65/mo) includes 150,000 emails'
    )
    text = text.replace(
        "that would save you $27.50/month",
        "but at 45K emails/month you don't need it — Starter covers you perfectly"
    )
    return text


def rewrite_response_l419(text):
    """Fix L419: Starter user, 18,240 of 25,000 → should be 50,000."""
    text = text.replace(
        "you've sent **18,240** of **25,000** emails",
        "you've sent **18,240** of **50,000** emails"
    )
    text = text.replace(
        '25,000 − 18,240 = **6,760 emails**',
        '50,000 − 18,240 = **31,760 emails**'
    )
    text = text.replace(
        '73% of monthly limit',
        '36% of monthly limit'
    )
    text = text.replace(
        'Pro ($65/mo) for 50,000 emails',
        'Pro ($65/mo) for 150,000 emails'
    )
    return text


def rewrite_response_l115_l763(text):
    """Fix L115/L763: Pro comparison for 50K PAYG."""
    text = text.replace(
        'The Pro plan at $65/month includes 50,000 emails plus features like custom tracking dom',
        'The Pro plan at $65/month includes 150,000 emails plus features like custom tracking dom'
    )
    text = text.replace(
        'PAYG saves you $23/month',
        "PAYG saves you $23/month at 50K volume, though Pro gives you 3× the capacity"
    )
    return text


# ═════════════════════════════════════════════════════════════════════════
# Main execution
# ═════════════════════════════════════════════════════════════════════════

def main():
    # Read all lines
    records = list(iter_jsonl(FILEPATH))
    print(f"Read {len(records)} training examples")

    # Backup
    write_jsonl(BACKUP_PATH, records, backup=False)

    # Track fixes
    total_fixes = 0
    fixed_lines = set()

    # Lines with specific full-response rewrites
    specific_rewrites = {
        42: rewrite_response_l42_l603,
        603: rewrite_response_l42_l603,
        689: rewrite_response_l689_l851,
        851: rewrite_response_l689_l851,
        310: rewrite_response_l310_l1044,
        1044: rewrite_response_l310_l1044,
        104: rewrite_response_l104_l341,
        341: rewrite_response_l104_l341,
        533: rewrite_response_l533_l596,
        596: rewrite_response_l533_l596,
        783: rewrite_response_l783_l964,
        964: rewrite_response_l783_l964,
        226: rewrite_response_l226_l612,
        612: rewrite_response_l226_l612,
        419: rewrite_response_l419,
        115: rewrite_response_l115_l763,
        763: rewrite_response_l115_l763,
    }

    # Process each line
    new_records = []
    for i, rec in records:
        text = rec['text']
        original = text

        # Apply specific rewrites first
        if i in specific_rewrites:
            text = specific_rewrites[i](text)

        # Apply general fixes (domain/team/email limits in all lines)
        text, fixes = fix_assistant_text(i, text)

        if text != original:
            fixed_lines.add(i)
            total_fixes += 1

        rec['text'] = text
        new_records.append(rec)

    # Write fixed data
    write_jsonl(FILEPATH, new_records, backup=False)

    print(f"\n{'='*60}")
    print(f"FIXES APPLIED: {total_fixes} lines modified")
    print(f"Fixed lines: {sorted(fixed_lines)}")
    print(f"{'='*60}")

    return total_fixes


if __name__ == '__main__':
    n = main()
    print(f"\nDone. {n} lines fixed.")
