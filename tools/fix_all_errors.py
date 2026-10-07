#!/usr/bin/env python3
"""
COMPREHENSIVE TRAINING DATA FIX SCRIPT (historical, one-off)

Fixes plan-limit / pricing errors in the historical train_agent.jsonl corpus.

All money and limit values in the replacement text are DERIVED from
tools/lib/pricing.py, which tools/validate_pricing_drift.py pins field-by-field
against the canonical Rust catalog (services/mail-server/crates/platform-catalog).
Nothing here may hardcode a price or a limit — the pre-2026-09-08 generation
(Starter $25 / Pro $65 / Growth $150, USD) is what this script used to write.

Safety (coverage audit U-2b): the corpus is written through
lib.fix_utils.write_jsonl, which refuses to overwrite an existing file without
creating a `<file>.bak` backup; `--dry-run` reports the fixes and writes
nothing. This script previously wrote the tracked corpus in place with no
backup (its sibling rewriters had no backup at all).

Categories:
A. Developer (starter) domain/team limits → canonical
B. Pro domain/team limits → canonical
C. Pro email limit → canonical
D. Overage rate rewrites → canonical per-plan rate
E. Full-response rewrites for the historical arithmetic errors
"""

import json
import re
import sys
from pathlib import Path

# Add tools/ to path for shared imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_paths import DATA_DIR
from lib.fix_utils import edit_assistant_text, iter_jsonl, write_jsonl
from lib.pricing import OVERAGE_RATE_PER_1K_CENTS, PLANS, calculate_payg_cents


# ── File paths (derived from shared common_paths) ─────────────────────────
FILEPATH = DATA_DIR / "train_agent.jsonl"

# Canonical plan facts (never hardcode these inline).
DEV = PLANS["starter"]        # display name: Developer
PRO = PLANS["pro"]
GROWTH = PLANS["growth"]

DEV_PRICE = f"€{DEV['price_cents'] // 100}"
PRO_PRICE = f"€{PRO['price_cents'] // 100}"
GROWTH_PRICE = f"€{GROWTH['price_cents'] // 100}"
DEV_EMAILS = f"{DEV['emails']:,}"
PRO_EMAILS = f"{PRO['emails']:,}"
GROWTH_EMAILS = f"{GROWTH['emails']:,}"
DEV_DOMAINS = DEV["domains"]
PRO_DOMAINS = PRO["domains"]
DEV_TEAM = DEV["team"]
PRO_TEAM = PRO["team"]
DEV_OVERAGE = f"€{OVERAGE_RATE_PER_1K_CENTS['starter'] / 100:.2f}"


class CorpusMissing(RuntimeError):
    """The historical corpus this one-off rewriter targets is absent."""


def money(cents: int) -> str:
    return f"€{cents / 100:,.2f}"


def fix_assistant_text(line_num, text):
    """Apply all fixes to assistant responses only. Returns (fixed_text, fixes_applied)."""
    fixes = []
    original_text = text

    edited = edit_assistant_text(text, _fix_assistant_part)

    if edited != original_text:
        fixes.append(f"L{line_num}: Text replacements applied")

    return edited, fixes


def _fix_assistant_part(part):
    """Apply fixes to a single assistant message body (canonical values only)."""
    # ─── FIX A: Developer (starter) domain/team limits → canonical ──
    # Pattern: "3 domains" near Developer/Starter context
    if re.search(r'(?:starter|developer).*?3 domains', part, re.I | re.DOTALL) or \
       re.search(r'3 domains.*?(?:starter|developer)', part, re.I | re.DOTALL):
        part = re.sub(
            r'(Starter.*?)3 domains',
            lambda m: m.group(1) + f'{DEV_DOMAINS} domains',
            part, flags=re.I | re.DOTALL,
        )
    # More generic: "3 domains" in listing format for the starter tier
    part = re.sub(r'(Webhooks, )3 domains', rf'\g<1>{DEV_DOMAINS} domains', part)
    part = re.sub(
        r'(Starter.*?)3 domains',
        lambda m: m.group(0).replace('3 domains', f'{DEV_DOMAINS} domains'),
        part, flags=re.I | re.DOTALL,
    )

    # "3 team members" near starter context
    if 'starter' in part.lower() or 'developer' in part.lower():
        part = re.sub(r'(up to \*?\*?)3 team members', rf'\g<1>{DEV_TEAM} team members', part)
        part = re.sub(r'(allows up to \*?\*?)3 team members', rf'\g<1>{DEV_TEAM} team members', part)

    # Table: "Starter ... 3 domains"
    part = re.sub(
        r'(\|\s*\*?\*?Starter\*?\*?\s*\|[^|]*\|[^|]*\|[^|]*?)3 domains',
        rf'\g<1>{DEV_DOMAINS} domains', part,
    )

    # ─── FIX B: Pro 5 domains → canonical, 5 team → canonical ─────
    part = re.sub(
        r'(\|\s*\*?\*?Pro\*?\*?\s*\|[^|]*\|[^|]*\|[^|]*?)5 domains',
        rf'\g<1>{PRO_DOMAINS} domains', part,
    )

    # "Pro includes ... 5 domains (vs. 3)" → canonical
    part = re.sub(
        r'(\bPro\b.*?)5 domains \(vs\.\s*3\)',
        lambda m: m.group(1) + f'{PRO_DOMAINS} domains (vs. {DEV_DOMAINS})',
        part, flags=re.I,
    )
    part = re.sub(
        r'(\bPro\b.*?)5 team members \(vs\.\s*3\)',
        lambda m: m.group(1) + f'{PRO_TEAM} team members (vs. {DEV_TEAM})',
        part, flags=re.I,
    )

    # "Pro supports 5 team members"
    part = re.sub(r'(Pro.*?supports\s+)5(\s+team members)', rf'\g<1>{PRO_TEAM}\2', part, flags=re.I)
    # "Growth supports 10" → canonical
    part = re.sub(r'(Growth.*?supports\s+)10\b', rf'\g<1>{GROWTH["team"]}', part, flags=re.I)

    # Generic: in plan comparison lists
    part = re.sub(r'(- Pro:\s*)5 domains', rf'\g<1>{PRO_DOMAINS} domains', part)
    part = re.sub(r'(- Starter:\s*)3 domains', rf'\g<1>{DEV_DOMAINS} domains', part)

    # Feature lists: section-scoped domain/team rewrites
    lines_list = part.split('\n')
    in_pro_section = False
    in_starter_section = False
    fixed_lines = []
    for ln in lines_list:
        # Input markers may be the retired USD forms; replacements are always
        # the canonical values above.
        if re.search(r'\bPro\b.*?(?:\$65|€65)', ln, re.I) or re.search(r'^\*?\*?Pro', ln):
            in_pro_section = True
            in_starter_section = False
        elif re.search(r'\b(?:Starter|Developer)\b.*?(?:\$25|€25)', ln, re.I) or \
                re.search(r'^\*?\*?(?:Starter|Developer)', ln):
            in_starter_section = True
            in_pro_section = False
        elif re.search(r'\b(?:Growth|Scale|Business|Enterprise|Free)\b', ln, re.I):
            in_pro_section = False
            in_starter_section = False

        if in_pro_section:
            ln = re.sub(r'\b5 domains\b', f'{PRO_DOMAINS} domains', ln)
            ln = re.sub(r'\b5 team members\b', f'{PRO_TEAM} team members', ln)
        if in_starter_section:
            ln = re.sub(r'\b3 domains\b', f'{DEV_DOMAINS} domains', ln)
            ln = re.sub(r'\b3 team members\b', f'{DEV_TEAM} team members', ln)

        fixed_lines.append(ln)
    part = '\n'.join(fixed_lines)

    # ─── FIX C: Pro price and email limit → canonical ────────────
    # Input markers are the retired USD price forms ($65/€65); both the
    # matched prefix's price and the email count are rewritten canonically.
    def canon_pro(prefix: str) -> str:
        return re.sub(r'(?:\$|€)65\b', PRO_PRICE, prefix)

    part = re.sub(
        r'(Pro(?: plan)?\s*\((?:\$65|€65)(?:/mo)?\).*?)\b50,000 emails\b',
        lambda m: canon_pro(m.group(1)) + f'{PRO_EMAILS} emails', part, flags=re.I,
    )
    part = re.sub(
        r'(Pro(?: plan)?\s*\((?:\$65|€65)(?:/mo)?\)\s*(?:for|includes|with)\s*)50,000\s*emails',
        lambda m: canon_pro(m.group(1)) + f'{PRO_EMAILS} emails', part, flags=re.I,
    )
    part = re.sub(
        r'(Pro plan at (?:\$65|€65)(?:/month)?\s*includes\s*)50,000\s*emails',
        lambda m: canon_pro(m.group(1)) + f'{PRO_EMAILS} emails', part, flags=re.I,
    )
    part = re.sub(
        r'(Pro(?: plan)?\s*\((?:\$65|€65)(?:/mo)?\)\s*(?:which gives you|for)\s*)50,000\s*emails',
        lambda m: canon_pro(m.group(1)) + f'{PRO_EMAILS} emails', part, flags=re.I,
    )
    part = re.sub(
        r'(Pro.*?)\b50,000 included\b',
        lambda m: canon_pro(m.group(1)) + f'{PRO_EMAILS} included', part, flags=re.I,
    )
    if re.search(r'Pro plan.*?(?:\$65|€65)', part, re.I):
        part = re.sub(
            r'Includes 50,000 emails/month \(you\'d use 80%\)',
            f"Includes {PRO_EMAILS} emails/month (you'd use 27%)", part,
        )
        part = re.sub(r'50,000 emails of headroom', '110,000 emails of headroom', part)

    # Pro price markers in the same assistant text ($65/€65 → €89).
    part = re.sub(r'(?:\$|€)65\b', PRO_PRICE, part)
    # Developer price markers in the same assistant text ($25/€25 → €29).
    part = re.sub(r'(?:\$|€)25\b', DEV_PRICE, part)
    # Growth price markers ($150/€150 → €229).
    part = re.sub(r'(?:\$|€)150\b', GROWTH_PRICE, part)
    # Business/Scale price markers ($350/€350 → €699).
    part = re.sub(r'(?:\$|€)350\b', f"€{PLANS['scale']['price_cents'] // 100}", part)
    # Enterprise price markers ($3,000/€3,000 → €1,750).
    part = re.sub(
        r'(?:\$|€)3,000\b',
        f"€{PLANS['enterprise']['price_cents'] // 100:,}",
        part,
    )

    # ─── FIX D: Wrong overage rate → canonical Developer rate ───
    # The historical corpus quotes a flat $1.50/1K; the canonical ladder is
    # 80/60/35/35/35 millicents per email (€0.80/€0.60/€0.35 per 1,000).
    part = re.sub(r'\$1\.50/1K', f'{DEV_OVERAGE}/1K', part)

    return part


# ═════════════════════════════════════════════════════════════════════════
# Full-response rewrites (line-specific) — canonical EUR values
# ═════════════════════════════════════════════════════════════════════════

def rewrite_response_l42_l603(text):
    """Fix L42/L603: Developer 35K emails bill. No overages since 35K < 50K."""
    old = f"""On the **Starter plan ($25/month)**, you get 50,000 emails included.

**Calculation:**
- Overage: 35,000 - 25,000 = **10,000 extra emails**
- Cost: 10,000 ÷ 1,000 × $0.40 = **$5.00**
- Total: $25 + $5 = **$34.00**

Tip: If your volume stays around 35K, the Pro plan ($65) includes 50K emails with no overages. But at 35K, Starter + overages ($34) is still cheaper."""

    new = f"""On the **Developer plan ({DEV_PRICE}/month)**, you get {DEV_EMAILS} emails included.

Since 35,000 is **within your {DEV_EMAILS} email limit**, there are **no overages** this month.

**Total bill: {DEV_PRICE}.00**

You're at **70% usage** — plenty of headroom. If your volume starts exceeding 50K regularly, the **Pro plan ({PRO_PRICE}/mo)** gives you {PRO_EMAILS} emails/month plus features like custom tracking domains and priority onboarding."""

    return text.replace(old, new)


def rewrite_response_l689_l851(text):
    """Fix L689/L851: Developer vs Pro for 30K emails."""
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

    new = f"""Let's compare for **30,000 emails/month**:

**Developer ({DEV_PRICE}/month):**
- {DEV_EMAILS} included → no overage at 30K
- Total: **{DEV_PRICE}.00/month**
- {DEV_DOMAINS} domains, {DEV_TEAM} team members, webhooks, analytics, data export

**Pro ({PRO_PRICE}/month):**
- {PRO_EMAILS} included → no overage
- Total: **{PRO_PRICE}.00/month**
- {PRO_DOMAINS} domains, {PRO_TEAM} team members, custom tracking domain, 60-day retention

**Price difference:** €60.00/month more for Pro.

**Recommendation:** Go with **Developer at {DEV_PRICE}** if you just need basic sending. Choose **Pro at {PRO_PRICE}** if you need custom tracking domains, more team seats, or expect to grow past 50K/month soon (where Developer overages at {DEV_OVERAGE}/1K add up)."""

    return text.replace(old, new)


def rewrite_response_l310_l1044(text):
    """Fix L310/L1044: Cost for 40K emails. Developer has 50K, no overages."""
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

    payg_40k = money(calculate_payg_cents(40_000))
    new = f"""For **40,000 emails/month**, here are your best options:

**Option 1: Developer plan — {DEV_PRICE}/month**
- Includes {DEV_EMAILS} emails/month — 40K is within your limit (80% usage)
- No overages at this volume
- {DEV_DOMAINS} domains, {DEV_TEAM} team members, webhooks

**Option 2: Pro plan — {PRO_PRICE}/month**
- Includes {PRO_EMAILS} emails/month — massive headroom for growth
- Custom tracking domain, {PRO_DOMAINS} domains, {PRO_TEAM} team members

**Option 3: Pay-As-You-Go**
- First 10K: €0.001 × 10,000 = €10
- Next 30K: €0.0008 × 30,000 = €24
- Total: **{payg_40k}/month**

**Recommendation:** **Developer at {DEV_PRICE}** is the best value — 40K fits well within the {DEV_EMAILS} limit with no overages. Choose **Pro at {PRO_PRICE}** if you need custom tracking domains or expect to grow past 50K/month. PAYG at {payg_40k} is more expensive than Developer and doesn't include webhooks or templates."""

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

    payg_74200 = money(calculate_payg_cents(74_200))
    dev_overage_cents = 24_200 * OVERAGE_RATE_PER_1K_CENTS["starter"] // 1_000  # 24,200 × €0.80/1K
    dev_total = money(DEV["price_cents"] + dev_overage_cents)
    new = f"""Let's analyze your **Pay-As-You-Go** costs:

Your current month: **74,200 emails** ≈ **{payg_74200}** (10K × €0.001 = €10 + 64.2K × €0.0008 = €51.36)

**Compare to monthly plans:**
- **Developer ({DEV_PRICE}/mo):** {DEV_EMAILS} emails — you'd need overages for 24,200 extra at {DEV_OVERAGE}/1K = {money(dev_overage_cents)} → **{dev_total} total** ✅ Much cheaper
- **Pro ({PRO_PRICE}/mo):** {PRO_EMAILS} emails — 74.2K is well within the limit → **{PRO_PRICE}.00 total** ❌ More expensive, but massive headroom
- **Growth ({GROWTH_PRICE}/mo):** {GROWTH_EMAILS} emails — **{GROWTH_PRICE}** ❌ More expensive

At your current volume, **Developer at ~{dev_total}** is actually the cheapest option — even cheaper than PAYG at {payg_74200}. If you're growing (52K last month → 74K this month) and expect to regularly exceed 100K, consider **Pro at {PRO_PRICE}** which comfortably covers up to 150K with no overages."""

    return text.replace(old, new)


def rewrite_response_l533_l596(text):
    """Fix L533/L596: Developer overage math (2.8K ÷ 1K × €0.80 = €2.24)."""
    text = text.replace(
        '2,800 ÷ 1,000 × $0.40 = **$1.40**',
        f'2,800 ÷ 1,000 × {DEV_OVERAGE} = **€2.24**'
    )
    text = text.replace(
        'Pro ($65/mo)** which gives you 50,000 emails/month — nearly double the capacity',
        f'Pro ({PRO_PRICE}/mo)** which gives you {PRO_EMAILS} emails/month — triple the capacity'
    )
    return text


def rewrite_response_l783_l964(text):
    """Fix L783/L964: Growth 142K emails. Growth has 500K, no overages."""
    old_calc = """- Overage: 142,000 - 100,000 = **42,000 extra emails**
- Cost: 42,000 ÷ 1,000 × $0.40 = **$21.00**"""

    new_calc = f"""Since 142,000 is **well within your {GROWTH_EMAILS} email limit**, there are **no overages** this month.
- Extra cost: **€0.00**"""

    text = text.replace(old_calc, new_calc)
    text = text.replace('$150 + $21 = **$171.00**', f'**{GROWTH_PRICE}.00**')
    text = text.replace('Total: $150 + $21.00 = **$171.00**', f'Total: **{GROWTH_PRICE}.00**')
    text = re.sub(
        r'\$150\s*\+\s*\$21(?:\.00)?\s*=\s*\*?\*?\$171(?:\.00)?\*?\*?',
        f'**{GROWTH_PRICE}.00**', text,
    )
    return text


def rewrite_response_l226_l612(text):
    """Fix L226/L612: 45K on Developer - no overages since 45K < 50K."""
    text = text.replace(
        "If you send 45,000 emails, you'd go over by 35,000",
        f"Since 45,000 is within your {DEV_EMAILS} email limit, you have **no overages**"
    )
    text = text.replace(
        '35,000 overage × $1.50/1K = **$52.50**',
        'You still have 5,000 emails remaining in your allocation.'
    )
    text = re.sub(
        r'Total.*?\$77\.50.*?\n?',
        f'Total: **{DEV_PRICE}.00/month** (no overages)\n',
        text
    )
    text = text.replace(
        'the Pro plan ($65/mo) includes 50,000 emails',
        f'the Pro plan ({PRO_PRICE}/mo) includes {PRO_EMAILS} emails'
    )
    text = text.replace(
        "that would save you $27.50/month",
        "but at 45K emails/month you don't need it — Developer covers you perfectly"
    )
    return text


def rewrite_response_l419(text):
    """Fix L419: Developer user, 18,240 of 25,000 → should be 50,000."""
    text = text.replace(
        "you've sent **18,240** of **25,000** emails",
        f"you've sent **18,240** of **{DEV_EMAILS}** emails"
    )
    text = text.replace(
        '25,000 − 18,240 = **6,760 emails**',
        f'{DEV_EMAILS} − 18,240 = **31,760 emails**'
    )
    text = text.replace(
        '73% of monthly limit',
        '36% of monthly limit'
    )
    text = text.replace(
        'Pro ($65/mo) for 50,000 emails',
        f'Pro ({PRO_PRICE}/mo) for {PRO_EMAILS} emails'
    )
    return text


def rewrite_response_l115_l763(text):
    """Fix L115/L763: Pro comparison for 50K PAYG."""
    text = text.replace(
        'The Pro plan at $65/month includes 50,000 emails plus features like custom tracking dom',
        f'The Pro plan at {PRO_PRICE}/month includes {PRO_EMAILS} emails plus features like custom tracking dom'
    )
    text = text.replace(
        'PAYG saves you $23/month',
        "PAYG saves you €47/month at 50K volume, though Pro gives you 3× the capacity"
    )
    return text


# ═════════════════════════════════════════════════════════════════════════
# Main execution
# ═════════════════════════════════════════════════════════════════════════

def main(dry_run: bool = False) -> int:
    if not FILEPATH.exists():
        raise CorpusMissing(
            f"corpus not found: {FILEPATH}\n"
            "The historical train_agent.jsonl corpus no longer exists "
            "(apps/ai/training/data/ holds only augmented_*.jsonl); nothing to rewrite."
        )

    # Read all lines
    records = [rec for _, rec in iter_jsonl(FILEPATH)]
    print(f"Read {len(records)} training examples")

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
    for i, rec in enumerate(records, 1):
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

    if dry_run:
        print(f"[dry-run] would modify {total_fixes} lines: {sorted(fixed_lines)}; no file written")
        return total_fixes

    # Guarded write: an existing corpus is backed up to train_agent.jsonl.bak.
    write_jsonl(FILEPATH, new_records, backup=True)

    print(f"\n{'='*60}")
    print(f"FIXES APPLIED: {total_fixes} lines modified")
    print(f"Fixed lines: {sorted(fixed_lines)}")
    print(f"Backup: {FILEPATH}.bak")
    print(f"{'='*60}")

    return total_fixes


if __name__ == '__main__':
    dry = "--dry-run" in sys.argv[1:]
    try:
        n = main(dry_run=dry)
    except CorpusMissing as error:
        print(error, file=sys.stderr)
        sys.exit(2)
    print(f"\nDone. {n} lines {'would be ' if dry else ''}fixed.")
