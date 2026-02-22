#!/usr/bin/env python3
"""One-time script to fix training data issues in train_agent.jsonl.

Fixes:
  1. Wrong SLA table (Starter=99.5%, Scale=99.95%, Enterprise=99.99%)
     → Correct: SLA only on Scale+Enterprise, both 99.9%
  2. Hetzner/PostgreSQL/Redis infrastructure leaks in customer responses
  3. GDPR deletion response mentioning PostgreSQL/Redis/S3
  4. DPA responses mentioning Hetzner
"""
import os
import sys

TRAIN_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "train_agent.jsonl")

def main():
    with open(TRAIN_FILE, "r") as f:
        data = f.read()

    original_len = len(data)
    total = 0

    # ── Fix 1: Wrong SLA table ─────────────────────────────────────────
    old_sla = (
        '| Free | None | \\u2014 |\\n'
        '| Starter | **99.5%** | \\u2014 |\\n'
        '| Pro | **99.9%** | \\u2014 |\\n'
        '| Growth | **99.9%** | \\u2014 |\\n'
        '| Scale | **99.95%** | 10% credit |\\n'
        '| Enterprise | **99.99%** | 25% credit |\\n'
        '\\nSLA credits are calculated based on downtime severity: '
        '99.0\\u201399.9% = 10% credit, 95\\u201399% = 25%, 90\\u201395% = 50%, <90% = 100%.'
    )
    new_sla = (
        '| Free\\u2013Growth | None | \\u2014 |\\n'
        '| Scale ($350) | **99.9%** | up to 10% credit |\\n'
        '| Enterprise ($800) | **99.9%** | up to 25% credit |\\n'
        '\\nOnly Scale and Enterprise plans include an SLA. '
        'Credits are based on downtime below the 99.9% target: '
        '0.1% below = 10% credit, 0.5% below = 25%, 1.0% below = 50%, 5.0%+ below = 100%. '
        'To claim SLA credits, email contact@apexmail.ee with your account ID and the affected time window.'
    )
    n = data.count(old_sla)
    if n == 0:
        # Try with literal em-dash
        old_sla = old_sla.replace("\\u2014", "\u2014").replace("\\u2013", "\u2013")
        n = data.count(old_sla)
    data = data.replace(old_sla, new_sla)
    total += n
    print(f"  Fix 1 — SLA table: {n} replacements")

    # ── Fix 2: Hetzner/PostgreSQL/Redis EU data leak ───────────────────
    old_eu = (
        '**Yes** \\u2014 all data is stored in the **EU by default**. '
        'Our infrastructure runs on Hetzner servers in **Germany/Finland**.'
        '\\n\\nSub-processors:\\n'
        '- **Hetzner** (Germany/Finland) \\u2014 compute, storage, backups\\n'
        '- **PostgreSQL** (self-hosted on Hetzner) \\u2014 primary database\\n'
        '- **Redis** (self-hosted on Hetzner) \\u2014 caching\\n'
        '- **Stripe** (EU data residency) \\u2014 billing\\n'
        '- **Cloudflare** \\u2014 DNS/CDN edge (minimal data)\\n\\n'
        'For **Enterprise** customers, we offer guaranteed EU-only data residency '
        'with contractual commitments. No customer email content is stored outside the EU.'
    )
    new_eu = (
        '**Yes** \\u2014 all ApexMail data is stored in the **EU by default** '
        '(data centers in Europe).'
        '\\n\\nKey points:\\n'
        '- All email content, metadata, and account data are processed within **EU data centers**\\n'
        '- **Stripe** handles billing with EU data residency\\n'
        '- **Cloudflare** provides DNS/CDN (edge, minimal data)\\n\\n'
        'For **Enterprise** customers, we offer **guaranteed EU-only data residency** '
        'with contractual commitments and a formal Data Processing Agreement (DPA). '
        'No customer email content is stored outside the EU.'
        '\\n\\nFor detailed sub-processor information and data residency documentation, '
        'contact **contact@apexmail.ee**.'
    )
    n = data.count(old_eu)
    if n == 0:
        old_eu = old_eu.replace("\\u2014", "\u2014")
        n = data.count(old_eu)
    data = data.replace(old_eu, new_eu)
    total += n
    print(f"  Fix 2 — EU/Hetzner leak: {n} replacements")

    # ── Fix 3: GDPR deletion mentions PostgreSQL/Redis/S3 ─────────────
    old_gdpr = "Data is removed from PostgreSQL, Redis, and S3 storage."
    new_gdpr = "Data is removed from all primary databases and caches."
    n = data.count(old_gdpr)
    data = data.replace(old_gdpr, new_gdpr)
    total += n
    print(f"  Fix 3 — GDPR PostgreSQL/Redis: {n} replacements")

    # ── Fix 4: DPA 'EU data stored at Hetzner (DE/FI)' ────────────────
    old_dpa1 = "EU data stored at Hetzner (DE/FI)"
    new_dpa1 = "EU data centers (Germany/Finland)"
    n = data.count(old_dpa1)
    data = data.replace(old_dpa1, new_dpa1)
    total += n
    print(f"  Fix 4 — DPA Hetzner ref 1: {n} replacements")

    # ── Fix 5: DPA 'data is stored in EU — Hetzner DE/FI' ─────────────
    # Try both unicode escape and literal
    for variant in [
        "your data is stored in EU \\u2014 Hetzner DE/FI",
        "your data is stored in EU \u2014 Hetzner DE/FI",
    ]:
        n = data.count(variant)
        if n > 0:
            data = data.replace(variant, "your data is stored in EU data centers (Germany/Finland)")
            total += n
            print(f"  Fix 5 — DPA Hetzner ref 2: {n} replacements")
            break
    else:
        print("  Fix 5 — DPA Hetzner ref 2: 0 replacements (not found)")

    # ── Write back ─────────────────────────────────────────────────────
    with open(TRAIN_FILE, "w") as f:
        f.write(data)

    print(f"\nTotal replacements: {total}")
    print(f"File size: {original_len} → {len(data)} bytes")

    # ── Verify no remaining leaks ──────────────────────────────────────
    remaining = {
        "Hetzner": data.count("Hetzner"),
        "PostgreSQL": data.count("PostgreSQL"),
        "99.99%": data.count("99.99%"),
        "99.95%": data.count("99.95%"),
        "99.5%": data.count("99.5%"),
    }
    print("\nRemaining mentions (should all be 0):")
    all_clean = True
    for key, cnt in remaining.items():
        status = "✓" if cnt == 0 else f"✗ ({cnt})"
        print(f"  {key}: {status}")
        if cnt > 0:
            all_clean = False

    if all_clean:
        print("\n✅ All training data issues fixed!")
    else:
        print("\n⚠️  Some issues remain — investigate manually.")
        sys.exit(1)


if __name__ == "__main__":
    main()
