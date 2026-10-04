#!/usr/bin/env python3
"""Security-posture gate: the merged production configuration must state
every security-control decision EXPLICITLY, match the managed-cloud
baseline, and every control the compliance templates claim must be ON.

Audit-3 #1/#2: a stack started from supplied defaults used to run with
spam filtering, attachment scanning, IDS and DLP all `false` and a WAF in
monitor-only — the implementation was real but the production posture was
weaker than the words. This gate makes that class return impossible:

  1. SECURITY_CONTROL_VARS: each variable must be EXPLICITLY defined in
     the production env (docker's ${VAR:?} guards already refuse to boot
     without them; this gate refuses the configuration one step earlier
     and independent of docker).
  2. MANAGED_PROFILE minimums: inspection/scanning controls must be `true`
     (spam filter, attachment scan, IDS, DLP, WAF enabled AND enforcing).
     Enforcement-style choices (spam reject, attachment strip, IDS refuse)
     are policy decisions — any explicit boolean passes.
  3. TEMPLATE CLAIM RECONCILIATION: capabilities that the customer-facing
     compliance templates (security-measures, trust-center, DPA, incident
     response) present as ACTIVE controls must be `true` in the profile.
     A template claiming an Intrusion Detection System while
     MTA_IDS_ENABLED=false is a legal-artifact contradiction — FAIL.
  4. DEPLOYMENT-FACTS RECONCILIATION (audit 2026-10-02 #6):
     docs/deployment-facts.json is the shared authority for what the managed
     baseline turns ON; for every managed-baseline control this checker owns,
     the linked fact's managed_cloud_enabled must agree with the env value —
     two checkers, one truth.
  5. MARKETING INTEGRITY-CLAIM CORPUS (audit 2026-10-02 #3): the localized
     marketing security pages must not carry the five unverifiable
     supply-chain/backup/monitoring claims (build-time signing, inotify FIM,
     append-only deployment logs, PostgreSQL page checksums + nightly scan,
     automated weekly restore tests) while the linked deployment fact is
     false. Flip the fact in the same change that ships a capability.

Self-test: `check_security_posture.py --self-test` mutates fixtures and
asserts this gate fails on every class it exists to catch.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = ROOT / ".env.production.example"
COMPOSE = ROOT / "docker-compose.prod.yml"
FACTS_PATH = ROOT / "docs/deployment-facts.json"
TEMPLATES = [
    ROOT / "templates/compliance/security-measures.md",
    ROOT / "templates/compliance/trust-center.md",
    ROOT / "templates/legal/dpa.md",
    ROOT / "templates/compliance/incident-response.md",
]

# Audit 2026-10-02 #3: the MARKETING security page (all locales) belongs to
# the posture corpus too — its supply-chain/backup/monitoring claims must
# match docs/deployment-facts.json, the shared authority.
MARKETING_SURFACES = [
    ROOT / "apps/marketing-zola/content/security/index.md",
    ROOT / "apps/marketing-zola/content/security/index.de.md",
    ROOT / "apps/marketing-zola/content/security/index.es.md",
    ROOT / "apps/marketing-zola/content/security/index.fr.md",
]

# deployment-facts id -> managed-baseline env var this checker already owns.
FACT_ENV_VARS = {
    "WAF_ENABLED": "web_application_firewall",
    "MTA_SPAM_FILTER_ENABLED": "spam_phishing_filtering",
    "MTA_ATTACHMENT_SCAN_ENABLED": "attachment_sandboxing",
    "MTA_IDS_ENABLED": "intrusion_detection_prevention",
    "WORKER_DLP_ENABLED": "data_loss_prevention",
}

# Audit 2026-10-02 #3 — the five unverifiable integrity-table claims. Each
# entry maps a deployment-facts id to claim patterns (EN + de/es/fr); while
# the fact's value is not true, a pattern hit on a marketing security surface
# is an advertisement of a control that does not exist — FAIL. When the
# capability genuinely ships, flip the fact IN THE SAME CHANGE and the gate
# relaxes.
INTEGRITY_CLAIM_PATTERNS = [
    ("artifact_signature", [
        r"cryptographically signed",
        r"kryptografisch signiert",
        r"firman criptográficamente",
        r"signés cryptographiquement",
        r"validate signatures before rollout",
        r"validieren signaturen vor dem rollout",
        r"validan las firmas antes del despliegue",
        r"valident les signatures avant le déploiement",
    ]),
    ("fim_inotify", [
        r"inotify",
        r"file-integrity monitoring",
        r"dateiintegritätsüberwachung",
        r"monitoreo de integridad de archivos",
        r"surveillance de l'intégrité des fichiers",
    ]),
    ("deployment_log_append_only", [
        r"append-only",
        r"nur-anhängen",
        r"solo anexar",
        r"en ajout seulement",
        r"tamper-evident",
        r"manipulationssichere\w* protokoll",
        r"registro a prueba de manipulaciones",
        r"journal inviolable",
    ]),
    ("postgres_page_checksums", [
        r"page checksums?",
        r"checksum validation on all data pages",
        r"prüfsummenvalidierung auf allen datenseiten",
        r"suma de verificación postgresql en todas las páginas",
        r"somme de contrôle postgresql sur toutes les pages",
        r"nightly full scan",
        r"nächtlicher vollständiger scan",
        r"escaneo completo nocturno",
        r"analyse complète nocturne",
    ]),
    ("backup_restore_automatic", [
        r"automated (weekly )?restore tests?",
        r"automatisierte wiederherstellungstests",
        r"pruebas de restauración automatizadas",
        r"tests de restauration automatisés",
        r"sample data comparison",
        r"vergleich von beispieldaten",
        r"comparación de datos de muestra",
        r"comparaison des données d'échantillon",
    ]),
]


# The production security-policy surface: every var is a REQUIRED decision.
SECURITY_CONTROL_VARS = [
    "WAF_ENABLED",
    "WAF_ENFORCE",
    "MTA_SPAM_FILTER_ENABLED",
    "MTA_SPAM_REJECT_ENABLED",
    "MTA_ATTACHMENT_SCAN_ENABLED",
    "MTA_ATTACHMENT_SCAN_MODE",
    "MTA_IDS_ENABLED",
    "MTA_IDS_REFUSE",
    "WORKER_DLP_ENABLED",
]

# Managed-cloud baseline: inspection/scanning/enforcement-active controls
# must be `true`. (Reject-style vars are explicit policy, not gated here.)
MANAGED_TRUE = [
    "WAF_ENABLED",
    "WAF_ENFORCE",
    "MTA_SPAM_FILTER_ENABLED",
    "MTA_ATTACHMENT_SCAN_ENABLED",
    "MTA_IDS_ENABLED",
    "WORKER_DLP_ENABLED",
]

# Template claim reconciliation: claimed-active control -> profile var that
# must be true, plus the alias phrases that constitute a "claimed active"
# statement in the compliance surfaces.
TEMPLATE_CLAIMS = [
    ("spam filtering", "MTA_SPAM_FILTER_ENABLED",
     ["spam filtering", "spam and phishing", "spam/phishing"]),
    ("attachment sandboxing", "MTA_ATTACHMENT_SCAN_ENABLED",
     ["attachment sandbox", "attachment scanning", "attachment analysis"]),
    ("intrusion detection", "MTA_IDS_ENABLED",
     ["intrusion detection", "ids/ips", "ids and ips"]),
    ("data-loss prevention", "WORKER_DLP_ENABLED",
     ["data loss prevention", "dlp"]),
    ("web application firewall", "WAF_ENABLED",
     ["web application firewall", "waf"]),
]


def parse_env_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"')
    return values


def evaluate(
    env_text: str,
    compose_text: str,
    templates: dict[str, str],
    quiet: bool = False,
    live: bool = False,
    facts: dict | None = None,
    marketing: dict[str, str] | None = None,
) -> list[str]:
    """Run every gate rule against the given texts; return the failure names.

    `templates` maps file name -> text. The main entry point feeds the real
    .env/compose/template files; `--self-test` feeds mutated FIXTURE copies
    so the gate can be pointed at injected breakage without ever touching
    the real files. `facts` (docs/deployment-facts.json's `facts` object) and
    `marketing` (the localized marketing security pages) enable the
    deployment-facts reconciliation and the integrity-claim corpus; both are
    None in the live-config path and the legacy self-test cases.
    """
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        status = "PASS" if ok else "FAIL"
        suffix = f" — {detail}" if detail and not ok else ""
        if not quiet:
            print(f"{status} {name}{suffix}")
        if not ok:
            failures.append(name)

    def compose_requires(var: str) -> bool:
        return re.search(rf"{var}:\s*\"?\s*\$\{{{var}:\?", compose_text) is not None

    def compose_implicit_default(var: str) -> str | None:
        """The implicit fallback compose would use if the env file omitted the
        var — non-None means the variable is NOT a required decision."""
        m = re.search(rf"{var}:\s*\"?\s*\$\{{{var}:-([^}}]*)\}}", compose_text)
        return m.group(1) if m else None

    values = parse_env_values(env_text)

    for var in SECURITY_CONTROL_VARS:
        if var not in values:
            check(f"explicit:{var}", False,
                  "not defined in .env.production.example — production has no "
                  "implicit security-control defaults")
            continue
        check(f"explicit:{var}", True)
        value = values[var]
        if value not in {"true", "false"} and not re.fullmatch(r"[a-z]+", value):
            check(f"value-format:{var}", False,
                  f"{value!r} is not a strict boolean or known mode word")

    for var in MANAGED_TRUE:
        value = values.get(var, "")
        check(
            f"managed-baseline:{var}",
            value == "true",
            f"the managed cloud claims this control ACTIVE; set {var}=true in "
            ".env.production.example or formally re-qualify the claim",
        )
        # Live deployments skip this rule: the resolved JSON carries the
        # final values, and the source-file :? guards were proven by the
        # main gate (and by compose itself, which refuses to boot without
        # them).
        if live:
            check(f"compose-guard:{var}", True)
        elif compose_requires(var):
            check(f"compose-guard:{var}", True)
        else:
            check(
                f"compose-guard:{var}", False,
                "docker-compose.prod.yml does not hard-require this variable "
                f"(${{VAR:?}}) — a stack can boot without the policy decision",
            )
        implicit = compose_implicit_default(var)
        if implicit is not None:
            check(
                f"no-implicit-default:{var}", False,
                f"compose silently defaults {var} to {implicit!r} — replace "
                f"with ${{{var}:?...}} so a missing decision refuses to boot",
            )

    # Template reconciliation: claimed-active controls must be profile-true.
    template_values = values  # the shipped example IS the managed profile
    for claim, var, aliases in TEMPLATE_CLAIMS:
        profile_true = template_values.get(var) == "true"
        for tpl_name, text in templates.items():
            lowered = text.lower()
            claimed = any(alias in lowered for alias in aliases)
            if claimed and not profile_true:
                check(
                    f"template-claim:{claim}:{tpl_name}", False,
                    f"{tpl_name} presents {claim!r} as an active control but "
                    f"{var} is not true in the managed profile",
                )
            elif claimed and profile_true:
                check(f"template-claim:{claim}:{tpl_name}", True)

    # Deployment-facts reconciliation: the shared authority must agree with
    # the managed profile (audit 2026-10-02 #6 — one truth, two checkers).
    if facts is not None:
        for var, fact_id in sorted(FACT_ENV_VARS.items()):
            fact = facts.get(fact_id)
            if fact is None:
                check(f"facts-present:{fact_id}", False,
                      f"docs/deployment-facts.json has no {fact_id!r} fact — "
                      "the managed-baseline reconciliation is blind")
                continue
            fact_on = fact.get("managed_cloud_enabled") is True
            env_on = values.get(var) == "true"
            check(
                f"facts-env:{fact_id}:{var}", fact_on == env_on,
                f"deployment-facts managed_cloud_enabled={fact.get('managed_cloud_enabled')} "
                f"but .env.production.example has {var}={values.get(var)!r} — "
                "reconcile both in the same change",
            )

    # Marketing integrity-claim corpus: while a fact is not true, the five
    # unverifiable supply-chain/backup/monitoring claims must not appear on
    # any localized marketing security page (audit 2026-10-02 #3).
    if marketing is not None and facts is not None:
        for fact_id, patterns in INTEGRITY_CLAIM_PATTERNS:
            fact = facts.get(fact_id) or {}
            if fact.get("value") is True:
                continue  # capability shipped: the claim is legal again
            for surface_name, text in marketing.items():
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        check(
                            f"marketing-claim:{fact_id}:{surface_name}", False,
                            f"surface claims a control that deployment-facts records as "
                            f"not true (pattern /{pattern}/i) — rewrite the claim to the "
                            f"honest statement or ship the capability and flip the fact",
                        )

    return failures


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    # Deploy-stage live gate: the FINAL rendered values from
    # `docker compose config --format json` (ci/stages/deploy.sh runs this
    # before `up`). Every control must be explicitly present and the
    # managed baseline active — no implicit false defaults, ever.
    if "--resolved-json" in argv:
        path = Path(argv[argv.index("--resolved-json") + 1])
        cfg = json.loads(path.read_text())
        values: dict[str, str] = {}
        for service in cfg.get("services", {}).values():
            env = service.get("environment") or {}
            if isinstance(env, dict):
                for var in SECURITY_CONTROL_VARS:
                    if env.get(var) is not None:
                        values[var] = str(env[var])
        synthesized_env = "\n".join(f"{k}={v}" for k, v in values.items())
        failures = evaluate(synthesized_env, "", {}, quiet=True, live=True)
        print()
        if failures:
            print(f"SECURITY POSTURE FAILURES (live config): {len(failures)}")
            for name in failures:
                print(f"  - {name}")
            return 1
        print("security posture (live config): managed baseline active")
        return 0

    env_text = ENV_EXAMPLE.read_text() if ENV_EXAMPLE.exists() else ""
    compose_text = COMPOSE.read_text()
    templates = {tpl.name: tpl.read_text() for tpl in TEMPLATES if tpl.exists()}
    if not FACTS_PATH.is_file():
        print("FAIL deployment-facts:docs/deployment-facts.json — missing: the shared "
              "authority for deployment truth must exist (audit 2026-10-02 #14)")
        return 1
    facts = (json.loads(FACTS_PATH.read_text()).get("facts")) or {}
    marketing = {p.name: p.read_text() for p in MARKETING_SURFACES if p.exists()}
    failures = evaluate(env_text, compose_text, templates, facts=facts, marketing=marketing)

    print()
    if failures:
        print(f"SECURITY POSTURE FAILURES: {len(failures)}")
        for name in failures:
            print(f"  - {name}")
        return 1
    print("security posture: matches the managed-cloud baseline and the "
          "compliance claims")
    return 0


def self_test() -> int:
    """Prove the gate fails on every class it exists to catch.

    Each case runs the REAL gate logic (evaluate) against a mutated FIXTURE
    env/compose/template triple held in memory — the real files are never
    read or touched. Classes: managed-baseline flip, missing control var,
    template-claim reconciliation (a template claims a control the profile
    disabled) and the compose :? guard (a stack that boots without the
    policy decision).
    """
    fixture_compose = "\n".join(
        f'  {var}: "${{{var}:?set {var} explicitly}}"'
        for var in SECURITY_CONTROL_VARS
    )
    fixture_template = (
        "# Security Measures\n\n"
        "Spam filtering, attachment scanning, an intrusion detection system, "
        "data loss prevention and a web application firewall are active on "
        "all production systems.\n"
    )
    templates = {"security-measures.md": fixture_template}

    def base_env() -> str:
        return "\n".join(
            f"{var}={'true' if var in MANAGED_TRUE else ('flag' if var.endswith('MODE') else 'false')}"
            for var in SECURITY_CONTROL_VARS
        )

    base = base_env()
    cases: list[tuple[str, str, str, str]] = [
        ("control fixture passes", base, fixture_compose, ""),
        (
            "template-claim class: control flipped false while the template claims it",
            base.replace("MTA_IDS_ENABLED=true", "MTA_IDS_ENABLED=false"),
            fixture_compose,
            "template-claim:intrusion detection:security-measures.md",
        ),
        (
            "compose-guard class: :? guard dropped from the compose fixture",
            base,
            fixture_compose.replace(
                'WORKER_DLP_ENABLED: "${WORKER_DLP_ENABLED:?set WORKER_DLP_ENABLED explicitly}"',
                'WORKER_DLP_ENABLED: "${WORKER_DLP_ENABLED:-false}"',
            ),
            "compose-guard:WORKER_DLP_ENABLED",
        ),
        (
            "managed-baseline class: inspection control disabled",
            base.replace("MTA_SPAM_FILTER_ENABLED=true", "MTA_SPAM_FILTER_ENABLED=false"),
            fixture_compose,
            "managed-baseline:MTA_SPAM_FILTER_ENABLED",
        ),
        (
            "explicitness class: control var missing from the profile",
            "\n".join(
                line for line in base.splitlines()
                if not line.startswith("WORKER_DLP_ENABLED")
            ),
            fixture_compose,
            "explicit:WORKER_DLP_ENABLED",
        ),
    ]

    ok = True
    for label, env_text, compose_text, needle in cases:
        failures = evaluate(env_text, compose_text, templates, quiet=True)
        if needle == "":
            passed = not failures
        else:
            passed = needle in failures
        if passed:
            print(f"SELF-TEST PASS {label}")
        else:
            ok = False
            print(f"SELF-TEST FAIL {label}: failures={failures}")

    # Deployment-facts classes (audit 2026-10-02 #3/#6): the facts file and
    # the marketing integrity corpus, exercised on in-memory fixtures.
    def base_facts() -> dict:
        return {
            fact_id: {
                "value": True,
                "managed_cloud_enabled": True,
                "enforcement_mode": "enforced",
                "monitored": False,
                "advertised": False,
                "implementation_stage": "runtime-wired",
                "binary_default": False,
                "evidence": "fixture",
                "source": "fixture",
            }
            for fact_id in FACT_ENV_VARS.values()
        }

    marketing_fixture = {
        "security/index.md": (
            "# Security\n\nSystem integrity is verified:\n\n"
            "| Control | What Is Verified |\n|---|---|\n"
            "| Deployment artifacts | Images are digest-pinned and verified "
            "before rollout; the release manifest records every digest. |\n"
            "| Backups | Every backup is decrypt-validated automatically; "
            "full restore drills are manual. |\n"
        )
    }
    facts_cases: list[tuple[str, dict, dict[str, str], str | None]] = [
        ("facts fixture passes", base_facts(), marketing_fixture, None),
        (
            "facts-env class: managed-baseline fact disagrees with the profile",
            {**base_facts(), "data_loss_prevention": {**base_facts()["data_loss_prevention"], "managed_cloud_enabled": False}},
            marketing_fixture,
            "facts-env:data_loss_prevention:WORKER_DLP_ENABLED",
        ),
        (
            "marketing-claim class: signed-artifact claim while the fact is false",
            {**base_facts(), "artifact_signature": {"value": False, "managed_cloud_enabled": False}},
            {"security/index.md": "Images are cryptographically signed at build time."},
            "marketing-claim:artifact_signature:security/index.md",
        ),
        (
            "marketing corpus clean when the control is honestly described",
            base_facts(),
            marketing_fixture,
            None,
        ),
    ]
    fixture_facts_env = base_env()
    for label, facts, marketing, needle in facts_cases:
        failures = evaluate(
            fixture_facts_env, fixture_compose, templates, quiet=True,
            facts=facts, marketing=marketing,
        )
        if needle is None:
            passed = not failures
        else:
            passed = needle in failures
        if passed:
            print(f"SELF-TEST PASS {label}")
        else:
            ok = False
            print(f"SELF-TEST FAIL {label}: failures={failures}")

    print(f"self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
