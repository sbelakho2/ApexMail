#!/usr/bin/env python3
"""B7 addendum — assignment persistence, determinism, second-call stability."""
import importlib.util, json, subprocess

spec = importlib.util.spec_from_file_location(
    "harness", "/Users/sabelakhoua/IdeaProjects/ApexMail/tools/dogfood-live-capabilities.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

CAMP = "bb84221f-c54d-44e3-8df2-f6f7ce32417e"  # ab-vfb7, 200 contacts

print("== split (phase x arm) ==")
print(h.sql("SELECT phase, arm_index, count(*) FROM campaign_recipients "
            f"WHERE campaign_id={h.q(CAMP)}::uuid GROUP BY phase, arm_index ORDER BY phase, arm_index"))
print(h.sql("SELECT count(*) total, count(ab_bucket) with_bucket, count(*) FILTER (WHERE phase IS NULL) unphased "
            f"FROM campaign_recipients WHERE campaign_id={h.q(CAMP)}::uuid"))

print("== determinism recompute (md5 formula vs stored ab_bucket) ==")
print(h.sql(
    "SELECT count(*) total, "
    "count(*) FILTER (WHERE ab_bucket IS DISTINCT FROM "
    "  ('x' || substr(md5(campaign_id::text || ':' || contact_id::text), 1, 8))::bit(32)::bigint) mismatches "
    f"FROM campaign_recipients WHERE campaign_id={h.q(CAMP)}::uuid"))

print("== row-set fingerprint before second assignment run ==")
before = h.sql1("SELECT md5(string_agg(id || ':' || COALESCE(phase,'-') || ':' || COALESCE(arm_index::text,'-') "
                f"|| ':' || COALESCE(ab_bucket::text,'-'), ',' ORDER BY id)) FROM campaign_recipients WHERE campaign_id={h.q(CAMP)}::uuid")
print("fingerprint_before:", before)

print("== second assignment call (AB_SPLIT_SQL re-run: only un-phased rows are touched) ==")
# psql -c with the SQL; $1/$2/$3 replaced literally here
split_sql = (
    "WITH scored AS (SELECT id, ('x' || substr(md5('" + CAMP + "' || ':' || contact_id::text), 1, 8))::bit(32)::bigint AS bucket "
    "FROM campaign_recipients WHERE campaign_id = '" + CAMP + "'::uuid AND phase IS NULL) "
    "UPDATE campaign_recipients cr SET phase = CASE WHEN s.bucket % 10000 < CEIL(0.5 * 10000)::bigint THEN 'test' ELSE 'holdout' END, "
    "arm_index = CASE WHEN s.bucket % 10000 < CEIL(0.5 * 10000)::bigint THEN ((s.bucket / 10000) % 2)::int ELSE NULL END, "
    "ab_bucket = s.bucket, updated_at = NOW() FROM scored s WHERE cr.id = s.id RETURNING cr.id")
out = subprocess.run(["docker", "exec", "apexmail-postgres", "psql", "-U", "apexmail", "-d", "apexmail", "-tAc", split_sql],
                     capture_output=True, text=True)
print("second-run rows assigned:", repr(out.stdout.strip()), "stderr:", out.stderr.strip()[:100])
after = h.sql1("SELECT md5(string_agg(id || ':' || COALESCE(phase,'-') || ':' || COALESCE(arm_index::text,'-') "
               f"|| ':' || COALESCE(ab_bucket::text,'-'), ',' ORDER BY id)) FROM campaign_recipients WHERE campaign_id={h.q(CAMP)}::uuid")
print("fingerprint_after: ", after)
print("IDEMPOTENT:", "PASS" if before == after and out.stdout.strip() == "" else "FAIL")

print("== second call on the read surface: GET /experiment twice ==")
key = h.mint_key("kdrbywwep9tr462oflky4isckq", "b7-verify-addendum", ["*"])
st1, b1, _ = h.api("GET", f"/v1/campaigns/{CAMP}/experiment", key)
st2, b2, _ = h.api("GET", f"/v1/campaigns/{CAMP}/experiment", key)
r1 = (b1 or {}).get("data", {}).get("recipients") if isinstance(b1, dict) else None
r2 = (b2 or {}).get("data", {}).get("recipients") if isinstance(b2, dict) else None
a1 = (b1 or {}).get("data", {}).get("arms") if isinstance(b1, dict) else None
a2 = (b2 or {}).get("data", {}).get("arms") if isinstance(b2, dict) else None
print("call1:", st1, json.dumps(r1), "arms:", json.dumps(a1))
print("call2:", st2, json.dumps(r2), "arms:", json.dumps(a2))
print("SECOND_CALL:", "PASS" if st1 == st2 == 200 and r1 == r2 and a1 == a2 else "FAIL")
print("DONE")
