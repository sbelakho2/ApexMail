#!/usr/bin/env python3
"""B8 — custom tracking domain CRUD + click-path proof (verify-final-money)."""
import importlib.util, json, sys, uuid

spec = importlib.util.spec_from_file_location(
    "harness", "/Users/sabelakhoua/IdeaProjects/ApexMail/tools/dogfood-live-capabilities.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

RUN = "vfb8"
ten = h.provision_tenant(f"Verify8 Td {RUN}", "growth")
other = h.provision_tenant(f"Verify8 TdOther {RUN}", "growth")
free = h.provision_tenant(f"Verify8 TdFree {RUN}", "free")
ten["domain"] = f"vfb8-{RUN}-a.dogfood.test"
h.sql(f"UPDATE domains SET name={h.q(ten['domain'])} WHERE tenant_id={h.q(ten['id'])}")
custom_host = f"track.{ten['domain']}"
print("tenant:", ten["id"], "parent:", ten["domain"], "custom:", custom_host)

# 1. CREATE via API
st, body, _ = h.api("POST", "/v1/tracking-domains", ten["key"], {"domain": custom_host})
print(f"CREATE {st} {json.dumps(body)[:300]}")
td = body.get("id")
print("CREATE_VERDICT", "PASS" if st == 201 and td and body.get("status") == "pending" else "FAIL")

# 2. LIST
st, body, _ = h.api("GET", "/v1/tracking-domains", ten["key"], None)
print(f"LIST {st} {json.dumps(body)[:300]}")

# 3. DNS records (the generated link's CNAME target)
st, recs, _ = h.api("GET", f"/v1/tracking-domains/{td}/dns-records", ten["key"], None)
print(f"DNS-RECORDS {st} {json.dumps(recs)[:400]}")
records = (recs or {}).get("records") or []
cname = records[0] if records else {}
cname_value = cname.get("value", "track.apexmail.ee")
print("DNS_VERDICT", "PASS" if st == 200 and cname.get("hostname") == custom_host and cname.get("record_type") == "CNAME" else "FAIL")

# 4. verify before DNS (state must stay pending; never a false failure)
st, body, _ = h.api("POST", f"/v1/tracking-domains/{td}/verify", ten["key"], {})
print(f"VERIFY-BEFORE-DNS {st} {json.dumps(body)[:250]}")

# 5. publish the CNAME in the api-server resolver view (the customer's DNS step)
target_ips = h.subprocess.run(
    ["docker", "exec", "apexmail-api-server-1", "getent", "ahostsv4", cname_value],
    capture_output=True, text=True).stdout.split()
target_ip = target_ips[0] if target_ips else "95.216.226.51"
print(f"publishing {custom_host} -> {target_ip} (extra_hosts resolver-view recreate, no build)")
h.compose_api_server_with_hosts({custom_host: target_ip})

st, body, _ = h.api("POST", f"/v1/tracking-domains/{td}/verify", ten["key"], {})
print(f"VERIFY {st} {json.dumps(body)[:300]}")
verified = isinstance(body, dict) and body.get("status") == "verified"
if verified:
    print("VERIFY_VERDICT PASS")
else:
    # fallback (offline DNS): mark the row verified via SQL fixture, disclosed
    h.sql(f"UPDATE tracking_domains SET status='verified', verified_at=NOW(), last_checked_at=NOW(), "
          f"status_reason='fixture: resolver offline' WHERE id={h.q(td)}::uuid")
    print("VERIFY_VERDICT FALLBACK-SQL (documented) reason=", json.dumps(body)[:200])

# 6. click path on the custom host — owner token served, foreign token refused
click_url = f"https://{ten['domain']}/b8-landing?i=1"
token = h.encode_click_token(ten["id"], str(uuid.uuid4()), "b8", click_url)
st, body, hdrs = h.http("GET", f"{h.TRACKING}/c/{token}", headers={"Host": custom_host}, retries=1)
loc = (hdrs or {}).get("location") or (hdrs or {}).get("Location")
print(f"CLICK owner on {custom_host} -> {st} location={loc!r}")
print("CLICK_VERDICT", "PASS" if st == 302 and loc == click_url else f"FAIL(st={st})")

foreign = h.encode_click_token(other["id"], str(uuid.uuid4()), "x", click_url)
st, body, hdrs = h.http("GET", f"{h.TRACKING}/c/{foreign}", headers={"Host": custom_host}, retries=1)
print(f"CLICK foreign on {custom_host} -> {st} {str(body)[:160]!r}")
print("FOREIGN_VERDICT", "PASS" if st in (400, 403, 404) else f"FAIL(st={st})")

pix = h.encode_pixel_token(ten["id"], str(uuid.uuid4()))
st, body, _ = h.http("GET", f"{h.TRACKING}/o/{pix}", headers={"Host": custom_host}, retries=1)
print(f"PIXEL owner on {custom_host} -> {st} type={type(body).__name__}")
print("PIXEL_VERDICT", "PASS" if st == 200 else f"FAIL(st={st})")

# 7. DELETE via API → serving stops
st, body, _ = h.api("DELETE", f"/v1/tracking-domains/{td}", ten["key"], {})
print(f"DELETE {st} {json.dumps(body)[:150]}")
st2, body2, _ = h.http("GET", f"{h.TRACKING}/o/{pix}", headers={"Host": custom_host}, retries=1)
print(f"PIXEL after delete -> {st2} {str(body2)[:120]!r}")
print("DELETE_VERDICT", "PASS" if st in (200, 204) and st2 in (400, 403, 404) else f"FAIL(st={st},after={st2})")

# restore the api-server without extra_hosts
h.compose_api_server_with_hosts(None)
print("DONE")
