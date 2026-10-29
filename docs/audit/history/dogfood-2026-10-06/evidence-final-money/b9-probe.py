#!/usr/bin/env python3
"""B9 — send-time optimization weekday proof (verify-final-money).

Two recipients in different timezones with engagement history on different
local weekdays. The campaign's settings.timezone drives the STO profile
buckets + window. We assert the computed scheduled_at lands on the CORRECT
local weekday/hour, and print the arithmetic (plus the old DOW shape).
"""
import importlib.util, sys, time, uuid
from datetime import datetime, timedelta, timezone

spec = importlib.util.spec_from_file_location(
    "harness", "/Users/sabelakhoua/IdeaProjects/ApexMail/tools/dogfood-live-capabilities.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

RUN = "vfb9"
ten = h.provision_tenant(f"Verify9 Sto {RUN}", "growth")
print("tenant:", ten["id"], "domain:", ten["domain"])

CASES = [
    # (label, tz, offset_min, event weekday target (0=Mon), event local hour, hours-back anchor)
    ("tallinn-wed", "Europe/Tallinn", 180, 2, 9),    # local Wednesday 09:00
    ("newyork-mon", "America/New_York", -240, 0, 10),  # local Monday 10:00
]
now = datetime.now(timezone.utc)

for label, tz, off_min, target_wd, local_hour in CASES:
    email = f"b9-{label}-{RUN}@dogfood.test"
    cid = h.grant_consent(ten["id"], email)
    lid = str(uuid.uuid4())
    h.sql("INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, status, created_at, updated_at) "
          f"VALUES ({h.q(lid)}, {h.q(ten['id'])}, {h.q('b9-'+label)}, 'dogfood', 'single', 'active', NOW(), NOW())")
    h.sql(f"INSERT INTO list_subscribers (id, list_id, contact_id, status, created_at) "
          f"VALUES (gen_random_uuid(), {h.q(lid)}, {h.q(cid)}, 'active', NOW())")

    # most recent occurrence of target weekday (strictly before today), at the
    # LOCAL hour expressed as UTC (local = UTC + off)
    local_now = now + timedelta(minutes=off_min)
    delta_days = (local_now.weekday() - target_wd) % 7
    if delta_days == 0:
        delta_days = 7
    event_local_date = (local_now - timedelta(days=delta_days)).date()
    event_local = datetime(event_local_date.year, event_local_date.month, event_local_date.day,
                           local_hour, 0, 0, tzinfo=timezone(timedelta(minutes=off_min)))
    event_utc = event_local.astimezone(timezone.utc)
    for i in range(8):
        h.sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
              f"({h.q(f'b9-{label}-{i}')}, {h.q(ten['id'])}, {h.q(str(uuid.uuid4()))}, 'opened', {h.q(email)}, "
              f"{h.q(event_utc.strftime('%Y-%m-%dT%H:%M:%SZ'))})")

    st, body, _ = h.api("POST", "/v1/campaigns", ten["key"], {
        "name": f"b9-{label}", "subject": f"B9 {label}", "from": f"dogfood@{ten['domain']}",
        "html": "<p>sto weekday</p>", "list_ids": [lid],
        "settings": {"sendTimeOptimization": True, "timezone": tz},
    })
    camp = h.unwrap_id(body)
    print(f"[{label}] campaign create -> {st} campaign={camp}")

    st, body, _ = h.api("POST", f"/v1/campaigns/{camp}/send", ten["key"], {})
    print(f"[{label}] send -> {st} status={body.get('status') if isinstance(body, dict) else body}")

    scheduled = ""
    for _ in range(90):
        scheduled = h.sql1("SELECT COALESCE(to_char(scheduled_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'') "
                           f"FROM email_queue WHERE campaign_id={h.q(camp)}::uuid AND scheduled_at IS NOT NULL LIMIT 1")
        if scheduled:
            break
        time.sleep(1)

    # SQL view of the two mappings on the event timestamp (evidence)
    row = h.sql1(
        "SELECT to_char(timestamp AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') "
        "|| '| isodow=' || EXTRACT(ISODOW FROM timestamp AT TIME ZONE 'UTC')::int "
        "|| '| dow=' || EXTRACT(DOW FROM timestamp AT TIME ZONE 'UTC')::int "
        "FROM events WHERE id=" + h.q(f"b9-{label}-0"))
    print(f"[{label}] event_utc={event_utc.isoformat()} sql={row}")
    print(f"[{label}] event_local={event_local.isoformat()} (weekday={event_local.strftime('%A')})")

    got_utc = datetime.fromisoformat(scheduled).replace(tzinfo=timezone.utc)
    got_local = got_utc + timedelta(minutes=off_min)
    ok = (got_local.weekday() == target_wd and got_local.hour == local_hour and got_utc > now)
    # what the OLD (Postgres DOW) bucket would have selected
    dow = int(row.split("| dow=")[1])
    old_index = dow  # 0=Sunday..6=Saturday used as if it were 0=Monday
    old_day_name = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][old_index % 7]
    print(f"[{label}] scheduled_at={scheduled} local={got_local.isoformat()} "
          f"weekday={got_local.strftime('%A')} hour={got_local.hour}")
    print(f"[{label}] OLD DOW-shifted bucket would name {old_day_name} (index {old_index}) vs correct "
          f"{event_local.strftime('%A')} (index {event_local.weekday()})")
    print(f"[{label}] VERDICT {'PASS' if ok else 'FAIL'}: expected {event_local.strftime('%A')} {local_hour}:00 local, "
          f"got {got_local.strftime('%A')} {got_local.hour}:00 local")

print("DONE")
