#!/usr/bin/env python3
"""ApexMail real-mail qualification runner, Python 3.12+, standard library only.

No external mail is sent by init, plan, prepare, verify, analyze, or selftest. `run` sends
only to the exact allowlist, through configured authorized routes. It uses
independent read-only IMAP observation. `webhooks` is a signed callback sink.
This tests email correctness and reliability, not marketing or conversion lift.
"""
from __future__ import annotations

import argparse
import base64
import collections
import concurrent.futures
import contextlib
import copy
import email
import email.policy
import hashlib
import hmac
import http.server
import imaplib
import ipaddress
import json
import math
import os
import re
import secrets
import smtplib
import socket
import socketserver
import sqlite3
import ssl
import statistics
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, parseaddr
from pathlib import Path

VERSION = "1.0"
REVIEWED_COMMIT = "81595f7197f9513219125c6bbc966149850e361b"
CASES = ("plain", "unicode", "html", "attachment", "idempotency", "reserved_header")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,100}$")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value, exclusive=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o600), "w") as out:
        json.dump(value, out, indent=2, ensure_ascii=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())


def load(path):
    return json.loads(Path(path).read_text())


def clock_id():
    p = Path("/proc/sys/kernel/random/boot_id")
    if p.exists():
        return p.read_text().strip()
    # Cross-process monotonic comparability is not inferred off Linux.
    return "process-" + str(os.getpid())


def address(value):
    if not isinstance(value, str) or any(c in value for c in "\r\n\x00"):
        raise ValueError("invalid address")
    _, parsed = parseaddr(value)
    if parsed != value or not re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+", value):
        raise ValueError("use one exact bare addr-spec")
    if not value.isascii():raise ValueError("this runner uses ASCII addresses and separately tests Unicode content")
    return value


def credential(name):
    if not isinstance(name, str) or not ENV_RE.fullmatch(name):
        raise ValueError("invalid credential environment name")
    value = os.environ.get(name)
    if not value:
        raise ValueError("missing environment variable: " + name)
    return value


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def validate_config(c, need_secrets=False, fixture=False):
    if set(c["routes"]) != {"A", "B"}:
        raise ValueError("define exactly A and B; point both at ApexMail for A/A")
    allow = set(map(address, c["allowlist"]))
    address(c["from"])
    if not allow or not c["mailboxes"]:
        raise ValueError("allowlist and independent receiver accounts required")
    ids = [m["id"] for m in c["mailboxes"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate mailbox id")
    for m in c["mailboxes"]:
        if address(m["address"]) not in allow:
            raise ValueError("recipient outside allowlist")
        if not m.get("folders") or len(m["folders"]) != len(set(m["folders"])):
            raise ValueError("declare distinct observable folders")
        if any(not isinstance(f,str) or not f.isascii() or any(x in f for x in "\r\n\x00") for f in m["folders"]):
            raise ValueError("use ASCII IMAP folder names without controls")
        if not fixture and not m.get("tls", True):
            raise ValueError("live IMAP requires TLS")
        if need_secrets:
            credential(m["user_env"])
            credential(m["token_env"] if m.get("auth")=="xoauth2" else m["password_env"])
    for r in c["routes"].values():
        if r["kind"] == "api":
            u = urllib.parse.urlsplit(r["url"])
            if not u.hostname or u.username or u.password or u.fragment or u.query:
                raise ValueError("API URL must not contain credentials, query or fragment")
            if u.path != "/v1/messages":
                raise ValueError("API URL must end in /v1/messages")
            if u.scheme != "https" and not (fixture and u.scheme == "http" and loopback(u.hostname)):
                raise ValueError("live API requires HTTPS")
            if need_secrets:
                credential(r["key_env"])
        elif r["kind"] == "smtp":
            if not fixture and r.get("tls") not in ("starttls", "implicit"):
                raise ValueError("live SMTP requires STARTTLS or implicit TLS")
            if need_secrets and not fixture:
                credential(r["user_env"])
                credential(r["token_env"] if r.get("auth")=="xoauth2" else r["password_env"])
        else:
            raise ValueError("route kind must be api or smtp")
    for key in ("deadline_s", "late_window_s", "poll_s", "pair_gap_s", "pace_s", "timeout_s"):
        v = c[key]
        if not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
            raise ValueError("positive finite " + key + " required")
    if not 0 < c["alpha"] < 1 or type(c["rounds"]) is not int or not 1 <= c["rounds"] <= 100:
        raise ValueError("invalid alpha or rounds")
    if not set(c["cases"]).issubset(CASES) or not c["cases"] or len(c["cases"])!=len(set(c["cases"])):
        raise ValueError("unknown/empty case list")
    return c


def example_config():
    return {
        "reviewed_commit": REVIEWED_COMMIT,
        "from": "canary@YOUR-VERIFIED-DOMAIN.example",
        "allowlist": ["YOUR-OWNED-SEED@gmail.com"],
        "routes": {
            "A": {"kind": "api", "url": "https://api.apexmail.ee/v1/messages", "key_env": "APEXMAIL_API_KEY"},
            "B": {"kind": "api", "url": "https://api.apexmail.ee/v1/messages", "key_env": "APEXMAIL_API_KEY"},
        },
        "mailboxes": [{"id": "gmail-owned-1", "provider": "google", "address": "YOUR-OWNED-SEED@gmail.com",
                       "host": "imap.gmail.com", "port": 993, "tls": True,
                       "user_env": "SEED_GMAIL_USER", "password_env": "SEED_GMAIL_APP_PASSWORD",
                       "folders": ["INBOX", "[Gmail]/Spam"]}],
        "cases": list(CASES), "rounds": 1, "max_logical_messages": 64,
        "deadline_s": 300, "late_window_s": 600, "poll_s": 10,
        "pair_gap_s": 1, "pace_s": 1, "timeout_s": 20, "alpha": .05,
        "randomization_assumptions": "Independent assignment coins; no cross-probe interference. A/A checks observer/route symmetry, not population inbox rate.",
    }


def make_plan(c, fixture=False):
    validate_config(c, fixture=fixture)
    run_id = secrets.token_hex(10)
    probes = []
    coins = []
    pair_num = 0
    for round_no in range(c["rounds"]):
        boxes = list(c["mailboxes"])
        secrets.SystemRandom().shuffle(boxes)
        for box in boxes:
            cases = list(c["cases"])
            secrets.SystemRandom().shuffle(cases)
            for case in cases:
                if case in ("idempotency", "reserved_header") and any(r["kind"] != "api" for r in c["routes"].values()):
                    continue  # Never imply SMTP has the HTTP idempotency contract.
                bit = secrets.randbits(1)
                coins.append(bit)
                pair_id = f"p{pair_num:05d}"
                for slot, route in enumerate(("B", "A") if bit else ("A", "B")):
                    pid = f"{pair_id}s{slot}"
                    probes.append({"id": pid, "pair_id": pair_id, "slot": slot, "route": route,
                                   "mailbox_id": box["id"], "provider": box["provider"], "case": case,
                                   "expected": "REFUSED" if case == "reserved_header" else "RECEIPT",
                                   "nonce": secrets.token_hex(16), "round": round_no})
                pair_num += 1
    if not probes or len(probes) > c["max_logical_messages"]:
        raise ValueError("empty plan or message budget exceeded")
    plan = {"version": VERSION, "origin": "LOCAL_FIXTURE" if fixture else "EXTERNAL_CONFIGURED",
            "run_id": run_id, "created_utc_ns": time.time_ns(), "config_sha256": sha(canonical(c)),
            "runner_sha256": sha(Path(__file__).read_bytes()), "reviewed_commit": c.get("reviewed_commit"),
            "assignment_coins": coins, "config": c, "probes": probes}
    return plan


def validate_plan(plan, expected_sha=None):
    digest = sha(canonical(plan))
    if expected_sha and not hmac.compare_digest(digest, expected_sha):
        raise ValueError("plan differs from externally retained hash")
    c = plan["config"]
    if sha(canonical(c)) != plan["config_sha256"]:
        raise ValueError("config mismatch")
    validate_config(c, fixture=plan["origin"] == "LOCAL_FIXTURE")
    ids = [p["id"] for p in plan["probes"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate probe id")
    pairs = collections.defaultdict(list)
    mailboxes = {m["id"]: m for m in c["mailboxes"]}
    for p in plan["probes"]:
        if p["mailbox_id"] not in mailboxes or p["route"] not in c["routes"] or p["case"] not in CASES:
            raise ValueError("invalid probe")
        pairs[p["pair_id"]].append(p)
    if len(pairs) != len(plan["assignment_coins"]):
        raise ValueError("missing randomization coin")
    for i, ps in enumerate(pairs.values()):
        ps = sorted(ps, key=lambda p: p["slot"])
        if [p["slot"] for p in ps] != [0, 1] or {p["route"] for p in ps} != {"A", "B"}:
            raise ValueError("unbalanced pair")
        if len({(p["mailbox_id"], p["case"]) for p in ps}) != 1:
            raise ValueError("unmatched pair")
        if [p["route"] for p in ps] != (["B", "A"] if plan["assignment_coins"][i] else ["A", "B"]):
            raise ValueError("assignment/coin mismatch")
    return digest


class Evidence:
    """Append-only, SQLite-transactional hash chain. An external root is needed
    against a party able to rewrite the entire database, not just one row.
    """
    def __init__(self, directory):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root / "raw").mkdir(exist_ok=True, mode=0o700)
        self.db = self.root / "evidence.sqlite3"
        with self.connect() as con:
            con.execute("CREATE TABLE IF NOT EXISTS log(seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL, prev TEXT NOT NULL, digest TEXT NOT NULL)")

    @contextlib.contextmanager
    def connect(self):
        con = sqlite3.connect(self.db, timeout=30)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:con.close()

    def append(self, kind, data):
        data = dict(data, wall_ns=time.time_ns(), mono_ns=time.monotonic_ns(), clock=clock_id())
        encoded = canonical(data).decode()
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            last = con.execute("SELECT seq,digest FROM log ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1]) if last else (1, "0" * 64)
            digest = sha(canonical([seq, kind, encoded, prev]))
            con.execute("INSERT INTO log VALUES (?,?,?,?,?)", (seq, kind, encoded, prev, digest))
        return data

    def rows(self):
        with self.connect() as con:
            return [{"seq":r[0],"kind":r[1],"data":json.loads(r[2]),"prev":r[3],"digest":r[4]}
                    for r in con.execute("SELECT * FROM log ORDER BY seq")]

    def raw(self, body, suffix):
        digest = sha(body)
        path = self.root / "raw" / (digest + suffix)
        if not path.exists():
            temp=path.with_name(path.name+"."+secrets.token_hex(8)+".tmp")
            try:
                with open(temp,"xb") as out:
                    out.write(body);out.flush();os.fsync(out.fileno())
                try:os.link(temp,path)
                except FileExistsError:pass
            finally:
                with contextlib.suppress(FileNotFoundError):temp.unlink()
        if sha(path.read_bytes())!=digest:raise ValueError("raw evidence collision/corruption")
        return path.relative_to(self.root).as_posix(), digest

    def verify(self, plan_sha):
        rows = self.rows()
        if not rows or rows[0]["kind"] != "plan" or rows[0]["data"]["plan_sha"] != plan_sha:
            raise ValueError("missing/wrong plan root")
        prev = "0" * 64
        for seq, row in enumerate(rows, 1):
            encoded = canonical(row["data"]).decode()
            if row["seq"] != seq or row["prev"] != prev or row["digest"] != sha(canonical([seq,row["kind"],encoded,prev])):
                raise ValueError("broken evidence hash chain")
            if "raw_path" in row["data"]:
                f = (self.root / row["data"]["raw_path"]).resolve()
                if self.root.resolve() not in f.parents or sha(f.read_bytes()) != row["data"]["raw_sha"]:
                    raise ValueError("missing or altered raw evidence")
            prev = row["digest"]
        return prev


def fixture(plan, p):
    c = plan["config"]
    subject = f"AMQ-{plan['run_id']}-{p['id']} controlled canary"
    marker = f"ApexMail qualification {plan['run_id']} {p['id']} {p['nonce']}"
    text = marker + "\nNo reply or link interaction is required.\n"
    if p["case"] == "unicode":
        text += "Tunis: مرحبا | Français: reçu été | 日本語: 確認 | emoji: 🧪\n"
    headers = {"X-Validation-Run":plan["run_id"],"X-Validation-Probe":p["id"]}
    if p["case"] == "reserved_header":
        headers["X-ApexMail-Route"] = "forbidden-qualification-header"
    body = {"from":c["from"],"to":[next(m["address"] for m in c["mailboxes"] if m["id"]==p["mailbox_id"])],
            "subject":subject,"text":text,"headers":headers,"category":"transactional",
            "metadata":{"validation_run_id":plan["run_id"],"validation_probe_id":p["id"]},
            "tags":["qualification",plan["run_id"]]}
    if p["case"] == "html":
        body["html"] = "<html><body><p>" + marker + "</p><p>Canary only.</p></body></html>"
    if p["case"] == "attachment":
        content = canonical({"probe":p["id"],"nonce":p["nonce"],"test":"attachment integrity"})
        body["attachments"] = [{"filename":"canary.json","content":base64.b64encode(content).decode(),"contentType":"application/json"}]
    return body


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward credentials or repeat a send at another URL.


def send_probe(plan, p, evidence, fixture_mode=False):
    c = plan["config"]; route = c["routes"][p["route"]]
    body = fixture(plan,p)
    key = "amq-" + plan["run_id"] + "-" + p["id"]
    payload = canonical(body)
    copies = 2 if p["case"] == "idempotency" else 1
    prior = [r for r in evidence.rows() if r["kind"]=="attempt_start" and r["data"].get("probe")==p["id"]]
    if prior:
        raise ValueError("probe already attempted; reconcile it, never silently resend")
    for replay in range(copies):
        start = evidence.append("attempt_start",{"probe":p["id"],"replay":replay,"payload_sha":sha(payload),"idempotency_key":key})
        result = {"probe":p["id"],"replay":replay,"start_ns":start["mono_ns"],"state":"UNKNOWN"}
        try:
            if route["kind"] == "api":
                req = urllib.request.Request(route["url"],data=payload,method="POST",headers={"Content-Type":"application/json","X-API-Key":credential(route["key_env"]),"Idempotency-Key":key})
                opener = urllib.request.build_opener(NoRedirect)
                with opener.open(req,timeout=c["timeout_s"]) as response:
                    raw = response.read(1024*1024)
                    response_json = json.loads(raw)
                    inner = response_json.get("data",response_json)
                    remote = inner.get("id") if isinstance(inner,dict) else None
                    result.update(http_status=response.status,response_sha=sha(raw),remote_id=remote)
                    result["state"] = "ACCEPTED" if response.status in (200,201,202) and isinstance(remote,str) and remote else "UNKNOWN"
            else:
                msg = EmailMessage(policy=email.policy.SMTP)
                for name,value in {"From":body["from"],"To":body["to"][0],"Subject":body["subject"],"Message-ID":f"<{key}@{body['from'].split('@')[1]}>","Date":formatdate(localtime=False)}.items():
                    msg[name]=value
                for name,value in body["headers"].items(): msg[name]=value
                msg.set_content(body["text"])
                if "html" in body:msg.add_alternative(body["html"],subtype="html")
                for item in body.get("attachments",[]):
                    main,sub=item["contentType"].split("/",1)
                    msg.add_attachment(base64.b64decode(item["content"]),maintype=main,subtype=sub,filename=item["filename"])
                context=ssl.create_default_context()
                smtp = smtplib.SMTP_SSL(route["host"],route["port"],timeout=c["timeout_s"],context=context) if route.get("tls")=="implicit" else smtplib.SMTP(route["host"],route["port"],timeout=c["timeout_s"])
                try:
                    smtp.ehlo()
                    if route.get("tls")=="starttls":smtp.starttls(context=context);smtp.ehlo()
                    if not fixture_mode:
                        if route.get("auth")=="xoauth2":
                            auth=f"user={credential(route['user_env'])}\x01auth=Bearer {credential(route['token_env'])}\x01\x01"
                            smtp.auth("XOAUTH2",lambda challenge=None:auth if challenge is None else "")
                        else:smtp.login(credential(route["user_env"]),credential(route["password_env"]))
                    refused=smtp.send_message(msg,from_addr=body["from"],to_addrs=body["to"])
                    result["state"]="REFUSED" if refused else "ACCEPTED"
                finally:
                    # QUIT loss after successful DATA must not erase acceptance.
                    with contextlib.suppress(Exception):smtp.quit()
        except urllib.error.HTTPError as error:
            result.update(http_status=error.code,state="REFUSED" if 400<=error.code<500 else "UNKNOWN",error_class=type(error).__name__)
        except smtplib.SMTPRecipientsRefused:
            result.update(state="REFUSED",error_class="SMTPRecipientsRefused")
        except Exception as error:
            result.update(error_class=type(error).__name__)
        evidence.append("attempt_end",result)
        # An unknown first outcome is reconciled before any intentional replay.
        if result["state"]!="ACCEPTED":break


def check_mime(plan,p,raw):
    msg=email.message_from_bytes(raw,policy=email.policy.default)
    body=fixture(plan,p)
    if parseaddr(str(msg.get("From","")))[1]!=body["from"]:return False,"From altered"
    if parseaddr(str(msg.get("To","")))[1]!=body["to"][0]:return False,"To altered"
    if str(msg.get("Subject",""))!=body["subject"]:return False,"Subject altered"
    text=[]; attachments=[];html=[]
    for part in msg.walk():
        if part.is_multipart():continue
        if part.get_content_disposition()=="attachment":
            attachments.append((part.get_filename(),sha(part.get_payload(decode=True) or b"")))
        elif part.get_content_type() in ("text/plain","text/html"):
            try:
                content=str(part.get_content());text.append(content)
                if part.get_content_type()=="text/html":html.append(content)
            except Exception:pass
    combined="\n".join(text)
    if body["text"].replace("\r\n","\n") not in combined.replace("\r\n","\n"):return False,"declared text missing or altered"
    expected=body["text"].splitlines()[0]
    if expected not in combined:return False,"missing exact nonce/marker"
    if p["case"]=="unicode" and "مرحبا | Français: reçu été | 日本語: 確認 | emoji: 🧪" not in combined:
        return False,"unicode corruption"
    for item in body.get("attachments",[]):
        item_hash=sha(base64.b64decode(item["content"]))
        if attachments.count((item["filename"],item_hash))!=1:return False,"attachment missing, duplicated or altered"
    if len(attachments)!=len(body.get("attachments",[])):return False,"unexpected attachment count"
    if p["nonce"] not in combined:return False,"nonce mismatch"
    if "html" in body and not any(body["html"] in h for h in html):return False,"HTML alternative missing or altered"
    return True,"marker and declared fixture bytes preserved"


def poll_mailbox(plan,box,evidence,fixture_mode=False):
    c=plan["config"]; client=None
    start=time.monotonic_ns()
    try:
        if box.get("tls",True):client=imaplib.IMAP4_SSL(box["host"],box["port"],ssl_context=ssl.create_default_context(),timeout=c["timeout_s"])
        elif fixture_mode:client=imaplib.IMAP4(box["host"],box["port"],timeout=c["timeout_s"])
        else:raise ValueError("live observer must use TLS")
        if box.get("auth")=="xoauth2":
            user=credential(box["user_env"]);token=credential(box["token_env"])
            client.authenticate("XOAUTH2",lambda _:f"user={user}\x01auth=Bearer {token}\x01\x01".encode())
        else:client.login(credential(box["user_env"]),credential(box["password_env"]))
        for folder in box["folders"]:
            began=time.monotonic_ns()
            quoted='"'+folder.replace('\\','\\\\').replace('"','\\"')+'"'
            typ,_=client.select(quoted,readonly=True)
            if typ!="OK":raise RuntimeError("EXAMINE failed")
            uidvalidity=client.response("UIDVALIDITY")[1]
            uidvalidity=repr(uidvalidity)
            typ,data=client.uid("SEARCH",None,"HEADER","Subject",f'"AMQ-{plan["run_id"]}"')
            if typ!="OK":raise RuntimeError("UID SEARCH failed")
            uids=(data[0] or b"").split()
            known={(r["data"]["folder"],r["data"]["uidvalidity"],r["data"]["uid"]) for r in evidence.rows() if r["kind"]=="observation" and r["data"]["mailbox"]==box["id"]}
            current=[]
            for uid in uids:
                uid_text=uid.decode()
                current.append(uid_text)
                if (folder,uidvalidity,uid_text) in known:continue
                typ,parts=client.uid("FETCH",uid,"(UID INTERNALDATE BODY.PEEK[])")
                if typ!="OK":raise RuntimeError("UID FETCH failed")
                literals=[part[1] for part in parts if isinstance(part,tuple) and isinstance(part[1],bytes)]
                if len(literals)!=1:raise RuntimeError("ambiguous FETCH literal")
                raw=literals[0]
                msg=email.message_from_bytes(raw,policy=email.policy.default)
                matches=[p for p in plan["probes"] if p["mailbox_id"]==box["id"] and f"AMQ-{plan['run_id']}-{p['id']} " in str(msg.get("Subject",""))]
                if len(matches)!=1:raise RuntimeError("message/probe identity ambiguous")
                p=matches[0];ok,reason=check_mime(plan,p,raw)
                raw_path,raw_sha=evidence.raw(raw,".eml")
                evidence.append("observation",{"probe":p["id"],"mailbox":box["id"],"folder":folder,"uid":uid_text,"uidvalidity":uidvalidity,
                    "raw_path":raw_path,"raw_sha":raw_sha,"mime_ok":ok,"mime_reason":reason,
                    "authentication_results_unverified":msg.get_all("Authentication-Results",[]),"received_headers":msg.get_all("Received",[])})
            evidence.append("poll_ok",{"mailbox":box["id"],"folder":folder,"begin_ns":began,"uids":current,"uidvalidity":uidvalidity})
    except Exception as error:
        evidence.append("poll_error",{"mailbox":box["id"],"begin_ns":start,"error_class":type(error).__name__})
    finally:
        if client:
            with contextlib.suppress(Exception):client.logout()


def prepare_run(plan,directory,expected_sha):
    digest=validate_plan(plan,expected_sha);evidence=Evidence(directory)
    if evidence.rows() or (evidence.root/"plan.json").exists():raise ValueError("evidence already prepared; use a new directory")
    write_json(evidence.root/"plan.json",plan,exclusive=True)
    evidence.append("plan",{"plan_sha":digest,"origin":plan["origin"],"run_id":plan["run_id"]})
    return evidence


def execute(plan,directory,expected_sha,fixture_mode=False):
    digest=validate_plan(plan,expected_sha)
    if (plan["origin"]=="LOCAL_FIXTURE")!=fixture_mode:raise ValueError("fixture/live origin mismatch")
    if plan["runner_sha256"]!=sha(Path(__file__).read_bytes()):raise ValueError("runner changed since plan; create a new plan")
    c=validate_config(plan["config"],need_secrets=True,fixture=fixture_mode)
    evidence=Evidence(directory)
    # A persistent exclusive lock also prevents simultaneous fresh dispatchers.
    lock_fd=os.open(evidence.root/"dispatch.lock",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.close(lock_fd)
    rows=evidence.rows()
    if rows:
        if len(rows)!=1 or rows[0]["kind"]!="plan":raise ValueError("evidence run already started; observe/reconcile, do not replay")
        validate_plan(load(evidence.root/"plan.json"),digest);evidence.verify(digest)
    else:evidence=prepare_run(plan,directory,expected_sha)
    stop=threading.Event()
    def observer():
        while not stop.is_set():
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,len(c["mailboxes"]))) as pool:
                list(pool.map(lambda m:poll_mailbox(plan,m,evidence,fixture_mode),c["mailboxes"]))
            stop.wait(c["poll_s"])
    thread=threading.Thread(target=observer,daemon=True);thread.start()
    try:
        for p in plan["probes"]:
            send_probe(plan,p,evidence,fixture_mode)
            time.sleep(c["pair_gap_s"] if p["slot"]==0 else c["pace_s"])
        evidence.append("dispatch_complete",{})
        until=time.monotonic()+c["deadline_s"]+c["late_window_s"]
        while time.monotonic()<until:time.sleep(min(1,until-time.monotonic()))
    finally:
        stop.set();thread.join(timeout=c["timeout_s"]*(len(c["mailboxes"])+2))
    if thread.is_alive():raise RuntimeError("observer did not stop; run incomplete")
    for box in c["mailboxes"]:poll_mailbox(plan,box,evidence,fixture_mode)
    evidence.append("run_complete",{})
    return analyze(plan,evidence,expected_sha)


def binomial_half_tail(k,n):
    if k<0:return 0.0
    if k>=n:return 1.0
    # Exact binomial model, evaluated in stable log arithmetic.
    logs=[math.lgamma(n+1)-math.lgamma(i+1)-math.lgamma(n-i+1)-n*math.log(2) for i in range(k+1)]
    biggest=max(logs)
    return min(1.0,math.exp(biggest)*math.fsum(math.exp(x-biggest) for x in logs))


def paired_summary(values,alpha):
    n=len(values)
    d=sum(v!=0 for v in values);plus=sum(v>0 for v in values)
    exact_p=min(1.0,2*binomial_half_tail(min(plus,d-plus),d)) if d else 1.0
    if n<2:return {"pairs":n,"sharp_null_p_raw":exact_p,"comparison_alpha":alpha,"difference_interval":[-1,1]}
    mean=statistics.fmean(values);variance=statistics.variance(values);x=math.log(4/alpha)
    radius=math.sqrt(2*variance*x/n)+14*x/(3*(n-1))
    return {"pairs":n,"B_minus_A_observed_by_deadline":mean,"discordant_pairs":d,"sharp_null_p_raw":exact_p,"comparison_alpha":alpha,
            "difference_interval":[max(-1,mean-radius),min(1,mean+radius)],
            "assumptions":"Independent pair-assignment coins; no interference; complete prespecified observations. This is a finite-panel protocol contrast, not a population inbox-rate claim."}


def analyze(plan,evidence,expected_sha):
    digest=validate_plan(plan,expected_sha);tail=evidence.verify(digest);rows=evidence.rows();c=plan["config"]
    problems=[];incomplete=[];outcomes={};started={};observations=collections.defaultdict(list)
    clocks={r["data"]["clock"] for r in rows if r["kind"]!="plan"}
    if len(clocks)!=1:incomplete.append("clock/boot changed")
    if not any(r["kind"]=="run_complete" for r in rows):incomplete.append("run not closed at prespecified maturity")
    for row in rows:
        d=row["data"]
        if row["kind"]=="attempt_start":started.setdefault(d["probe"],d["mono_ns"])
        if row["kind"]=="observation":observations[d["probe"]].append(d)
    epochs=collections.defaultdict(set)
    for row in rows:
        if row["kind"]=="poll_ok":epochs[(row["data"]["mailbox"],row["data"]["folder"])].add(row["data"]["uidvalidity"])
    if any(len(v)>1 for v in epochs.values()):incomplete.append("UIDVALIDITY changed during run")
    for p in plan["probes"]:
        pid=p["id"];ends=[r["data"] for r in rows if r["kind"]=="attempt_end" and r["data"]["probe"]==pid]
        starts=[r for r in rows if r["kind"]=="attempt_start" and r["data"]["probe"]==pid]
        if len(starts)!=len(ends) or not ends or any(e["state"]=="UNKNOWN" for e in ends):incomplete.append(pid+": interrupted/ambiguous send")
        if p["case"]=="idempotency" and (len(ends)!=2 or len({e.get("remote_id") for e in ends})!=1):problems.append(pid+": idempotency response mismatch")
        if p["expected"]=="REFUSED":
            if any(e["state"]!="REFUSED" or e.get("http_status")!=422 for e in ends) or observations[pid]:problems.append(pid+": reserved internal header did not produce exact 422 with no receipt")
        elif any(e["state"]=="REFUSED" for e in ends):problems.append(pid+": positive canary refused")
        obs=observations[pid]
        if any(not o["mime_ok"] for o in obs):problems.append(pid+": MIME/attachment mismatch")
        if p["expected"]=="RECEIPT" and not obs:problems.append(pid+": not observed by final horizon")
        for folder in next(m["folders"] for m in c["mailboxes"] if m["id"]==p["mailbox_id"]):
            folder_obs=[o for o in obs if o["folder"]==folder]
            epochs={o["uidvalidity"] for o in folder_obs}
            if len(epochs)>1:incomplete.append(pid+": UIDVALIDITY changed")
            # Simultaneous membership of two UIDs is evidence of two visible copies.
            by_epoch=collections.defaultdict(set)
            for o in folder_obs:by_epoch[o["uidvalidity"]].add(o["uid"])
            for epoch,uids in by_epoch.items():
                polls=[r["data"] for r in rows if r["kind"]=="poll_ok" and r["data"]["mailbox"]==p["mailbox_id"] and r["data"]["folder"]==folder and r["data"]["uidvalidity"]==epoch]
                if any(len(set(x["uids"])&uids)>1 for x in polls):problems.append(pid+": duplicate simultaneous folder copies")
            close=started.get(pid,10**30)+int((c["deadline_s"]+c["late_window_s"])*1e9)
            coverage=[r["data"] for r in rows if r["kind"]=="poll_ok" and r["data"]["mailbox"]==p["mailbox_id"] and r["data"]["folder"]==folder and r["data"]["begin_ns"]>=close]
            if not coverage:incomplete.append(pid+": no mature observer poll for "+folder)
        upper=min((o["mono_ns"]-started.get(pid,o["mono_ns"]) for o in obs),default=None)
        ontime=upper is not None and 0<=upper<=c["deadline_s"]*1e9
        outcomes[pid]={"observed":bool(obs),"confirmed_by_deadline":ontime,"first_observed_upper_s":upper/1e9 if upper is not None else None,
                       "folders":sorted({o["folder"] for o in obs}),"authentication":"NOT_INDEPENDENTLY_VERIFIED"}
    if not problems and not incomplete and any(not outcomes[p["id"]]["confirmed_by_deadline"] for p in plan["probes"] if p["expected"]=="RECEIPT"):
        problems.append("one or more positive canaries not proved on time")
    groups=collections.defaultdict(list)
    pairs=collections.defaultdict(list)
    for p in plan["probes"]:
        if p["expected"]=="RECEIPT":pairs[p["pair_id"]].append(p)
    for ps in pairs.values():
        if len(ps)!=2:incomplete.append("missing pair member");continue
        arms={p["route"]:outcomes[p["id"]]["confirmed_by_deadline"] for p in ps}
        groups[ps[0]["provider"]].append(int(arms["B"])-int(arms["A"]))
    stats={g:paired_summary(v,c["alpha"]/max(1,len(groups))) for g,v in groups.items()} if not incomplete else {}
    status="INCOMPLETE" if incomplete else "OBSERVED_FAILURE" if problems else "PANEL_CHECKS_PASSED"
    result={"status":status,"origin":plan["origin"],"scope":"Only the declared receiver panel, routes, message fixtures and finite observation window.",
            "plan_sha256":digest,"terminal_chain_sha256":tail,"problems":sorted(set(problems)),"incomplete":sorted(set(incomplete)),
            "logical_probes":len(plan["probes"]),"outcomes":outcomes,"paired_route_diagnostics":stats,
            "route_inference_status":"CONDITIONAL_ONLY: independent assignment coins are generated; no interference and stable potential outcomes are not verified by the runner.",
            "not_established":["population inbox placement","independent per-message failure probability","99.9% long-run availability","DKIM/SPF/DMARC trust boundary","correct quota/billing without ledger reconciliation"]}
    write_json(evidence.root/"summary.json",result)
    return result


def audit_sample(plan,evidence,plan_sha,chain_sha,count):
    """Uniform sample without replacement of immutable receipt records.

    A human/independent implementation must adjudicate the selected .eml
    files. This samples evidence, not future mail or a provider population.
    """
    validate_plan(plan,plan_sha)
    tail=evidence.verify(plan_sha)
    if not hmac.compare_digest(tail,chain_sha):raise ValueError("audit population differs from retained terminal hash")
    population=[]
    for row in evidence.rows():
        if row["kind"]=="observation":
            d=row["data"]
            population.append({"seq":row["seq"],"probe":d["probe"],"mailbox":d["mailbox"],"folder":d["folder"],"uid":d["uid"],"uidvalidity":d["uidvalidity"],"raw_path":d["raw_path"],"raw_sha":d["raw_sha"]})
    if type(count) is not int or not 0<count<=len(population):raise ValueError("sample count must be positive and no larger than observation population")
    selected=secrets.SystemRandom().sample(population,count)
    return {"plan_sha256":plan_sha,"population_terminal_sha256":tail,"population_records":len(population),"sample_records":count,
            "sampling":"Uniform without replacement; retain this selection before independent adjudication. Records can represent folder aliases of one mail.","selected":selected}


def webhook_valid(raw,signature,timestamp,secret,now_ms=None):
    if not isinstance(timestamp,str) or not re.fullmatch(r"[0-9]{13}",timestamp):return False
    if not isinstance(signature,str) or not re.fullmatch(r"sha256=[0-9a-f]{64}",signature):return False
    if not secret:return False
    now_ms=int(time.time()*1000) if now_ms is None else now_ms
    if abs(now_ms-int(timestamp))>300000:return False
    expected=hmac.new(secret.encode(),timestamp.encode()+b"."+raw,hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature[7:],expected)


def webhook_correlates(payload,plan,rows,tenant_id):
    if not isinstance(payload,dict) or payload.get("tenantId")!=tenant_id:return False
    data=payload.get("data")
    if not isinstance(data,dict):return False
    known_probes={p["id"] for p in plan["probes"]}
    metadata=data.get("metadata",{})
    if isinstance(metadata,dict) and metadata.get("validation_run_id")==plan["run_id"] and metadata.get("validation_probe_id") in known_probes:return True
    remote={r["data"].get("remote_id") for r in rows if r["kind"]=="attempt_end" and r["data"].get("state")=="ACCEPTED"}
    remote.discard(None)
    return data.get("messageId") in remote or data.get("message_id") in remote


def webhook_handler(evidence,plan,secret,fail_first,tenant_id):
    event_lock=threading.Lock()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            try:length=int(self.headers.get("Content-Length","0"))
            except ValueError:length=0
            if not 0<length<=1024*1024:self.send_error(413);return
            raw=self.rfile.read(length);ts=self.headers.get("X-ApexMail-Timestamp");sig=self.headers.get("X-ApexMail-Signature")
            if not webhook_valid(raw,sig,ts,secret):self.send_error(401);return
            try:payload=json.loads(raw)
            except ValueError:self.send_error(400);return
            if not webhook_correlates(payload,plan,evidence.rows(),tenant_id):
                self.send_response(202);self.end_headers();return
            eid=payload.get("id")
            if not isinstance(eid,str) or not eid:self.send_error(400);return
            with event_lock:
                previous=sum(r["kind"]=="webhook" and r["data"]["event_id"]==eid for r in evidence.rows())
                path,digest=evidence.raw(raw,".webhook.json")
                status=503 if previous<fail_first else 204
                evidence.append("webhook",{"event_id":eid,"tenant_id":tenant_id,"type":payload.get("type"),"timestamp_header":ts,"signature_valid":True,
                                           "raw_path":path,"raw_sha":digest,"response_status":status})
            self.send_response(status);self.end_headers()
    return Handler


def webhook_server(directory,secret_env,host,port,fail_first,tenant_id):
    if not loopback(host):raise ValueError("bind to loopback behind your authenticated HTTPS reverse proxy")
    if fail_first<0 or not tenant_id:raise ValueError("expected tenant and nonnegative fail-first required")
    evidence=Evidence(directory);secret=credential(secret_env);plan=load(Path(directory)/"plan.json")
    Handler=webhook_handler(evidence,plan,secret,fail_first,tenant_id)
    print(json.dumps({"listen":f"http://{host}:{port}","requires":"Register your own HTTPS reverse-proxy URL in ApexMail. No tunnel or external endpoint is created."}),flush=True)
    http.server.ThreadingHTTPServer((host,port),Handler).serve_forever()


def main():
    os.umask(0o077)
    ap=argparse.ArgumentParser(description=__doc__)
    sub=ap.add_subparsers(dest="command",required=True)
    init=sub.add_parser("init");init.add_argument("--config",required=True)
    plan=sub.add_parser("plan");plan.add_argument("--config",required=True);plan.add_argument("--output",required=True)
    run=sub.add_parser("run");run.add_argument("--plan",required=True);run.add_argument("--plan-sha",required=True);run.add_argument("--out",required=True)
    prepare=sub.add_parser("prepare");prepare.add_argument("--plan",required=True);prepare.add_argument("--plan-sha",required=True);prepare.add_argument("--out",required=True)
    audit=sub.add_parser("audit-sample");audit.add_argument("--out",required=True);audit.add_argument("--plan-sha",required=True);audit.add_argument("--chain-sha",required=True);audit.add_argument("--count",type=int,required=True);audit.add_argument("--output",required=True)
    for name in ["verify","analyze","observe"]:
        p=sub.add_parser(name);p.add_argument("--out",required=True);p.add_argument("--plan-sha",required=True)
        if name=="verify":p.add_argument("--chain-sha",help="Externally retained terminal hash; detects a rewritten or truncated suffix")
        if name=="observe":p.add_argument("--seconds",type=float,default=60)
    hooks=sub.add_parser("webhooks");hooks.add_argument("--out",required=True);hooks.add_argument("--secret-env",default="APEXMAIL_WEBHOOK_SECRET");hooks.add_argument("--host",default="127.0.0.1");hooks.add_argument("--port",type=int,default=8097);hooks.add_argument("--fail-first",type=int,default=0);hooks.add_argument("--tenant-id",required=True)
    sub.add_parser("selftest")
    args=ap.parse_args()
    if args.command=="init":write_json(args.config,example_config(),exclusive=True);print(args.config);return
    if args.command=="plan":
        p=make_plan(load(args.config));write_json(args.output,p,exclusive=True)
        print(json.dumps({"plan":args.output,"plan_sha256":sha(canonical(p)),"logical_messages":len(p["probes"]),"note":"Retain this hash outside the run directory before sending."}));return
    if args.command=="selftest":
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (Checks,WireChecks)])
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if args.command=="webhooks":webhook_server(args.out,args.secret_env,args.host,args.port,args.fail_first,args.tenant_id);return
    if args.command=="prepare":
        e=prepare_run(load(args.plan),args.out,args.plan_sha);print(json.dumps({"prepared":args.out,"root_sha256":e.verify(args.plan_sha)}));return
    if args.command=="run":result=execute(load(args.plan),args.out,args.plan_sha)
    else:
        e=Evidence(args.out);p=load(Path(args.out)/"plan.json");validate_plan(p,args.plan_sha)
        if args.command=="audit-sample":
            selection=audit_sample(p,e,args.plan_sha,args.chain_sha,args.count)
            write_json(args.output,selection,exclusive=True);print(json.dumps({"population_records":selection["population_records"],"sample_records":args.count,"selection_sha256":sha(canonical(selection))}));return
        if args.command=="verify":
            tail=e.verify(args.plan_sha)
            if args.chain_sha and not hmac.compare_digest(tail,args.chain_sha):raise ValueError("terminal chain differs from external anchor")
            print(json.dumps({"verified_terminal_hash":tail,"external_terminal_anchor_checked":bool(args.chain_sha)}));return
        if args.command=="observe":
            if args.seconds<=0:raise ValueError("positive observation period required")
            end=time.monotonic()+args.seconds
            while True:
                for box in p["config"]["mailboxes"]:poll_mailbox(p,box,e)
                if time.monotonic()>=end:break
                time.sleep(min(p["config"]["poll_s"],max(0,end-time.monotonic())))
            e.append("reconciliation_observation_complete",{})
        result=analyze(p,e,args.plan_sha)
    print(json.dumps({k:result[k] for k in ["status","origin","logical_probes","problems","incomplete"]},indent=2))
    raise SystemExit(0 if result["status"]=="PANEL_CHECKS_PASSED" else 2)


class WireWorld:
    """Local wire fixtures, never a production ApexMail or provider test.

    HTTP, SMTP and IMAP really cross loopback sockets. The intentional faults
    test whether the evidence apparatus rejects incorrect/uncertain outcomes.
    """
    def __init__(self,fault=None):
        self.fault=fault;self.lock=threading.RLock();self.messages=[];self.idempotency={}
        self.requests=[];self.commands=[];self.epoch=771;self.servers=[];self.threads=[]

    def add(self,raw):
        with self.lock:
            m=email.message_from_bytes(raw,policy=email.policy.default)
            if self.fault=="corrupt_attachment":
                for part in m.walk():
                    if part.get_content_disposition()=="attachment":part.set_payload(base64.b64encode(b"corruption").decode())
                raw=m.as_bytes(policy=email.policy.SMTP)
            if self.fault=="strip_html":
                raw=raw.replace(b"text/html",b"text/plain")
            if self.fault=="forged_auth":
                m["Authentication-Results"]="attacker.invalid; dkim=pass; spf=pass; dmarc=pass"
                raw=m.as_bytes(policy=email.policy.SMTP)
            if self.fault=="drop_message":return
            for _ in range(2 if self.fault=="duplicate" else 1):
                self.messages.append({"uid":len(self.messages)+1,"folder":"Spam" if self.fault=="deliver_spam" else "INBOX","raw":raw})

    def __enter__(self):
        world=self
        class API(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                key=self.headers.get("Idempotency-Key")
                with world.lock:
                    world.requests.append((key,body))
                    if "X-ApexMail-Route" in body.get("headers",{}):
                        self.send_response(401 if world.fault=="reserved_unauthorized" else 422);self.end_headers();return
                    if key not in world.idempotency:
                        remote="msg_fixture_"+str(len(world.idempotency))
                        m=EmailMessage(policy=email.policy.SMTP)
                        for h,v in {"From":body["from"],"To":body["to"][0],"Subject":body["subject"],**body.get("headers",{})}.items():m[h]=v
                        m.set_content(body["text"])
                        if "html" in body:m.add_alternative(body["html"],subtype="html")
                        for item in body.get("attachments",[]):
                            main,sub=item["contentType"].split("/",1)
                            m.add_attachment(base64.b64decode(item["content"]),maintype=main,subtype=sub,filename=item["filename"])
                        world.add(m.as_bytes());world.idempotency[key]=remote
                    response={"data":{"status":"queued","id":world.idempotency[key]}}
                    if world.fault=="api_no_id":del response["data"]["id"]
                raw=canonical(response)
                self.send_response(202);self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
        class TCP(socketserver.ThreadingTCPServer):
            allow_reuse_address=True;daemon_threads=True
            def handle_error(self,*args):pass
        class Base(socketserver.StreamRequestHandler):
            def setup(self):
                super().setup();self.request.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            def reply(self,value):self.wfile.write(value.encode() if isinstance(value,str) else value);self.wfile.flush()
        class SMTP(Base):
            def handle(self):
                self.reply("220 fixture ESMTP\r\n")
                while True:
                    line=self.rfile.readline()
                    if not line:return
                    verb=line.split(b" ",1)[0].strip().upper()
                    if verb in (b"EHLO",b"HELO"):self.reply("250-fixture\r\n250 SIZE 1048576\r\n")
                    elif verb in (b"MAIL",b"RCPT",b"RSET",b"NOOP"):self.reply("250 OK\r\n")
                    elif verb==b"DATA":
                        self.reply("354 end with dot\r\n");parts=[]
                        while True:
                            item=self.rfile.readline()
                            if not item:return
                            if item==b".\r\n":break
                            parts.append(item[1:] if item.startswith(b"..") else item)
                        world.add(b"".join(parts))
                        if world.fault=="smtp_lost_ack":return
                        self.reply("250 durable fixture acceptance\r\n")
                    elif verb==b"QUIT":self.reply("221 bye\r\n");return
                    else:self.reply("500 unsupported\r\n")
        class IMAP(Base):
            def handle(self):
                self.reply("* OK fixture IMAP4rev1\r\n");folder="INBOX"
                while True:
                    line=self.rfile.readline()
                    if not line:return
                    text=line.decode().rstrip();parts=text.split(" ",2)
                    if len(parts)<2:return
                    tag,cmd=parts[0],parts[1].upper();args=parts[2] if len(parts)>2 else ""
                    with world.lock:world.commands.append((cmd,args))
                    if cmd=="CAPABILITY":self.reply(f"* CAPABILITY IMAP4rev1\r\n{tag} OK capability\r\n")
                    elif cmd=="LOGIN":self.reply(f"{tag} OK authenticated fixture\r\n")
                    elif cmd=="EXAMINE":
                        folder=args.strip('"')
                        if world.fault=="missing_folder" and folder=="Spam":self.reply(f"{tag} NO folder unavailable\r\n");continue
                        self.reply(f"* FLAGS (\\Seen)\r\n* 0 EXISTS\r\n* OK [UIDVALIDITY {world.epoch}] epoch\r\n{tag} OK [READ-ONLY] examined\r\n")
                    elif cmd=="UID" and args.upper().startswith("SEARCH"):
                        match=re.search(r"AMQ-[a-f0-9]+",args);needle=match.group(0).encode() if match else b"impossible"
                        with world.lock:uids=[str(m["uid"]) for m in world.messages if m["folder"]==folder and needle in m["raw"]]
                        self.reply(f"* SEARCH {' '.join(uids)}\r\n{tag} OK search\r\n")
                    elif cmd=="UID" and args.upper().startswith("FETCH"):
                        uid=int(args.split()[1])
                        with world.lock:found=[m for m in world.messages if m["uid"]==uid and m["folder"]==folder]
                        if not found:self.reply(f"{tag} NO uid absent\r\n");continue
                        raw=found[0]["raw"]
                        self.reply(f'* {uid} FETCH (UID {uid} INTERNALDATE "28-Oct-2026 00:00:00 +0000" BODY[] {{{len(raw)}}}\r\n')
                        self.reply(raw);self.reply(f")\r\n{tag} OK fetch\r\n")
                    elif cmd=="LOGOUT":self.reply(f"* BYE\r\n{tag} OK logout\r\n");return
                    else:self.reply(f"{tag} BAD unsupported\r\n")
        for server in (http.server.ThreadingHTTPServer(("127.0.0.1",0),API),TCP(("127.0.0.1",0),SMTP),TCP(("127.0.0.1",0),IMAP)):
            thread=threading.Thread(target=lambda s=server:s.serve_forever(poll_interval=.02),daemon=True)
            thread.start();self.servers.append(server);self.threads.append(thread)
        return self

    def config(self,cases,transport="api",deadline=.7):
        c=example_config();c.update({"from":"canary@sender.example","allowlist":["seed@receiver.example"],"cases":list(cases),
            "deadline_s":deadline,"late_window_s":.05,"poll_s":.025,"pair_gap_s":.005,"pace_s":.005,"timeout_s":2})
        c["mailboxes"]=[{"id":"fixture","provider":"local-fixture","address":"seed@receiver.example","host":"127.0.0.1",
            "port":self.servers[2].server_address[1],"tls":False,"user_env":"AMQ_FIXTURE_USER","password_env":"AMQ_FIXTURE_PASSWORD","folders":["INBOX","Spam"]}]
        api={"kind":"api","url":f"http://127.0.0.1:{self.servers[0].server_address[1]}/v1/messages","key_env":"AMQ_FIXTURE_KEY"}
        smtp={"kind":"smtp","host":"127.0.0.1","port":self.servers[1].server_address[1],"tls":"fixture-only"}
        c["routes"]={"A":copy.deepcopy(api if transport!="smtp" else smtp),"B":copy.deepcopy(api if transport=="api" else smtp)}
        return c

    def __exit__(self,*args):
        for s in self.servers:s.shutdown();s.server_close()
        for t in self.threads:t.join(timeout=3)


class WireChecks(unittest.TestCase):
    @contextlib.contextmanager
    def case(self,cases=("plain",),fault=None,transport="api"):
        env={name:os.environ.get(name) for name in ("AMQ_FIXTURE_USER","AMQ_FIXTURE_PASSWORD","AMQ_FIXTURE_KEY")}
        for name in env:os.environ[name]="local-fixture-only"
        try:
            with tempfile.TemporaryDirectory() as d,WireWorld(fault) as w:
                p=make_plan(w.config(cases,transport),fixture=True);digest=validate_plan(p)
                if transport=="api":prepare_run(p,d,digest)
                result=execute(p,d,digest,fixture_mode=True)
                yield w,p,Evidence(d),result
        finally:
            for name,value in env.items():
                if value is None:os.environ.pop(name,None)
                else:os.environ[name]=value

    def test_api_imap_all_six_cases_and_idempotency(self):
        with self.case(CASES) as (w,p,e,r):
            self.assertEqual(r["status"],"PANEL_CHECKS_PASSED",r)
            self.assertEqual(len(w.requests),14);self.assertEqual(len(w.messages),10)
            self.assertTrue(all(b["category"]=="transactional" for _,b in w.requests))
            self.assertTrue(all(cmd!="SELECT" for cmd,_ in w.commands))
            self.assertTrue(all("BODY.PEEK[]" in arg for cmd,arg in w.commands if cmd=="UID" and arg.startswith("FETCH")))
            self.assertEqual(r["origin"],"LOCAL_FIXTURE")
            self.assertEqual(e.verify(validate_plan(p)),r["terminal_chain_sha256"])

    def test_api_vs_smtp_actual_wire(self):
        with self.case(("plain","unicode","html","attachment"),transport="mixed") as (w,p,e,r):
            self.assertEqual(r["status"],"PANEL_CHECKS_PASSED",r);self.assertEqual(len(w.messages),8)

    def test_duplicate_visible_copies_fail(self):
        with self.case(fault="duplicate") as (_,_,_,r):
            self.assertEqual(r["status"],"OBSERVED_FAILURE");self.assertTrue(any("duplicate" in x for x in r["problems"]))

    def test_attachment_corruption_fails(self):
        with self.case(("attachment",),fault="corrupt_attachment") as (_,_,_,r):
            self.assertEqual(r["status"],"OBSERVED_FAILURE");self.assertTrue(any("MIME" in x for x in r["problems"]))

    def test_stripped_html_fails(self):
        with self.case(("html",),fault="strip_html") as (_,_,_,r):self.assertEqual(r["status"],"OBSERVED_FAILURE")

    def test_lost_smtp_final_ack_is_incomplete_even_if_received(self):
        with self.case(fault="smtp_lost_ack",transport="smtp") as (w,p,e,r):
            self.assertEqual(len(w.messages),2)
            self.assertTrue(all(x["observed"] for x in r["outcomes"].values()))
            self.assertEqual(r["status"],"INCOMPLETE")

    def test_missing_folder_cannot_pass(self):
        with self.case(fault="missing_folder") as (_,_,_,r):self.assertEqual(r["status"],"INCOMPLETE")

    def test_success_without_api_message_id_is_incomplete(self):
        with self.case(fault="api_no_id") as (_,_,_,r):self.assertEqual(r["status"],"INCOMPLETE")

    def test_wrong_negative_error_cannot_pass(self):
        with self.case(("reserved_header",),fault="reserved_unauthorized") as (_,_,_,r):self.assertEqual(r["status"],"OBSERVED_FAILURE")

    def test_spam_is_receipt_with_spam_placement(self):
        with self.case(fault="deliver_spam") as (_,_,_,r):
            self.assertEqual(r["status"],"PANEL_CHECKS_PASSED",r)
            self.assertTrue(all(x["folders"]==["Spam"] for x in r["outcomes"].values()))

    def test_forged_authentication_results_never_becomes_verified(self):
        with self.case(fault="forged_auth") as (_,_,e,r):
            self.assertEqual(r["status"],"PANEL_CHECKS_PASSED",r)
            self.assertTrue(all(x["authentication"]=="NOT_INDEPENDENTLY_VERIFIED" for x in r["outcomes"].values()))
            self.assertTrue(any("attacker.invalid" in str(x["data"]) for x in e.rows() if x["kind"]=="observation"))

    def test_uidvalidity_rotation_marks_incomplete(self):
        with self.case() as (w,p,e,r):
            w.epoch+=1;poll_mailbox(p,p["config"]["mailboxes"][0],e,True)
            self.assertEqual(analyze(p,e,validate_plan(p))["status"],"INCOMPLETE")

    def test_reexecute_never_resends(self):
        with self.case() as (w,p,e,r):
            before=len(w.requests)
            self.assertRaises(FileExistsError,execute,p,e.root,validate_plan(p),True)
            self.assertEqual(len(w.requests),before)

    def test_independent_audit_sample_is_anchored_without_replacement(self):
        with self.case() as (_,p,e,r):
            sample=audit_sample(p,e,validate_plan(p),r["terminal_chain_sha256"],2)
            self.assertEqual(len({x["seq"] for x in sample["selected"]}),2)
            self.assertRaises(ValueError,audit_sample,p,e,validate_plan(p),"0"*64,1)

    def test_missing_mail_stays_in_denominator(self):
        with self.case(fault="drop_message") as (_,_,_,r):
            self.assertEqual(r["status"],"OBSERVED_FAILURE")
            self.assertEqual(len(r["outcomes"]),2)
            self.assertTrue(all(not x["observed"] for x in r["outcomes"].values()))

    def test_webhook_raw_http_retry_tamper_and_wrong_tenant(self):
        with tempfile.TemporaryDirectory() as d:
            p=make_plan(example_config());e=Evidence(d);e.append("plan",{"plan_sha":validate_plan(p)})
            secret="fixture-only-secret";server=http.server.ThreadingHTTPServer(("127.0.0.1",0),webhook_handler(e,p,secret,1,"t1"))
            thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.02),daemon=True);thread.start()
            def post(raw,signature=None):
                ts=str(int(time.time()*1000));sig=signature or "sha256="+hmac.new(secret.encode(),ts.encode()+b"."+raw,hashlib.sha256).hexdigest()
                req=urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/",data=raw,headers={"X-ApexMail-Timestamp":ts,"X-ApexMail-Signature":sig})
                try:
                    with urllib.request.urlopen(req,timeout=2) as response:return response.status
                except urllib.error.HTTPError as error:return error.code
            try:
                payload={"id":"evt_fixture","type":"message.accepted","tenantId":"t1","data":{"metadata":{"validation_run_id":p["run_id"],"validation_probe_id":p["probes"][0]["id"]}}}
                raw=canonical(payload)
                self.assertEqual(post(raw),503);self.assertEqual(post(raw),204)
                self.assertEqual(post(raw,"sha256="+"0"*64),401)
                payload["tenantId"]="other-tenant";self.assertEqual(post(canonical(payload)),202)
                callbacks=[r["data"] for r in e.rows() if r["kind"]=="webhook"]
                self.assertEqual([r["response_status"] for r in callbacks],[503,204]);self.assertEqual(len({r["raw_sha"] for r in callbacks}),1)
                e.verify(validate_plan(p))
            finally:server.shutdown();server.server_close();thread.join(timeout=3)


class Checks(unittest.TestCase):
    def test_allowlist_refuses_extra_recipient(self):
        c=example_config();c["allowlist"]=[]
        self.assertRaises(ValueError,make_plan,c)

    def test_header_injection_address_refused(self):
        for a in ["x@example.com\r\nBcc: y@example.com","A <x@example.com>","x@example.com,y@example.com"]:
            self.assertRaises(ValueError,address,a)

    def test_two_arm_pair_balance_and_frozen_coins(self):
        p=make_plan(example_config());validate_plan(p)
        self.assertEqual(len(p["probes"]),12)
        q=copy.deepcopy(p);q["probes"][0]["route"]=q["probes"][1]["route"]
        self.assertRaises(ValueError,validate_plan,q)

    def test_plan_anchor_rejects_changed_cases(self):
        p=make_plan(example_config());d=validate_plan(p);p["probes"][0]["nonce"]="changed"
        self.assertRaises(ValueError,validate_plan,p,d)

    def test_smtp_does_not_inherit_api_idempotency(self):
        c=example_config();c["routes"]["B"]={"kind":"smtp","host":"smtp.example.com","port":587,"tls":"starttls","user_env":"U","password_env":"P"}
        p=make_plan(c)
        self.assertFalse(any(x["case"] in ("reserved_header","idempotency") for x in p["probes"]))

    def test_evidence_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            e=Evidence(d);e.append("plan",{"plan_sha":"abc"});e.append("test",{"n":1});e.verify("abc")
            with e.connect() as con:con.execute("UPDATE log SET data='{}' WHERE seq=2")
            self.assertRaises(ValueError,e.verify,"abc")

    def test_raw_corruption_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            e=Evidence(d);e.append("plan",{"plan_sha":"a"});path,digest=e.raw(b"good",".eml");e.append("observation",{"raw_path":path,"raw_sha":digest})
            (Path(d)/path).write_bytes(b"bad")
            self.assertRaises(ValueError,e.verify,"a")

    def test_no_implicit_repeat_after_interruption(self):
        with tempfile.TemporaryDirectory() as d:
            p=make_plan(example_config());e=Evidence(d);x=p["probes"][0];e.append("attempt_start",{"probe":x["id"]})
            self.assertRaises(ValueError,send_probe,p,x,e)

    def test_reserved_header_only_in_negative_case(self):
        p=make_plan(example_config())
        for x in p["probes"]:
            b=fixture(p,x);self.assertEqual(b["category"],"transactional")
            self.assertEqual("X-ApexMail-Route" in b["headers"],x["case"]=="reserved_header")

    def test_mime_attachment_exact_bytes(self):
        p=make_plan(example_config());x=next(q for q in p["probes"] if q["case"]=="attachment");b=fixture(p,x)
        m=EmailMessage();m["Subject"]=b["subject"];m["From"]=b["from"];m["To"]=b["to"][0];m.set_content(b["text"]);item=b["attachments"][0]
        m.add_attachment(base64.b64decode(item["content"]),maintype="application",subtype="json",filename=item["filename"])
        self.assertTrue(check_mime(p,x,m.as_bytes())[0])
        next(m.iter_attachments()).set_payload(base64.b64encode(b"corrupt").decode())
        self.assertFalse(check_mime(p,x,m.as_bytes())[0])

    def test_known_binomial_sign_tail(self):
        self.assertAlmostEqual(binomial_half_tail(0,10),1/1024,places=14)
        self.assertAlmostEqual(paired_summary([1]*10,.05)["sharp_null_p_raw"],2/1024,places=14)
        self.assertEqual(paired_summary([0]*10,.05)["sharp_null_p_raw"],1)

    def test_binomial_numerics_against_exact_integer_arithmetic(self):
        for n in range(101):
            total=0
            for k in range(n+1):
                total+=math.comb(n,k)
                self.assertAlmostEqual(binomial_half_tail(k,n),total/(2**n),places=11)

    def test_exact_randomization_type_one_error_exhaustive(self):
        for n in range(17):
            rejected=0
            for k in range(n+1):
                pval=min(1,2*binomial_half_tail(min(k,n-k),n))
                if pval<=.05:rejected+=math.comb(n,k)
            self.assertLessEqual(rejected/(2**n),.05)

    def test_tiny_panel_has_wide_difference_interval(self):
        self.assertEqual(paired_summary([0]*8,.05)["difference_interval"],[-1,1])

    def test_webhook_ms_exact_bytes_and_replay_window(self):
        raw=b'{"id":"evt_a"}';ts="1793200000000";secret="unit-secret"
        sig="sha256="+hmac.new(secret.encode(),ts.encode()+b"."+raw,hashlib.sha256).hexdigest()
        self.assertTrue(webhook_valid(raw,sig,ts,secret,int(ts)))
        self.assertFalse(webhook_valid(raw+b" ",sig,ts,secret,int(ts)))
        self.assertFalse(webhook_valid(raw,sig,ts,secret,int(ts)+300001))
        self.assertFalse(webhook_valid(raw,sig,"1793200000",secret,int(ts)))

    def test_live_plaintext_transports_refused(self):
        c=example_config();c["routes"]["A"]["url"]="http://127.0.0.1:1234/v1/messages"
        self.assertRaises(ValueError,validate_config,c)

    def test_webhook_requires_exact_tenant_and_probe_correlation(self):
        p=make_plan(example_config());probe=p["probes"][0]["id"]
        good={"tenantId":"t1","data":{"metadata":{"validation_run_id":p["run_id"],"validation_probe_id":probe}}}
        self.assertTrue(webhook_correlates(good,p,[],"t1"))
        self.assertFalse(webhook_correlates(good,p,[],"t2"))
        good["data"]["metadata"]["validation_probe_id"]="nonexistent"
        self.assertFalse(webhook_correlates(good,p,[],"t1"))


if __name__=="__main__":
    main()
