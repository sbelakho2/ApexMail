# mta

ApexMail MTA — inbound SMTP, bounce processing, feedback loops, and email authentication.

## Overview

The `mta` crate is the Mail Transfer Agent at the heart of ApexMail. It handles inbound SMTP reception, bounce classification and processing, feedback-loop (FBL) ingestion, and email authentication via SPF, DKIM, and DMARC. It orchestrates message flow from acceptance through to delivery or rejection.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
mta = { path = "../mta" }
```

## Development

```sh
cargo test -p mta
cargo clippy -p mta
```

## SMTP policy decisions

### Listeners and AUTH

| Port | Listener | AUTH |
|------|----------|------|
| 25 | Inbound (plain + STARTTLS) | **Off by default** (`SMTP_ADVERTISE_AUTH_PORT25=false`). Neither advertised in EHLO nor accepted — `AUTH` gets `502 5.5.1` pointing at 587/465. Port 25 faces the whole internet; AUTH there is a pure brute-force surface. |
| 465 | Inbound (implicit TLS) | Always on. This is a submission port; clients that auto-detect 465 wait for the `AUTH` capability. |
| 587 | Submission (STARTTLS) | Always on, but only advertised/accepted once the session is on TLS. |

Clients submitting real mail must use **587 (STARTTLS)** or **465 (implicit TLS)**.

Failed-AUTH lockout counters (per-IP + per-account, 5-minute window) are
mirrored into Redis (`mta:authfail:*` with TTL), so a lockout survives an
MTA restart and applies across replicas sharing the Redis. When Redis is
unreachable the in-process cache keeps protecting the local replica.

### ESMTP extension advertisement vs enforcement

- **8BITMIME (RFC 6152)** — advertised and honoured: DATA lines are read,
  stored, and relayed as raw bytes; octets outside US-ASCII are never
  mangled through a lossy UTF-8 decode.
- **SMTPUTF8 (RFC 6531)** — advertised and honoured: the envelope address
  validator is charset-agnostic, so UTF-8 mailbox names are accepted
  end-to-end (`MAIL FROM ... SMTPUTF8` parameter included).
- **SIZE (RFC 1870)** — the advertised value equals the enforced byte cap
  (over-cap DATA is refused with `552 5.3.4`); a `MAIL FROM ... SIZE=n`
  declaration above the advertisement is refused immediately with `552`
  before any body is transferred.
- ESMTP parameters for extensions that were **not** advertised (or are
  unknown, e.g. DSN's `NOTIFY=`) are refused with `555 5.5.4` per RFC 5321
  §4.1.1.11 rather than silently ignored.
- The bounce and FBL endpoints advertise SIZE with exactly the cap they
  enforce (`max_message_size` / `max_arf_size`); over-cap DATA gets
  `552 5.3.4`. Recipients are capped at 100 per transaction (`452 4.5.3`),
  and envelope addresses at 320 octets (`501 5.1.3`, RFC 5321 §4.5.3.1.1).

### Reply discipline

Every 4xx/5xx reply from all four servers carries an accurate RFC 3463
enhanced status code (`501` = syntax, `503` = sequencing, `502` = not
implemented, `550` = policy/mailbox refusal, `552 5.3.4` = SIZE, `421 4.4.2`
= timeout) and is emitted through the shared `write_reply`/`log_smtp_reject`
path, so no reject is silent:

- `mta.smtp.reject{server,code}` — one structured log line + counter per
  rejection (reason + IP-only peer + session id).
- `mta.smtp.session{server}` — one summary line per connection (TLS, auth,
  message count, duration, close reason).
- `mta.auth.failure` / `mta.auth.lockout` / `mta.tls.handshake{result}`.

### Line discipline and smuggling defence

- End-of-DATA is strictly `<CRLF>.<CRLF>` (a bare-LF `.` line is body data).
- Over-long lines are **fully drained through their terminating newline**
  before the session continues, so the tail of an oversized line can never
  be interpreted as fresh commands. If no newline arrives within the
  absolute drain budget (64 MiB), the connection is closed — replying and
  reading on would parse attacker bytes as commands.
- Stored body lines are CRLF-normalized and dot-unstuffed (exactly one
  leading dot removed, RFC 5321 §4.5.2).

