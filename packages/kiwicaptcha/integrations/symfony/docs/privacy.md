# Privacy

This is the single authoritative privacy document for the Symfony bundle:
what data is stored, in what form, for how long, and what the privacy
configuration keys mean. The verifiable claims made here are listed with
their evidence in [claims-registry.md](claims-registry.md).

## Privacy guarantees

**No third-party tracking or runtime services. Privacy Strict collects no
behavioral, device, hardware, or screen telemetry. Raw IP addresses are not
persisted; short-lived keyed pseudonyms are used only where required for
abuse prevention.**

Concretely, KiwiCaptcha stores no raw IP and no stable IP-derived
identifier. The challenge record holds a nonce-bound binding tag (unique
per challenge). The rate limiter keys are peppered HMACs of the IP,
rotated per epoch (`rate_limit_rotation_secs`, default 3600). The same IP
therefore yields a different keyed pseudonym in every epoch, and Redis
snapshots cannot correlate one source across time periods. Linkability
within one epoch is unavoidable for rate limiting.

The optional adaptive risk engine, off by default, follows the same rule.
Its Redis state is keyed by 128-bit keyed pseudonyms of the source
(rotating every epoch) and subnet. It is also keyed by a keyed pseudonym
of the first-party continuity cookie's random nonce, never raw IPs, never
stable identifiers. Enabling risk adds one HttpOnly first-party cookie
carrying a fresh random nonce (see below).

## Privacy modes

`privacy_mode` (default **strict**) is the privacy contract:

- **strict**: the extension forces the privacy-sensitive options
  regardless of what the operator wrote in the config file.
  `telemetry: off` means the widget never collects signal fields.
  `same_origin_only: true` means cross-origin challenge requests are
  rejected. `min_duration_ms: 0` means there is no server-side
  solve-timing floor; the timing heuristic is off. Rate limits default to
  nonzero (10 per client / 500 global per window) so abuse mitigation
  stays on.

- **standard**: the operator's explicit values for those keys are honored
  (`telemetry: minimal|full`, `same_origin_only: false`, a positive
  `min_duration_ms`).

`binding_mode` is NOT forced under strict: IP binding is a relay mitigation,
and the stored tag is a per-challenge, nonce-bound HMAC — never a stable
identifier that follows the client.

The config keys themselves (with validation) are in
[configuration.md](configuration.md#privacy-posture).

## Continuity cookie

The risk-v1 "session" signal links observations from the same browser
across requests, so repeated failed solves are attributable to one source.
The link material is a **random 16-byte nonce** (hex) in a first-party,
HttpOnly, SameSite=Lax cookie (`kiwi_risk_session` by default) — no
IP-derived or device-derived identity, no PII; the engine only ever stores
the keyed pseudonym of the value. Browsers that reject cookies simply fall
back to a session-less identity (availability is never coupled to cookie
acceptance).

## Telemetry

Behavioral telemetry is **off by default**: the default widget mode is
`telemetry: off`, and `privacy_mode: strict` forces it regardless of
operator config. The widget collects signal fields only in the mode the
page opts into via the `telemetry` option / `data-kiwi-telemetry`
attribute:

- `minimal` — aggregate widget interaction counts only (`me`/`ke`);
- `full` — adds `navigator.webdriver` and at most 20 coarse 250 ms timing
  samples (`wd`/`et`).

Telemetry is a supplementary signal: it is client-controlled and
forgeable, so it is never treated as the security boundary; see
[SECURITY.md](../../../../../SECURITY.md#what-kiwicaptcha-explicitly-does-not-protect-against).
`enforce_telemetry` (reject bot-scored telemetry at verification time) is
defense-in-depth only. The enforcement key is documented in
[configuration.md](configuration.md#privacy-posture).

## Coarse client context (risk-v2)

The widget collects **no device-capability or screen-size signals** unless
the operator enables `risk.client_context` AND the app renders the opt-in
attribute on the widget container (`data-kiwi-risk-context="coarse"`).
Without the attribute the widget never sends the field. The tag is deliberately coarse: viewport class, pointer class, language
family, timezone class. It carries no canvas/audio/font-list/GPU signals
and no stable identifiers; a missing capability contributes nothing.

`privacy_mode: strict` refuses the opt-in entirely: `risk.client_context:
true` fails at container compile time, and the runtime never renders the
attribute under strict — a per-render `risk_client_context` override is
ignored there too. So strict deployments keep collecting no
device-capability or screen-size signal under every configuration.

## Logs and metrics never carry identity

Decisions are logged through the app's `logger` (info for decisions,
warning for denials) with scope/action/score/reasons only. The log never
carries an IP or cookie value, never a decision id or nonce. Metric keys
are bounded (algorithm/result/reason/profile tuples, no
challenge_id/ip/user_agent labels), so log/metrics cardinality can never be
driven by identity material. `metricsSnapshot()` returns aggregate decision
counters, global level, store latency, without identity labels.

## Claims

The "no third-party requests", "behavioral telemetry off by default", "no
device-capability or screen-size signals unless opted in", and "no
canvas/audio/font/GPU fingerprints" claims — with their exact scopes,
assumptions and the tests that evidence them — live in
[claims-registry.md](claims-registry.md).

## Related links

- [claims-registry.md](claims-registry.md): the verifiable privacy claims.
- [configuration.md](configuration.md#privacy-posture): the privacy
  configuration keys.
- [SECURITY.md](../../../../../SECURITY.md): the security document; privacy and
  security overlap only where noted.
