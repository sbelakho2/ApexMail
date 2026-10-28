# Interactive-Client Lifecycle v1

Shared cross-language contract for the KiwiCaptcha interactive client
lifecycle: how a native widget (Android, iOS, desktop, headless SDKs)
races a challenge's time-to-live against its solve, honours the
challenge's minimum duration, and stays cancellable while it burns CPU.

The reference implementation is the Android package
(`packages/kiwicaptcha-android`): `KiwiLifecycle` (the pure decision
helper), `KiwiSolver` (the cooperative cancellation checkpoints),
`KiwiCaptchaView` (the widget wiring). Every other client binding MUST
reproduce the same semantics and MUST pass the shared vectors in
[lifecycle-vectors.json](lifecycle-vectors.json).

## Definitions

- `receivedAtMs`: the wall-clock millisecond captured immediately
  after the challenge JSON parses. The expiry clock starts at parse
  time, never after solving.
- `expiresAtMs`: `receivedAtMs + ttlSecs * 1000 - 1000`. The fixed
  1 s safety margin keeps the client from racing the server's own
  expiry verdict down to the wire. A challenge with `ttlSecs == 0` has
  **no expiry** at all (no timer, no expired state).
- `minSubmitAtMs`: `receivedAtMs + minDurationMs`; `0` semantics
  when the field is absent (it then equals `receivedAtMs` and never
  gates). Challenges use it to bound how fast a token may come back.
- **generation**: a monotonically increasing handle minted per
  `start()`-style run. Only the newest generation may emit: results,
  errors and timers from superseded generations are discarded.

## Normative lifecycle

1. Fetch the challenge. Mint the generation before the fetch; discard
   everything if a newer generation started while the fetch was in
   flight.
2. Parse. Capture **receivedAtMs** immediately after the JSON parses.
3. Compute `expiresAtMs` and `minSubmitAtMs` from `receivedAtMs`.
4. Start the expiry timer at parse time. The timer racing the solve is
   correct and intended — the previous behaviour (arming the timer only
   after `onVerify`) let a slow solve deliver a token the server had
   already expired.
5. Run the solve with a cooperative cancellation probe (below). The
   probe is cancelled when the job/task is cancelled, a newer
   generation started, or `now >= expiresAtMs`.
6. Solve finishes. If `solveFinishedAtMs >= expiresAtMs`, the
   generation is invalidated: the token is never delivered, `onVerify`
   is suppressed, and the widget surfaces the typed expired state.
7. Delivery gating: if the solve finished before `minSubmitAtMs`,
   delay delivery (cancellably) until `minSubmitAtMs`. If
   `minSubmitAtMs >= expiresAtMs`, treat the generation as expired.
8. Never deliver a token after `expiresAtMs`: at each checkpoint and
   immediately before `onVerify`, if `now >= expiresAtMs` the
   generation is invalidated, `onVerify` is suppressed, and the widget
   surfaces the typed expired state.
9. Only the newest generation may emit. Results from superseded
   generations are discarded without surfacing state or callbacks.

## Solver-level cooperative cancellation

`solve()` accepts an `isCancelled` probe (a zero-argument predicate, or
a cancellation token) checked at bounded intervals. The probe must be
cheap and non-blocking. When the probe fires, the solver raises the
typed cancelled error and **schedules no further CPU work** — the
checkpoint runs before the next batch of work, never after it. The
solver also checks the probe once on entry, before any work is spent.

Bounded cancellation latency per workload:

| Workload | Checkpoint cadence              | Stale-work ceiling after a firing probe |
|----------|---------------------------------|-----------------------------------------|
| sha256   | every 2048 candidates           | 2048 hashes                              |
| argon2id | between candidate derivations   | one derivation                           |
| rsw      | every 256 modular squarings     | 256 squarings                            |
| fetch / parse | not probed; cancellation is cooperative at the coroutine/task level | one in-flight request |

The cancelled outcome is a typed error, not a silent empty result
and not a generic failure. Android spells it `KiwiSolveError.Cancelled`.
The widget uses it to distinguish "stop because the expiry race was
lost or a newer generation started" from "the solve failed".

## The pure decision helper

Every client implements and tests the pure decision function:

```
deliveryDecision(receivedAtMs, ttlSecs, minDurationMs,
                 solveFinishedAtMs, nowMs)
  -> { deliver: Boolean, deliverAtMs: Long, reason: String }
```

with reasons `"deliver" | "defer" | "expired"`. Clients that surface
cancellation through the same helper accept one additional input,
`cancelled: Boolean = false`, which short-circuits to
`{deliver: false, deliverAtMs: 0, reason: "cancelled"}`.

Evaluation order (deterministic; first match wins):

1. `cancelled` → `{false, 0, "cancelled"}`.
2. If `ttlSecs > 0`:
   a. `minSubmitAtMs >= expiresAtMs` → `{false, 0, "expired"}`.
   b. `solveFinishedAtMs >= expiresAtMs` → `{false, 0, "expired"}`.
   c. `nowMs >= expiresAtMs` → `{false, 0, "expired"}`.
3. `deliverAtMs = max(solveFinishedAtMs, minSubmitAtMs)`.
   - `nowMs >= deliverAtMs` → `{true, nowMs, "deliver"}`.
   - otherwise → `{false, deliverAtMs, "defer"}`.

Boundary semantics, pinned by the vectors: `now == expiresAtMs` is
**expired** (the gate is `>=`), and `now == minSubmitAtMs` **delivers**
(delivery is due from `minSubmitAtMs` onward). `ttlSecs == 0` is
treated as no expiry: the decision is made on min-duration alone.
`deliverAtMs` conventions: `"deliver"` reports `nowMs` (the delivery
instant), `"defer"` reports the scheduled future instant, `"expired"`
and `"cancelled"` report `0` (never delivered).

Vectors assume `nowMs >= receivedAtMs`; `solveFinishedAtMs` may lie in
the future relative to `nowMs` (a checkpoint taken while the solve is
still running), which then defers to `solveFinishedAtMs`.

## Shared vectors

[lifecycle-vectors.json](lifecycle-vectors.json) is an array of
deterministic scenarios with concrete integer times. Schema:

```json
{
  "name": "...",
  "receivedAtMs": 0, "ttlSecs": 0, "minDurationMs": 0,
  "solveFinishedAtMs": 0, "nowMs": 0, "cancelled": false,
  "expect": { "deliver": false, "deliverAtMs": 0, "reason": "deliver|defer|expired|cancelled" }
}
```

The suite covers immediate delivery (min-duration 0), deferral to
`minSubmitAtMs` when the solve is faster than the floor, expiry during
the solve, and a solve finishing just before expiry. It also covers
`minSubmitAtMs >= expiresAtMs`, cancellation, the exact boundary cases
(`now == expiresAtMs` expired; `now == minSubmitAtMs` delivered), a
long TTL without a min-duration,
a `ttlSecs == 0` challenge (no expiry; min-duration only), and a
deferred delivery whose checkpoint lands after expiry. Client bindings
MUST test every vector; the Android binding runs them in
`KiwiLifecycleTest` against this file via a repo-relative path.

## Execution capability header

Native clients cannot execute the execution dimension of a challenge
(the browser interpreter). Because the *absence* of a capability header
means the v1 compatibility floor rather than "cannot execute", a native
interactive client MUST send the capability header explicitly on the
challenge POST:

```
Kiwi-Execution-Max-Version: 0
```

(Android: set by `KiwiClient.fetchChallenge`.) The server can then
route execution-armed challenges away from clients that declared they
cannot run them, instead of inferring capability from a missing header.
