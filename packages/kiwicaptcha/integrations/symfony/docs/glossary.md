# Glossary

One term per entry, one line each. The definitions follow the actual code
semantics (the core packages and this bundle's source), not marketing
usage.

- **challenge** — the server-issued, HMAC-signed proof-of-work problem: a
  256-bit nonce, the algorithm (`sha256` | `argon2id`), the difficulty
  parameters, the scope, an optional nonce-bound binding tag, the policy
  epoch, and a TTL; the client solves it in the browser and returns the
  solution token.
- **solution token** — the client-submitted value carrying the challenge
  nonce, the solver counter, the client-reported duration, and the
  telemetry fields; verification decodes it, re-derives the proof, and
  consumes the challenge (a counter above the 5M-hash solver ceiling is
  rejected at decode time).
- **nonce** — the 256-bit random challenge identifier, the canonical jti of
  the consumed record; it keys the stored challenge, the consumed-state
  result, and the deterministic disposition.
- **request_binding** — the application transaction binding
  (`[A-Za-z0-9._:-]`, 1..128 chars) signed into a challenge by the server
  and enforced at verification: the final POST must present the SAME
  value, so a challenge minted for one transaction is never redeemable for
  another.
- **operation identity** — a caller-supplied token naming the logical
  operation redeeming a nonce (e.g. siteverify backend + idempotency key +
  response fingerprint), recorded atomically with the pending→consumed
  transition (`[A-Za-z0-9_-]`, 1..128 bytes), so the retained consumed
  record provably carries the ACTUAL atomic consume winner's identity.
- **obligation** — the server-side record that a transaction has an open
  chain: an hmac-derived pseudonymous obligation id
  (`chain-obligation\0{policyVersion}\0{scope}\0{binding}`) mapped to a
  chain id, created atomically with the chain and deleted only by a
  terminal verified state.
- **chain** — the two-stage (or stronger) challenge sequence anchored on an
  obligation: stage 1 opens it, stage 2 completes it; the client can never
  restart the transaction at stage 1 by discarding its ticket.
- **stage 1** — the first, weaker proof stage of a chained transaction; a
  valid stage-1 solve with an open obligation issues a chain ticket and
  raises the required rank instead of passing.
- **stage 2** — the stronger proof stage minted from a chain ticket; only
  successful verification of the exact stage-2 nonce transitions the chain
  to the terminal verified state (step_up_required/denied are terminal
  too, and keep the obligation bound).
- **disposition** — the final application-level result of a verified proof
  (`PASS` | `DENY` | `STEP_UP` | `CHAIN_REQUIRED`), persisted per nonce by
  the `PostSolveDispositionStore` so a replayed valid proof reproduces the
  same result and a denial can never replay into a pass.
- **decision** — the risk engine's assessment output: a score, a risk
  action, the reasons, the policy epoch and the global level, plus an
  internal 16-byte decision id used to settle confirmations and the
  outcome ledger.
- **policy epoch** — `risk.policy_version`, the challenge security-policy
  epoch signed into every issued record and enforced at verification;
  bumping it immediately invalidates all outstanding challenges (the
  emergency-revocation knob).
- **risk action** — the ordered risk-engine response
  (`allow < sha16 < sha18 < sha20 < argon16 < argon32 < argon64 < step_up <
  deny`) that maps a decision to a challenge profile; escalation stays
  within the deployment's algorithm family and never raises the server
  verification memory envelope.
- **consumed result** — the deterministic verification outcome
  (`consumed_result`) committed to the consumed record by the verifier; a
  re-verification of the record returns it as-is instead of re-deriving,
  and a consumed record without one is `ConsumeIndeterminate`.
