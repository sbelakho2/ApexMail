# Chained challenges (stage 1 / stage 2)

Chained challenges make a **stronger proof stage non-skippable**: when the
post-solve policy decides `CHAIN_REQUIRED` for a transaction, the client
must solve a second, stronger challenge — the chain — before the
application accepts the protected action. A client cannot restart the
transaction at stage 1 by discarding its ticket: the chain is a
server-side transaction obligation.

## Transaction bindings and the authority

Non-skippable chaining requires a server-authoritative per-transaction
binding resolved by the application through the
`RequestBindingAuthorityInterface`: the binding signed into the challenge
comes from the authority, never from the client. A raw client-supplied
hidden form field alone is NOT a security-bound transaction identity — it
proves nothing about a trusted backend decision. When the authority is
configured, the controller never signs an untrusted client string: a
client-supplied value is resolved against the authority's server-held
transaction state, and only the resolved authoritative binding is signed.
An open stage-2 obligation is stored server-side against the authoritative
transaction binding. A challenge request for that transaction cannot
restart at stage 1 by omitting or discarding the client ticket.

Configuration (see [configuration.md](configuration.md) for the full
`risk.chaining` block):

- `risk.request_binding_authority` — the service id of the application's
  `RequestBindingAuthorityInterface` implementation (required at compile
  time when chaining is enabled).
- `risk.chaining.reservation_lease_secs` — the server-side reservation
  lease for a chained transaction (default 15 s).
- Chaining is OFF by default; enabling it requires the risk engine enabled
  and the binding authority configured.

## The obligation and the ticket

A chain opened by a `CHAIN_REQUIRED` stage-1 verification leaves a
server-side **obligation** — `{kiwi:<ns>}:chain-obligation:<obligationId>`
→ chainId, same TTL — anchored on a bounded pseudonymous obligation id
(`hmac("chain-obligation\0{policyVersion}\0{scope}\0{binding}",
chainSecret)`; the raw binding is never a Redis key). The obligation id
participates in the policy version, so an old-policy chain never blocks a
new-policy flow.

The client-carrying half is the **chain ticket**: `base64url([1, chainId,
expiresAt]) "." base64url(hmac_sha256(body, secret, true))`. It is MINIMAL
by design — version, the random chain id, the signed expiry, the raw 32-byte
MAC — so it stays ~60 bytes no matter how long the legitimate
request_binding is. EVERYTHING else (stage1Nonce, scope, requestBinding,
requiredAction, requiredRank, policyVersion, chainDepth, state) is
SERVER-HELD in the state record, so a client can never alter it, never
extend its own validity (the expiry is signed), never downgrade the
promised stage (the required action is enforced at stage-2 issuance), and
never detach the chain from its transaction (a ticket whose obligation
cannot match the current transaction is refused).

## Stage 1 → stage 2 flow

1. **Stage 1.** The client solves the ordinary challenge. When the
   post-solve assessment answers `CHAIN_REQUIRED` (or an open obligation
   requires a higher rank than the stage-1 proof satisfied), the valid
   solve issues exactly one chain ticket and creates/raises the
   obligation — `kiwi.post_solve_chain_required` fails the form and the
   application presents the stage-2 widget with the ticket
   (`data-kiwi-chain-ticket`; presented once, then cleared).
2. **Stage 2.** A challenge request carrying the ticket mints the stronger
   challenge (the required rank can only ever RAISE; the stage-2 TTL is
   clipped to the chain's remaining lifetime, with the configured
   minimum-duration floor respected). `markIssued` transitions the chain
   to `issued(stage2Nonce)`; a retry RECOVERS the exact same issued
   challenge instead of re-minting.
3. **Terminal transitions.** Only successful verification of that exact
   stage-2 nonce ends the chain. The stage-2 solve's final disposition
   decides the terminal state:
   - `PASS` → `verified(nonce)` — TERMINAL, and the obligation mapping is
     deleted atomically (only if it still points at this chainId);
   - `STEP_UP` → `step_up_required(nonce)` — TERMINAL, obligation KEPT;
   - `DENY` → `denied(nonce)` — TERMINAL, obligation KEPT.

   Terminal `step_up_required`/`denied` states keep the obligation bound —
   a later challenge request for the same transaction re-encounters the
   terminal state and can never restart at stage 1. A fresh
   `Deny`/`StepUp` assessment against a DIFFERENT verified nonce of the
   obligated transaction terminalizes the open obligation the same way
   (nonce-agnostic `markTransactionDenied` / `markTransactionStepUpRequired`).

## Failure semantics

- A consumed-valid stage-2 with a committed `PASS` disposition VERIFIES
  the chain; consumed-valid with `STEP_UP`/`DENY` transitions to the
  terminal states. A consumed stage-2 WITHOUT a committed result is
  `temporary_unavailable` — never a rearm.
- An expired or invalid stage-2 REARMS the chain for a FRESH stage-2 mint
  at the same-or-stronger floor — NEVER a stage 1.
- An expired stage-2 challenge with a still-valid chain is REARMED, never
  downgraded; an expired chain ticket is refused (`temporary_unavailable`).
- The reservation lease is short (default 15 s, bounded by the chain
  record's own remaining TTL): a crashed owner blocks retries for seconds,
  not minutes. Release by a NON-owner is an atomic no-op; a rate-limited
  stage-2 request leaves the ticket reusable.
- Chain-state read failures are `temporary_unavailable` in both the
  stage-1 and stage-2 paths — never a guessed pass. A chain record
  without an expiry is corrupted state and fails closed.

The disposition store that drives the terminal decisions is documented in
[security-hardening.md](security-hardening.md#deterministic-final-disposition);
the risk decisions that answer `CHAIN_REQUIRED` are in
[risk-engine.md](risk-engine.md).

## Related

- [configuration.md](configuration.md) — `risk.chaining` configuration and
  the binding-authority wiring.
- [security-hardening.md](security-hardening.md) — deterministic final
  disposition and the post-solve disposition store.
- [risk-engine.md](risk-engine.md) — post-solve assessment and step-up
  semantics.
- [troubleshooting.md](troubleshooting.md) — the `temporary_unavailable`
  and `kiwi.post_solve_chain_required` codes.
