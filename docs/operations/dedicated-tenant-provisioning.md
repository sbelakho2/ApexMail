# Dedicated Tenant Host Provisioning

> Control-plane route: `POST /ent/private-deployments/:id/provision`
> Code: `services/mail-server/crates/enterprise/src/dedicated_exec.rs`

## What this does

For a Dedicated Tenant deployment in the `validated` state, the control
plane creates the physical host at the provider (Hetzner Cloud). It records
the provider host id and addresses on the deployment row, then moves the
deployment `validated` to `provisioned` through the existing lifecycle
machine. The host-group name is the same deterministic scheme the deployment
bundle renders, so DNS, monitoring and the provider agree on one name.

## Operator flow

1. Set `DT_PROVISIONING_ENABLED=1` on the enterprise server. This is the
   hard gate: without it every execution request is refused with a 403 that
   carries this instruction.
2. Set `HETZNER_API_TOKEN` with server-creation permission. A missing token
   is a 409 that names the variable, and never a silent skip.
3. Call `POST /ent/private-deployments/:id/provision` with the
   `dedicated-tenants:write` scope (or admin). On success the response names
   the provider host id and the host addresses.
4. Run the existing transition and verification steps to reach `active`
   (`POST /deployments/:id/transition`). Activation still records the
   billing contract and still requires the validated-bundle artifact.

## Contract status (seventh external audit)

The executor implements the provider's documented create-server contract.
It sends the required `image` parameter, parses the singular `server` +
`action` response, and follows the asynchronous action lifecycle: park in
`provisioning`, poll the action, verify `running` plus a public IPv4
before `provisioned`. Access is SSH-key-only, so no root password is ever
generated or persisted. The wire shapes are pinned by committed fixtures
(`services/mail-server/crates/enterprise/tests/fixtures/hetzner_contract.json`);
if the provider's schema changes, that file changes first.

Not yet exercised against the live provider. The capacity SKU, image and
SSH-key names are the operator's explicit configuration
(`DT_HETZNER_SERVER_TYPE`, `DT_HETZNER_IMAGE`, `DT_HETZNER_SSH_KEYS`):
there is deliberately no default SKU, and execution refuses until they are
set. The first live provisioning run is an operator-gated validation step;
until it passes, treat one-command provisioning as code-complete, not
operationally proven.

## Honesty boundary

The route runs a real provider call, and nothing else. The gate is
required, and no execution happens automatically. The bundle validation
stays authoritative: the lifecycle transition `validated -> provisioned`
still runs through `transition_dedicated` with all its authorize gates. A
row without the recorded bundle artifact keeps its host (the provider
resource exists and is recorded), and the transition is refused with a typed
error. Re-run bundle validation, then re-run the transition.

## Failure and resume

A provider refusal (non-2xx) records its tail in `provision_error` on the
deployment row, which stays `validated`. Resolve the cause and call the
route again. Re-execution is idempotent: a deployment that already carries a
provider host returns an `already_exists` outcome and makes no second
create call.
