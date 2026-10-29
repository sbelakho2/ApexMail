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
