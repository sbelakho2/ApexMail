# outbound-queue

> **Retired — do not deploy or invoke for delivery.**

This archived source remains in the repository only for source-history and
migration reference. Its global DKIM signer cannot enforce the current per-domain
encrypted-key, sender-authorization, and transport-readiness contract.

## Replacement

Use `worker-processors` as the only outbound delivery worker. API and SMTP
submission enqueue authenticated messages directly into `email_queue`; the
worker validates the current domain row immediately before sending.

## Do not use

The former gRPC service, `send-email` CLI, Docker target, Compose service, and
Cargo package are retired. Do not restore it as a dependency or deploy it.
