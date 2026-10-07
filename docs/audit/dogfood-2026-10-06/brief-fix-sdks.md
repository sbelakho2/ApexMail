# FIX FLEET — SDKs vs the live API (whole slice)

You are a FIX agent. The four SDKs must actually match the server's real contract. Work in
/Users/sabelakhoua/IdeaProjects/ApexMail.

## Slice
`packages/sdk-php/**`, `packages/sdk-python/**`, `packages/sdk-java/**`, `packages/sdk-ruby/**`.

## Bar
- Every documented SDK method maps to a route the api-server MOUNTS, with the same auth mechanism
  (API key / bearer), the same request shape and the same error contract. Grep the api-server
  routers for each path the SDK calls; a method pointing at a nonexistent or differently-shaped
  route is a defect.
- Pagination, idempotency keys, retries/backoff, webhook signature verification and error typing
  must match `docs/api/**` and the server's real behaviour.
- Adversarially: a SDK that silently swallows a non-2xx, that builds a URL from unescaped input, or
  that verifies a webhook signature with a non-constant-time comparison is a defect.

## Deliverable
Findings -> docs/audit/dogfood-2026-10-06/fix-sdks.md. Fixes in place; prove each fix with the
SDK's own test (phpunit / pytest / maven test / rake test) or a runnable script exercising the LIVE
stack at 127.0.0.1:8080 (Host app.apexmail.ee) where the language toolchain is available; if a
toolchain is missing, say exactly which and verify by code inspection + a curl-equivalent of the
call. Own `packages/sdk-*/**` only. Report FIXED (evidence) / NOT FIXED (exact blocker) per item.
