/**
 * SDK version constant.
 *
 * Must equal the `version` field of package.json, the User-Agent literal in
 * client.ts, and the head entry of CHANGELOG.md. `packages/check_versions.py`
 * enforces the invariant mechanically in CI — the same gate every other
 * first-party SDK is under (audit SM15 F4).
 */
export const SDK_VERSION = "1.0.1";
