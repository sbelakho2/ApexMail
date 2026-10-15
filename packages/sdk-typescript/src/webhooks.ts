/**
 * Webhook signature verification for inbound ApexMail deliveries.
 *
 * Platform wire format (worker-processors/src/webhook/processor.rs,
 * `deliver_webhook` / `sign_payload`):
 *
 *   X-ApexMail-Signature: sha256=<hex HMAC-SHA256>
 *   X-ApexMail-Timestamp: <milliseconds since epoch>
 *
 * The signed message is `"{timestamp}.{payload}"` where the timestamp
 * digits are used VERBATIM as delivered — the signature input must be built
 * from the raw header string, never a normalized or second-converted
 * timestamp. The millisecond timestamp is auto-detected (its seconds
 * sibling cannot exist above 10^12) so both the platform path and older
 * integrations verify.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export type SignatureHeader = string | readonly string[] | null | undefined;

export interface VerifySignatureOptions {
  /** Maximum accepted age of the timestamp in seconds (default 300; 0 disables). */
  toleranceSeconds?: number;
  /** Explicit timestamp override (seconds or milliseconds digits). */
  timestamp?: string | number | null;
  /** The X-ApexMail-Timestamp header value. */
  timestampHeader?: string | number | null;
}

// Timestamps above this value (2001-09-09T01:46:40Z) cannot be epoch
// seconds; below it they cannot be epoch milliseconds.
const MS_CUTOFF = 1_000_000_000_000;

interface ParsedHeader {
  timestamp: string | null;
  signature: string | null;
}

function parseSignatureHeader(signatureHeader: string): ParsedHeader {
  const trimmed = signatureHeader.trim();
  if (trimmed === "") {
    return { timestamp: null, signature: null };
  }
  if (trimmed.includes("t=") && trimmed.includes("v1=")) {
    let timestamp: string | null = null;
    let signature: string | null = null;
    for (const part of trimmed.split(",")) {
      const [key, ...rest] = part.trim().split("=");
      const value = rest.join("=");
      if (key === "t" && value) {
        timestamp = value;
      } else if (key === "v1" && value) {
        signature = value;
      }
    }
    return { timestamp, signature };
  }
  if (trimmed.startsWith("sha256=")) {
    return { timestamp: null, signature: trimmed.slice("sha256=".length) };
  }
  return { timestamp: null, signature: trimmed };
}

/**
 * Validate an ApexMail webhook signature using HMAC-SHA256.
 *
 * Pass BOTH platform headers for real deliveries:
 *
 * ```ts
 * const ok = verifySignature(
 *   rawBody,
 *   req.headers["x-apexmail-signature"],
 *   secret,
 *   { timestampHeader: req.headers["x-apexmail-timestamp"] },
 * );
 * ```
 *
 * The legacy combined header form `"t=<seconds>,v1=<hex>"` and an explicit
 * `timestamp` override remain supported for older integrations.
 */
export function verifySignature(
  payload: string | Uint8Array,
  signatureHeader: SignatureHeader,
  secret: string,
  options: VerifySignatureOptions = {},
): boolean {
  if (signatureHeader === null || signatureHeader === undefined || secret === "") {
    return false;
  }

  let headerValue: string;
  if (Array.isArray(signatureHeader)) {
    if (signatureHeader.length === 0) {
      return false;
    }
    headerValue = String(signatureHeader[0]);
  } else {
    headerValue = String(signatureHeader);
  }

  const parsed = parseSignatureHeader(headerValue);
  const toleranceSeconds = options.toleranceSeconds ?? 300;

  let timestamp: string | number | null;
  if (options.timestamp !== undefined && options.timestamp !== null) {
    timestamp = options.timestamp;
  } else if (options.timestampHeader !== undefined && options.timestampHeader !== null) {
    timestamp = options.timestampHeader;
  } else {
    timestamp = parsed.timestamp;
  }

  const signature = parsed.signature;
  if (signature === null || signature === "") {
    return false;
  }
  if (timestamp === null || timestamp === undefined) {
    return false;
  }
  const timestampText = String(timestamp).trim();
  if (!/^\d+$/.test(timestampText)) {
    return false;
  }

  // Auto-detect seconds vs milliseconds: the platform sends milliseconds.
  const timestampValue = Number.parseInt(timestampText, 10);
  const isMilliseconds = timestampText.length > 11 || timestampValue > MS_CUTOFF;
  const now = isMilliseconds ? Date.now() : Date.now() / 1000;
  const tolerance = toleranceSeconds * (isMilliseconds ? 1000 : 1);
  if (toleranceSeconds > 0 && Math.abs(now - timestampValue) > tolerance) {
    return false;
  }

  const payloadBytes = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  // Sign with the timestamp digits EXACTLY as delivered (milliseconds on the
  // platform path) — never a normalized form.
  const signedPayload = Buffer.concat([Buffer.from(`${timestampText}.`, "utf8"), payloadBytes]);
  const expected = createHmac("sha256", Buffer.from(secret, "utf8")).update(signedPayload).digest("hex");

  const expectedBytes = Buffer.from(expected, "utf8");
  const signatureBytes = Buffer.from(signature, "utf8");
  if (expectedBytes.length !== signatureBytes.length) {
    return false;
  }
  return timingSafeEqual(expectedBytes, signatureBytes);
}

/**
 * Historical alias of {@link verifySignature} (sdk-python's changelog
 * documented the helper under this name).
 */
export const verifyWebhookSignature = verifySignature;
