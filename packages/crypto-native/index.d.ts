/// <reference types="node" />

/**
 * @module @apexmail/crypto-native
 *
 * Native Node.js bindings for ApexMail cryptographic operations.
 * All computationally-expensive operations run off the event loop
 * via the libuv thread-pool.
 */

// ─── AES-128-GCM ──────────────────────────────────────────────────────────────

/**
 * Encrypt `plaintext` with AES-128-GCM.
 *
 * @param key       - 16-byte AES-128 key.
 * @param plaintext - Plaintext bytes to encrypt.
 * @param aad       - Optional Additional Authenticated Data (not encrypted, but authenticated).
 * @returns         `nonce (12 B) ‖ ciphertext+tag` as a `Buffer`.
 * @throws          If the key length is not 16 bytes.
 */
export declare function encryptAes128Gcm(
  key: Buffer,
  plaintext: Buffer,
  aad?: Buffer | null,
): Buffer

/**
 * Decrypt `ciphertext` with AES-128-GCM.
 *
 * Expects `nonce (12 B) ‖ ciphertext+tag` as produced by {@link encryptAes128Gcm}.
 *
 * @param key        - 16-byte AES-128 key.
 * @param ciphertext - Nonce-prefixed ciphertext+tag buffer.
 * @param aad        - Optional Additional Authenticated Data (must match what was used to encrypt).
 * @returns          Decrypted plaintext.
 * @throws           On authentication failure (tag mismatch) or invalid key.
 */
export declare function decryptAes128Gcm(
  key: Buffer,
  ciphertext: Buffer,
  aad?: Buffer | null,
): Buffer

// ─── AES-256-GCM ──────────────────────────────────────────────────────────────

/**
 * Encrypt `plaintext` with AES-256-GCM.
 *
 * @param key       - 32-byte AES-256 key.
 * @param plaintext - Plaintext bytes to encrypt.
 * @param aad       - Optional Additional Authenticated Data.
 * @returns         `nonce (12 B) ‖ ciphertext+tag`.
 * @throws          If the key length is not 32 bytes.
 */
export declare function encryptAes256Gcm(
  key: Buffer,
  plaintext: Buffer,
  aad?: Buffer | null,
): Buffer

/**
 * Decrypt `ciphertext` with AES-256-GCM.
 *
 * @param key        - 32-byte AES-256 key.
 * @param ciphertext - Nonce-prefixed ciphertext+tag buffer.
 * @param aad        - Optional Additional Authenticated Data.
 * @returns          Decrypted plaintext.
 * @throws           On authentication failure or invalid key.
 */
export declare function decryptAes256Gcm(
  key: Buffer,
  ciphertext: Buffer,
  aad?: Buffer | null,
): Buffer

// ─── HKDF key derivation ──────────────────────────────────────────────────────

/**
 * Derive a 32-byte sub-key from `masterKey` using HKDF-SHA-256.
 *
 * The salt is the HKDF default (all-zero `HashLen` bytes).
 * Use `info` as a domain-separation label (e.g. `"apexmail:signing-key:v1"`).
 *
 * @param masterKey - Input key material (any length ≥ 1 byte).
 * @param info      - Context / domain-separation string.
 * @returns         32-byte derived key as a `Buffer`.
 */
export declare function deriveKeyHkdf(masterKey: Buffer, info: string): Buffer

// ─── HMAC-SHA-256 ─────────────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA-256.
 *
 * @param key  - HMAC key (any length).
 * @param data - Input data.
 * @returns    32-byte MAC as a `Buffer`.
 */
export declare function hmacSha256(key: Buffer, data: Buffer): Buffer

// ─── Argon2id password hashing ────────────────────────────────────────────────

/**
 * Hash `password` with Argon2id (off-thread).
 *
 * Returns a PHC-format string (e.g. `$argon2id$v=19$m=65536,t=3,p=4$...`).
 * The result is safe to store verbatim in the database and is self-describing
 * (algorithm + parameters are embedded), making future migrations trivial.
 *
 * @param password    - Plaintext password.
 * @param timeCost    - Number of iterations (default 3).
 * @param memoryCost  - Memory usage in KiB (default 65536 = 64 MiB).
 * @param parallelism - Degree of parallelism (default 4).
 * @returns           PHC-formatted hash string.
 */
export declare function hashPassword(
  password: string,
  timeCost?: number | null,
  memoryCost?: number | null,
  parallelism?: number | null,
): Promise<string>

/**
 * Verify `password` against an Argon2 `hash` (PHC format, off-thread).
 *
 * @param hash     - PHC-formatted hash string (from {@link hashPassword}).
 * @param password - Plaintext password to verify.
 * @returns        `true` on success, `false` on mismatch.
 * @throws         If `hash` is not a valid PHC string.
 */
export declare function verifyPassword(hash: string, password: string): Promise<boolean>

// ─── RSA DKIM key-pair generation ─────────────────────────────────────────────

/** DER-encoded RSA key pair for DKIM signing. */
export interface DkimKeyPair {
  /** PKCS#8 DER-encoded private key. */
  privateKey: Buffer
  /**
   * SubjectPublicKeyInfo (SPKI) DER-encoded public key.
   *
   * This is the key material published in a DKIM DNS TXT record (`p=` tag),
   * Base64-encoded: `p=${publicKey.toString('base64')}`.
   */
  publicKey: Buffer
}

/**
 * Generate an RSA key pair for DKIM signing (off-thread).
 *
 * DKIM requires RSA keys of at least 1024 bits; the recommended minimum
 * for new deployments is 2048 bits.
 *
 * @param bits - Key size in bits (1024–8192).
 * @returns    `{ privateKey, publicKey }` as DER-encoded `Buffer`s.
 * @throws     If `bits` is outside [1024, 8192].
 */
export declare function generateDkimKeyPair(bits: number): Promise<DkimKeyPair>

// ─── Constant-time comparison ─────────────────────────────────────────────────

/**
 * Compare two buffers in constant time (timing-safe).
 *
 * Unlike `Buffer.equals`, this function does not short-circuit on the first
 * differing byte, preventing timing-oracle attacks.
 *
 * @param a - First buffer.
 * @param b - Second buffer.
 * @returns `true` only when `a.length === b.length` AND every byte matches.
 */
export declare function timingSafeEqual(a: Buffer, b: Buffer): boolean

// ─── Secure random bytes ──────────────────────────────────────────────────────

/**
 * Generate `length` cryptographically-secure random bytes using the OS RNG.
 *
 * This is a thin wrapper around the Rust `OsRng` (i.e. `/dev/urandom` on Linux,
 * `SecRandomCopyBytes` on macOS) and is suitable for generating nonces, IVs,
 * session tokens, CSRF tokens, etc.
 *
 * @param length - Number of bytes to generate (max 1 MiB = 1048576).
 * @returns      Random bytes as a `Buffer`.
 * @throws       If `length` > 1048576.
 */
export declare function secureRandomBytes(length: number): Buffer

// ─── Hex / Base64 helpers ─────────────────────────────────────────────────────

/**
 * Encode `bytes` to a lowercase hexadecimal string.
 *
 * Example: `bufToHex(Buffer.from([0xde, 0xad, 0xbe, 0xef]))` → `"deadbeef"`
 */
export declare function bufToHex(bytes: Buffer): string

/**
 * Decode a hexadecimal string to a `Buffer`.
 *
 * @throws If `s` contains characters outside `[0-9a-fA-F]` or has odd length.
 */
export declare function hexToBuf(s: string): Buffer

/**
 * Encode `bytes` to a Base64 string (standard alphabet, with padding).
 */
export declare function bufToBase64(bytes: Buffer): string

/**
 * Decode a Base64 string to a `Buffer`.
 *
 * @throws If `s` is not valid Base64.
 */
export declare function base64ToBuf(s: string): Buffer
