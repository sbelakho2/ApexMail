# backup-envelope.sh — THE canonical backup envelope, sourced by BOTH the
# producer (postgres-backup-encrypt.sh) and the consumer
# (postgres-restore-drill.sh).
#
# Why this file exists (external audit 2026-10-26, finding: "a recovery drill
# that cannot restore the backups the backup service actually creates"): the
# producer encrypted with PBKDF2 at 600,000 iterations while the drill
# decrypted at 100,000, so every real backup failed the drill. One envelope,
# one implementation, no parameter copy-paste.
#
# The envelope, exactly:
#   pg_dump -Fc  →  gzip  →  openssl enc -aes-256-cbc -pbkdf2
#                              -iter 600000 -md sha256 -salt
#   file name:   apexmail-backup-YYYYmmdd-HHMMSS.sql.gz.enc (UTC)
#
# POSIX sh, no side effects on source. Callers resolve the key first (see
# backup_envelope_key) and pass it in BACKUP_ENVELOPE_KEY.

BACKUP_ENVELOPE_ITER="${BACKUP_ENVELOPE_ITER:-600000}"
BACKUP_ENVELOPE_CIPHER="aes-256-cbc"
BACKUP_ENVELOPE_MD="sha256"
BACKUP_ENVELOPE_MAGIC="PGDMP"

# backup_envelope_key — sets BACKUP_ENVELOPE_KEY from the Docker secret file
# (preferred) or the env var. Returns 1 when no key is available; callers
# decide the failure policy (production: refuse, see the producer script).
backup_envelope_key() {
    _be_key_file="${BACKUP_ENCRYPTION_KEY_FILE:-/run/secrets/backup_encryption_key}"
    if [ -f "$_be_key_file" ]; then
        BACKUP_ENCRYPTION_KEY="$(tr -d '\r\n' < "$_be_key_file")"
    fi
    BACKUP_ENVELOPE_KEY="${BACKUP_ENCRYPTION_KEY:-}"
    [ -n "$BACKUP_ENVELOPE_KEY" ]
}

# backup_envelope_encrypt <plaintext.gz> <ciphertext.enc>
# The production encoder. Fails non-zero on any error; the caller owns
# plaintext-retention semantics.
backup_envelope_encrypt() {
    openssl enc -"$BACKUP_ENVELOPE_CIPHER" -pbkdf2 -iter "$BACKUP_ENVELOPE_ITER" \
        -md "$BACKUP_ENVELOPE_MD" -salt \
        -pass "pass:${BACKUP_ENVELOPE_KEY}" -in "$1" -out "$2"
}

# backup_envelope_decrypt <ciphertext.enc> <plaintext.gz>
# The production decoder — byte-for-byte the inverse of the encoder above.
backup_envelope_decrypt() {
    openssl enc -d -"$BACKUP_ENVELOPE_CIPHER" -pbkdf2 -iter "$BACKUP_ENVELOPE_ITER" \
        -md "$BACKUP_ENVELOPE_MD" -salt \
        -pass "pass:${BACKUP_ENVELOPE_KEY}" -in "$1" -out "$2"
}

# backup_envelope_uncompress <plaintext.gz> <dump>
# The gzip stage between decryption and pg_restore. pg_restore CAN read a
# gzipped archive, but the drill names each stage so a corruption is
# attributable, and the byte-level self-test below needs the plain dump.
backup_envelope_uncompress() {
    gzip -dc "$1" > "$2"
}

# backup_envelope_self_test — a REAL round trip through the production codec.
# This is the check that would have caught the 100k/600k iteration drift: a
# synthetic dump (PGDMP magic, like a real pg_dump -Fc archive) is gzipped,
# encrypted and decrypted with the SAME functions production uses, and the
# recovered bytes must be identical. No database required; openssl is
# required (it is baked into both images and present on every CI runner).
backup_envelope_self_test() {
    if ! command -v openssl >/dev/null 2>&1; then
        echo "[envelope] self-test FAILED: openssl is required" >&2
        return 1
    fi
    _es_tmp="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-envelope-test.XXXXXX")" || return 1
    # Synthetic dump body: PGDMP magic + deterministic filler, gunzipped and
    # re-compressed exactly like the production pipeline stages.
    { printf '%s' "$BACKUP_ENVELOPE_MAGIC"; \
      printf 'synthetic archive body %s\n' "$$"; \
      i=0; while [ "$i" -lt 200 ]; do printf 'envelope self-test line %s\n' "$i"; i=$((i+1)); done; \
    } > "$_es_tmp/expected.dump"
    gzip -c "$_es_tmp/expected.dump" > "$_es_tmp/expected.dump.gz"

    # Pin the key so the round trip runs through the exact production codec
    # (same function bodies, same parameters) without a Docker secret.
    _es_saved_key="${BACKUP_ENCRYPTION_KEY-}"
    _es_saved_key_file="${BACKUP_ENCRYPTION_KEY_FILE-}"
    BACKUP_ENCRYPTION_KEY="envelope-self-test-key-do-not-use"
    BACKUP_ENCRYPTION_KEY_FILE=/nonexistent
    if ! backup_envelope_key \
        || ! backup_envelope_encrypt "$_es_tmp/expected.dump.gz" "$_es_tmp/roundtrip.sql.gz.enc" \
        || ! backup_envelope_decrypt "$_es_tmp/roundtrip.sql.gz.enc" "$_es_tmp/roundtrip.sql.gz" \
        || ! backup_envelope_uncompress "$_es_tmp/roundtrip.sql.gz" "$_es_tmp/actual.dump"; then
        echo "[envelope] self-test FAILED: codec round trip errored" >&2
        BACKUP_ENCRYPTION_KEY="$_es_saved_key"
        BACKUP_ENCRYPTION_KEY_FILE="$_es_saved_key_file"
        rm -rf "$_es_tmp"
        return 1
    fi
    BACKUP_ENCRYPTION_KEY="$_es_saved_key"
    BACKUP_ENCRYPTION_KEY_FILE="$_es_saved_key_file"
    if ! cmp -s "$_es_tmp/expected.dump" "$_es_tmp/actual.dump"; then
        echo "[envelope] self-test FAILED: round-trip bytes differ" >&2
        rm -rf "$_es_tmp"
        return 1
    fi
    # A wrong iteration count is exactly a wrong key: prove the ciphertext is
    # NOT decryptable with a drifted parameter set (mutation guard).
    if openssl enc -d -"$BACKUP_ENVELOPE_CIPHER" -pbkdf2 -iter 100000 \
            -md "$BACKUP_ENVELOPE_MD" -salt \
            -pass "pass:envelope-self-test-key-do-not-use" \
            -in "$_es_tmp/roundtrip.sql.gz.enc" -out "$_es_tmp/wrong-parameter.sql.gz" \
            2>/dev/null && cmp -s "$_es_tmp/expected.dump.gz" "$_es_tmp/wrong-parameter.sql.gz"; then
        echo "[envelope] self-test FAILED: drifted parameters still decode (codec is not binding)" >&2
        rm -rf "$_es_tmp"
        return 1
    fi
    rm -rf "$_es_tmp"
    echo "[envelope] self-test OK: production codec round trip + drifted-parameter rejection"
    return 0
}
