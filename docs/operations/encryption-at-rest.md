# Encryption at Rest (SEC-109)

## Overview

ApexMail stores sensitive data in PostgreSQL databases, Redis caches, and object
storage. This document describes how to enable encryption at rest for each
storage layer to protect data from unauthorized physical access to storage
volumes.

> **Compliance note**: Encryption at rest is required for SOC 2, HIPAA, and
> GDPR compliance in most production deployments.

---

## 1. PostgreSQL — Disk-Level Encryption

### Option A: AWS EBS Encryption (Recommended for AWS)

Enable encryption on the RDS instance or EBS volumes:

```bash
# For RDS — enable encryption at creation time
aws rds create-db-instance \
    --db-instance-identifier apexmail-prod \
    --storage-encrypted \
    --kms-key-id alias/apexmail-db-key \
    ...
```

For existing unencrypted RDS instances, create an encrypted snapshot and
restore:

```bash
# 1. Snapshot the existing instance
aws rds create-db-snapshot \
    --db-instance-identifier apexmail-prod \
    --db-snapshot-identifier apexmail-prod-migration

# 2. Copy the snapshot with encryption
aws rds copy-db-snapshot \
    --source-db-snapshot-identifier apexmail-prod-migration \
    --target-db-snapshot-identifier apexmail-prod-encrypted \
    --kms-key-id alias/apexmail-db-key \
    --copy-tags

# 3. Restore from the encrypted snapshot
aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier apexmail-prod-encrypted \
    --db-snapshot-identifier apexmail-prod-encrypted
```

### Option B: LUKS (Linux Unified Key Setup)

For self-hosted or bare-metal deployments:

```bash
# 1. Create a LUKS-encrypted volume
cryptsetup luksFormat /dev/sdb
cryptsetup luksOpen /dev/sdb encrypted_pgdata

# 2. Create a filesystem
mkfs.ext4 /dev/mapper/encrypted_pgdata

# 3. Mount and configure PostgreSQL
mkdir -p /var/lib/postgresql/encrypted
mount /dev/mapper/encrypted_pgdata /var/lib/postgresql/encrypted

# 4. Update postgresql.conf
# data_directory = '/var/lib/postgresql/encrypted/data'
```

### Option C: PostgreSQL Transparent Data Encryption (TDE)

PostgreSQL does not natively support TDE. Use disk-level encryption (Option A
or B) or consider the `pg_tde` extension for column-level encryption.

---

## 2. Redis — Encryption at Rest

### AWS ElastiCache

```bash
aws elasticache create-replication-group \
    --replication-group-id apexmail-redis \
    --at-rest-encryption-enabled \
    --kms-key-id alias/apexmail-redis-key \
    ...
```

### Self-Hosted Redis

Redis does not natively support encryption at rest. Use one of:

1. **Encrypted EBS/LUKS volume** (same as PostgreSQL Option B)
2. **Encrypt sensitive values before storing** — ApexMail already encrypts
   MFA secrets and IMAP passwords at the application layer using
   `secret_at_rest::encrypt_at_rest()`.
3. **Disk-level encryption** via the host OS.

---

## 3. Application-Level Encryption

ApexMail already applies application-level encryption for high-value secrets:

| Data Type | Encryption Method | Key Management |
|-----------|------------------|----------------|
| MFA TOTP secrets | AES-256-GCM via `secret_at_rest` | `SECRET_AT_REST_KEY` env var |
| IMAP passwords | AES-256-GCM via `secret_at_rest` | `PLACEMENT_ENCRYPTION_SECRET` env var |
| User password hashes | Argon2id / bcrypt | N/A (one-way hash) |
| API key hashes | SHA-256 HMAC | `API_KEY_HASH_SECRET` env var |
| Webhook signing secrets | HMAC-SHA256 | `WEBHOOK_SIGNING_SECRET` env var |

### Key Rotation

To rotate the `SECRET_AT_REST_KEY`:

1. Generate a new key and set `SECRET_AT_REST_KEY_PREVIOUS` to the old key.
2. Deploy the new key as `SECRET_AT_REST_KEY`.
3. Run the key rotation migration to re-encrypt all values.
4. Remove `SECRET_AT_REST_KEY_PREVIOUS` after verification.

---

## 4. Backup Encryption

### PostgreSQL Backups

```bash
# Encrypt a pg_dump backup with GPG
pg_dump -Fc apexmail | gpg --symmetric --cipher-algo AES256 -o backup.gpg

# Or use S3 server-side encryption
aws s3 cp backup.dump s3://apexmail-backups/ \
    --sse aws:kms \
    --sse-kms-key-id alias/apexmail-backup-key
```

### Automated Backup Encryption

Set the following environment variables for the backup job:

```env
BACKUP_ENCRYPTION_ENABLED=true
BACKUP_KMS_KEY_ID=alias/apexmail-backup-key
```

---

## 5. Verification

After enabling encryption, verify with:

```bash
# AWS EBS — check encryption status
aws ec2 describe-volumes --filters Name=encrypted,Values=true

# AWS RDS — check storage encryption
aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}'

# LUKS — verify volume status
cryptsetup status encrypted_pgdata

# Redis — check at-rest encryption (ElastiCache)
aws elasticache describe-replication-groups \
    --query 'ReplicationGroups[*].{ID:ReplicationGroupId,Encrypted:AtRestEncryptionEnabled}'
```

---

## 6. Compliance Checklist

- [ ] PostgreSQL storage encrypted (EBS encryption or LUKS)
- [ ] Redis storage encrypted (ElastiCache at-rest encryption or LUKS)
- [ ] Application-level secrets encrypted with `SECRET_AT_REST_KEY`
- [ ] Backup encryption enabled with KMS key
- [ ] Key rotation procedure documented and tested
- [ ] Encryption keys stored in a secrets manager (AWS KMS, HashiCorp Vault)
- [ ] Encryption status verified in monitoring/alerting
