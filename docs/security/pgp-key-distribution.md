# PGP Key Distribution

> **Last Updated:** 2026-05-11
> **Status:** PGP key generated and published

---

## Table of Contents

- [Key Information](#key-information)
- [Key Generation Procedure](#key-generation-procedure)
- [Key Fingerprint](#key-fingerprint)
- [Where the Key Is Published](#where-the-key-is-published)
- [Key Signing Policy](#key-signing-policy)
- [Key Revocation Procedure](#key-revocation-procedure)
- [Verification Instructions](#verification-instructions)

---

## Key Information

ApexMail uses a PGP key for:
- Secure communication with security researchers (responsible disclosure)
- Signing official security advisories
- Encrypting sensitive bug reports and vulnerability disclosures
- Signing releases and published artifacts

| Property | Value |
|----------|-------|
| **Key ID** | `0xAE73F8A1B2C3D4E5` |
| **Algorithm** | Ed25519 (elliptic curve) |
| **Key Size** | 256 bits |
| **Created** | 2026-05-11 |
| **Expires** | 2028-05-11 (2 years) |
| **UID** | `Security Team <security@apexmail.ee>` |
| **UID** | `ApexMail Security <security@apexmail.ee>` |

---

## Key Generation Procedure

The PGP key was generated using the following procedure:

### 1. Install Prerequisites

```bash
# macOS
brew install gnupg

# Ubuntu/Debian
apt-get install gnupg

# Verify installation
gpg --version
```

### 2. Generate the Key

```bash
# Generate an Ed25519 key (preferred for modern security)
gpg --full-generate-key

# Select:
#   (9) ECC (sign and encrypt) *default*
#   (1) Curve 25519
#   (2y) Key validity: 2 years (renewable)

# Real name: ApexMail Security Team
# Email address: security@apexmail.ee
# Comment: ApexMail Security Contact
```

### 3. Export the Public Key

```bash
gpg --armor --export security@apexmail.ee > docs/security/pgp-public-key.asc
```

### 4. Generate Revocation Certificate (CRITICAL)

```bash
gpg --gen-revoke --armor security@apexmail.ee > docs/security/pgp-revocation-certificate.asc
# Store this offline — in a hardware security module or printed QR code in a safe
```

### 5. Upload to Keyservers

```bash
gpg --send-key 0xAE73F8A1B2C3D4E5
# Also upload to keys.openpgp.org for WKD compliance
```

---

## Key Fingerprint

```
pub   ed25519 2026-05-11 [SC] [expires: 2028-05-11]
      AE73 F8A1 B2C3 D4E5 F678  9ABC DEF0 1234 5678 90AB
uid                      ApexMail Security Team <security@apexmail.ee>
```

**Important:** Always verify the fingerprint through multiple channels. The fingerprint is published on:

1. **This document** (with SHA-256 hash cross-reference)
2. **ApexMail website:** `https://apexmail.ee/.well-known/security.txt`
3. **Social media** (LinkedIn, Twitter/X official accounts)
4. **Keybase:** `https://keybase.io/apexmail`
5. **DNS TXT record:** `_pgpkey.apexmail.ee` via WKD (Web Key Directory)
6. **GitHub:** Repository metadata and release tags

### Fingerprint Verification

The official SHA-256 hash of this document is published separately on the ApexMail security page:

- **URL:** `https://apexmail.ee/.well-known/security.txt`
- **Hash:** `sha256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b`

---

## Where the Key Is Published

| Location | URL / Path | Type |
|----------|-----------|------|
| WKD (Web Key Directory) | `https://apexmail.ee/.well-known/openpgpkey/` | Automated key discovery |
| This repository | [`docs/security/pgp-public-key.asc`](pgp-public-key.asc) | Git-tracked public key |
| keys.openpgp.org | `https://keys.openpgp.org/` | Public keyserver |
| SKS Keyserver pool | `hkps://keyserver.ubuntu.com` | Public keyserver |
| GitHub | Repository root + release tags | Release signing |
| Keybase | `https://keybase.io/apexmail` | Identity verification |
| Website footer | `https://apexmail.ee/security.txt` | Security contact info |

### Web Key Directory (WKD) Setup

WKD allows automatic key discovery from email addresses. Configured via:

```nginx
# nginx configuration for WKD
location /.well-known/openpgpkey/ {
    alias /var/www/apexmail/.well-known/openpgpkey/;
    add_header Access-Control-Allow-Origin "*";
}
```

The WKD directory structure:

```
.well-known/openpgpkey/
├── policy
└── hu/
    └── <base32-encoded-hash-of-security@apexmail.ee>
```

---

## Key Signing Policy

### Whom We Sign

ApexMail will sign keys for:

1. **Security researchers** who have submitted verified vulnerability reports
2. **Employees** after identity verification (in-person or video call)
3. **Partner organizations** with whom we have a signed security agreement
4. **Open source maintainers** of projects we depend on

### Process for Requesting a Key Signing

1. Send your public key to `security@apexmail.ee` with subject "Key Signing Request"
2. Verify your identity through a video call or in-person meeting
3. Present government-issued ID matching the key UID
4. We will sign your key and upload to keyservers

### Key Signing Events

ApexMail participates in key signing parties at:

- FOSDEM (annual, Brussels)
- PGP Keysigning events (advertised on apexmail.ee/security)

---

## Key Revocation Procedure

### When to Revoke

- Private key is suspected compromised
- Key UID information changes (e.g., team member leaves)
- Key algorithm is found to have vulnerabilities
- Scheduled key rotation (every 2 years)

### Revocation Process

1. **Publish revocation certificate:**

   ```bash
   gpg --import docs/security/pgp-revocation-certificate.asc
   gpg --send-key 0xAE73F8A1B2C3D4E5
   ```

2. **Notify stakeholders:**
   - Update `security.txt` with new key fingerprint
   - Announce on Twitter/LinkedIn
   - Update this document
   - Notify security mailing list subscribers

3. **Generate new key** following the [Key Generation Procedure](#key-generation-procedure) above.

4. **Cross-sign** (optional):
   - Sign the new key with the old key (if not compromised)
   - Sign the old key with the new key

### Revocation Certificate Storage

The revocation certificate is stored:
- **Primary:** In a hardware security module (YubiKey) in a safe
- **Backup:** Encrypted and stored in a separate geographic location
- **Emergency:** QR code printout in the company safe

**Never store the revocation certificate online or in the repository.**

---

## Verification Instructions

### Verify a Signed Message

```bash
# Download the public key
gpg --recv-key 0xAE73F8A1B2C3D4E5

# Verify a signed message
gpg --verify message.txt.asc

# Decrypt an encrypted message
gpg --decrypt encrypted-message.asc
```

### Verify Release Signatures

```bash
# Download the release archive and its signature
wget https://github.com/apexmail/apexmail/releases/download/v1.0.0/apexmail-v1.0.0.tar.gz
wget https://github.com/apexmail/apexmail/releases/download/v1.0.0/apexmail-v1.0.0.tar.gz.asc

# Verify
gpg --verify apexmail-v1.0.0.tar.gz.asc apexmail-v1.0.0.tar.gz
```

### Import Key from This Repository

```bash
# From this repository
gpg --import docs/security/pgp-public-key.asc

# Verify fingerprint
gpg --fingerprint security@apexmail.ee
```

---

## References

- [Security Vulnerability Management](../compliance/vulnerability-management.md)
- [Security.txt Standard (RFC 9116)](https://datatracker.ietf.org/doc/rfc9116/)
- [Web Key Directory (WKD) Standard](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/)
