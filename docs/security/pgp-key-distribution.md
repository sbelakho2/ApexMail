# PGP Key Distribution

> **Last Updated:** 2026-10-07
> **Status:** PGP public key shipped; private key held by the security team

## Key Information

The ApexMail security contact key is used for encrypted vulnerability
reports and for signing security advisories.

| Property | Value |
|----------|-------|
| **Fingerprint** | `B30B 9531 6B44 4E38 2803  19A5 5183 FF3B C9A6 9386` |
| **Key ID** | `0x5183FF3BC9A69386` |
| **Algorithm** | RSA 4096 (sign, certify, encrypt) |
| **Created** | 2026-07-29 |
| **UID** | `ApexMail Security <security@apexmail.ee>` |
| **Public key** | [`apps/marketing-zola/static/pgp-key.asc`](../../apps/marketing-zola/static/pgp-key.asc) (`https://apexmail.ee/pgp-key.asc`) |
| **Repository copy** | [`docs/security/pgp-public-key.asc`](pgp-public-key.asc) |

The private key is held by the security team and is not in the repository.
Verify the shipped public key with:

```bash
gpg --show-keys apps/marketing-zola/static/pgp-key.asc
# pub   rsa4096 2026-07-29 [SCE]
#       B30B95316B444E38280319A55183FF3BC9A69386
# uid           ApexMail Security <security@apexmail.ee>
```

## Where the Key Is Published

| Location | URL / Path |
|----------|-----------|
| Marketing origin (served) | `https://apexmail.ee/pgp-key.asc` |
| Repository | [`apps/marketing-zola/static/pgp-key.asc`](../../apps/marketing-zola/static/pgp-key.asc) |
| Repository copy | [`docs/security/pgp-public-key.asc`](pgp-public-key.asc) |
| security.txt | `Encryption:` field points at the served `.asc` |

The fingerprint is published in
[the vulnerability disclosure program](vulnerability-disclosure-program.md)
and in `security.txt`'s `Encryption` target. Keyserver, WKD, Keybase and
social-profile publication are not configured by this repository; treat this
page and the served `.asc` as the publication record.

## Key Generation (operator step)

The private key is held only by the security team. To generate a replacement
(with the same algorithm profile) on a trusted machine:

```bash
gpg --batch --generate-key <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign,cert,encrypt
Name-Real: ApexMail Security
Name-Email: security@apexmail.ee
Expire-Date: 2y
%commit
EOF
gpg --armor --export security@apexmail.ee > apps/marketing-zola/static/pgp-key.asc
cp apps/marketing-zola/static/pgp-key.asc docs/security/pgp-public-key.asc
```

Store the revocation certificate offline:

```bash
gpg --gen-revoke --armor security@apexmail.ee > pgp-revocation-certificate.asc
```

Update the fingerprint in this page and in
[the vulnerability disclosure program](vulnerability-disclosure-program.md)
whenever the key changes.

## Signing the Contact File

The served `security.txt` is unsigned; a clear-signed copy is the requested
form for signed disclosures. Signing requires the private key:

```bash
gpg --clear-sign --local-user security@apexmail.ee \
  --output security.txt.asc \
  apps/marketing-zola/static/.well-known/security.txt
```

## Verification Instructions

```bash
# Verify the shipped key
gpg --show-keys docs/security/pgp-public-key.asc

# Import it
gpg --import docs/security/pgp-public-key.asc

# Check the fingerprint matches the published one
gpg --fingerprint security@apexmail.ee
```

Compare the printed fingerprint against
`B30B 9531 6B44 4E38 2803  19A5 5183 FF3B C9A6 9386` through a second
channel before trusting a message signed with this key.

## Revocation

When a revocation is required (suspected private-key compromise or scheduled
rotation), import the offline revocation certificate, publish the updated key
material, and update the fingerprint in both security pages:

```bash
gpg --import pgp-revocation-certificate.asc
gpg --armor --export security@apexmail.ee > apps/marketing-zola/static/pgp-key.asc
```

## References

- [Security Vulnerability Management](../compliance/vulnerability-management.md)
- [Vulnerability Disclosure Program](vulnerability-disclosure-program.md)
- [RFC 9116 — security.txt](https://datatracker.ietf.org/doc/rfc9116/)
