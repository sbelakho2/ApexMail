# DKIM Configuration

DomainKeys Identified Mail (DKIM) adds a cryptographic signature to every outgoing email, allowing receiving servers to verify the email was sent by an authorized sender and was not modified in transit.

## How DKIM Works

1. ApexMail signs outgoing email with a private key.
2. The corresponding public key is published in your domain's DNS as a TXT record.
3. Receiving mail servers retrieve the public key and verify the signature.
4. If the signature is valid, the email passes DKIM authentication.

## Required DKIM Records

ApexMail provides two DKIM selectors for key rotation. Add both CNAME records to your DNS:

| Type | Host | Value |
|---|---|---|
| CNAME | `am1._domainkey` | `am1.dkim.apexmail.ee` |
| CNAME | `am2._domainkey` | `am2.dkim.apexmail.ee` |

These are CNAME records that point to ApexMail's DKIM infrastructure, where the actual TXT records (public keys) are hosted and automatically rotated.

### Custom DKIM (Enterprise)

Enterprise customers with dedicated tenants can bring their own DKIM keys. Contact support for the key exchange protocol.

## 1024-bit vs 2048-bit

ApexMail uses 2048-bit RSA keys by default, which provide stronger security and meet modern requirements (including some government and financial sector mandates).

## DKIM Signature Headers

ApexMail signs the following headers by default:

- `From`
- `To`
- `Subject`
- `Date`
- `Message-ID`
- `MIME-Version`
- `Content-Type`
- `Reply-To`
- `X-ApexMail-*` headers

## Verifying DKIM

Send a test email and check the headers:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
  s=am1; h=from:to:subject:date:message-id;
  bh=...; b=...
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com
```

## DKIM Alignment

For DMARC to pass, the domain in the `d=` tag of the DKIM signature must align with the `From` header domain. ApexMail signs with your verified domain in the `d=` tag.

## Related

- [SPF](spf.md)
- [DMARC](dmarc.md)
- [Domain Verification](../getting-started/domain-verification.md)
