# DKIM Configuration

DomainKeys Identified Mail (DKIM) adds a cryptographic signature to every outgoing email, allowing receiving servers to verify the email was sent by an authorized sender and was not modified in transit.

## How DKIM Works

1. ApexMail signs outgoing email with a private key.
2. The corresponding public key is published in your domain's DNS as a TXT record.
3. Receiving mail servers retrieve the public key and verify the signature.
4. If the signature is valid, the email passes DKIM authentication.

## Required DKIM Records

Create the domain in the dashboard, then copy the exact DKIM record or records
shown in its DNS settings. The selector is stored per domain; it is not safe to
reuse a selector or target from an example, another tenant, or an older guide.
The default selector applies only when a domain has not been assigned one.

Key changes follow an operational overlap and DNS-propagation procedure. They
are not an automatic public rotation service.

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

## Verifying DKIM

Send a test email and check the headers:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
  s=<assigned-selector>; h=from:to:subject:date:message-id;
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
