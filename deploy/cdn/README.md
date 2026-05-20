# CDN Configuration — ApexMail Static Assets (SCALE-H-05)

## Overview

This directory contains CDN configuration templates for serving ApexMail static
assets (marketing site, tracking pixels, web app assets) through a content
delivery network. Using a CDN reduces origin load, improves global latency, and
provides DDoS absorption at the edge.

## Supported CDN Providers

| Provider | Config File | Notes |
|----------|-------------|-------|
| AWS CloudFront | `cloudfront.yaml` | Recommended for AWS deployments |
| Fastly | `fastly.vcl` | Recommended for multi-cloud / edge-compute |
| Cloudflare | `cloudflare-rules.json` | Simple DNS-based setup |

## Architecture

```
Client → CDN Edge (global PoPs) → Nginx Origin → Static Assets
                                   ↘ API Server (dynamic)
```

### Static Asset Paths

| Path | Cache TTL | Notes |
|------|-----------|-------|
| `/assets/*` | 1 year | Hashed filenames, immutable |
| `/fonts/*` | 1 year | Font files rarely change |
| `/css/*` | 1 day | May update with deploys |
| `/js/*` | 1 day | May update with deploys |
| `/images/*` | 7 days | Marketing images |
| `/*.html` | 5 minutes | HTML pages (stale-while-revalidate) |

### Dynamic Paths (bypass CDN cache)

| Path | Notes |
|------|-------|
| `/v1/*` | API endpoints — forward to origin |
| `/t/*` | Tracking endpoints — forward to origin |
| `/api/*` | Enterprise API — forward to origin |

## Configuration

### Environment Variables

```bash
# CDN_DOMAIN: The CDN domain name (e.g., cdn.apexmail.ee)
# ORIGIN_DOMAIN: The origin server domain (e.g., api.apexmail.ee)
# SSL_CERTIFICATE_ARN: ARN of the ACM certificate (CloudFront)
# FASTLY_API_KEY: Fastly API key for purging
# FASTLY_SERVICE_ID: Fastly service ID
```

### CloudFront Setup (AWS)

1. Create an ACM certificate in `us-east-1` for `cdn.apexmail.ee`
2. Deploy the CloudFormation stack:
   ```bash
   aws cloudformation deploy \
     --template-file deploy/cdn/cloudfront.yaml \
     --stack-name apexmail-cdn \
     --parameter-overrides \
       DomainName=cdn.apexmail.ee \
       OriginDomain=api.apexmail.ee \
       AcmCertificateArn=arn:aws:acm:us-east-1:123456789:certificate/xxx \
     --capabilities CAPABILITY_IAM
   ```
3. Create a DNS CNAME record pointing `cdn.apexmail.ee` to the CloudFront distribution domain
4. Configure your application to use `cdn.apexmail.ee` for static asset URLs

### Fastly Setup

1. Create a Fastly service pointing to `api.apexmail.ee` as origin
2. Upload `fastly.vcl` as the custom VCL:
   ```bash
   fastly vcl upload --service-id=$FASTLY_SERVICE_ID --version=active --file=deploy/cdn/fastly.vcl
   ```
3. Configure DNS CNAME for `cdn.apexmail.ee` to point to the Fastly domain

### Cache Invalidation

After deploying new static assets, invalidate the CDN cache:

```bash
# CloudFront
aws cloudfront create-invalidation \
  --distribution-id $CLOUDFRONT_DISTRIBUTION_ID \
  --paths "/assets/*" "/css/*" "/js/*"

# Fastly
curl -X POST "https://api.fastly.com/service/$FASTLY_SERVICE_ID/purge_all" \
  -H "Fastly-Key: $FASTLY_API_KEY"
```

## Monitoring

- **Cache Hit Ratio**: Target > 90% for static assets
- **Origin Load**: Should decrease significantly after CDN setup
- **Latency p50**: Should be < 50ms globally with CDN
- **Bandwidth**: Monitor CDN egress vs origin egress

## Security Headers

All CDN configurations enforce:
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
