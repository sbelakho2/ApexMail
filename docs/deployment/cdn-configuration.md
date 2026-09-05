# CDN Configuration

> **SCALE-H-05** | Owner: Platform Engineering | Last updated: 2026-05-17

## Overview

A Content Delivery Network (CDN) accelerates delivery of static assets, offloads traffic from the origin servers, and provides DDoS protection. This document covers recommended CDN configurations for ApexMail's static assets, cache headers, and API vs static asset routing through the Helm chart ingress.

---

## 1. Architecture Overview

```
                        ┌──────────────────┐
                        │     CDN Edge     │
                        │  (CloudFront /   │
                        │   Cloudflare)    │
                        └────────┬─────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
          ┌──────────────────┐     ┌──────────────────┐
          │  Static Assets   │     │   API Server     │
          │  (S3 / GCS)      │     │  (Kubernetes)    │
          │  apexmail-cdn/   │     │  api.apexmail.ee │
          └──────────────────┘     └──────────────────┘
                    │                         │
                    ▼                         ▼
          ┌──────────────────┐     ┌──────────────────┐
          │  Long cache TTL  │     │  No caching or   │
          │  (1y, immutable) │     │  short TTL only  │
          └──────────────────┘     └──────────────────┘
```

- **Static assets** (CSS, JS, images, fonts): Served via CDN with aggressive caching
- **API traffic**: Routed directly to the Kubernetes ingress, bypassing CDN caching

---

## 2. Recommended CDN Providers

### 2.1 Amazon CloudFront

Best choice for deployments on AWS (RDS, S3, EKS).

#### Distribution Configuration

```hcl
# Terraform: CloudFront distribution for ApexMail static assets
resource "aws_cloudfront_distribution" "apexmail_static" {
  origin {
    domain_name = "apexmail-cdn.s3.amazonaws.com"
    origin_id   = "S3-apexmail-cdn"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.apexmail_cdn.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"  # North America + Europe only

  # Custom domain
  aliases = ["cdn.apexmail.ee"]

  # SSL certificate (ACM in us-east-1)
  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.apexmail_cdn.arn
    ssl_support_method  = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # Default cache behaviour
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-apexmail-cdn"
    compress         = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400    # 24 hours
    max_ttl                = 31536000 # 1 year
  }

  # Cache behaviour for images (longer TTL — images are rarely updated)
  ordered_cache_behavior {
    path_pattern     = "images/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-apexmail-cdn"
    compress         = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 31536000 # 1 year
    max_ttl                = 31536000 # 1 year
  }

  # Cache behaviour for fonts (immutable, fingerprinted filenames)
  ordered_cache_behavior {
    path_pattern     = "fonts/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-apexmail-cdn"
    compress         = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 31536000
    default_ttl            = 31536000
    max_ttl                = 31536000
  }

  # Custom error responses
  custom_error_response {
    error_code         = 403
    response_code      = 404
    response_page_path = "/404.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 404
    response_page_path = "/404.html"
  }

  # Logging
  logging_config {
    bucket = "apexmail-cdn-logs.s3.amazonaws.com"
    prefix = "cloudfront/"
  }

  tags = {
    Name        = "apexmail-static-cdn"
    Environment = "production"
  }
}
```

### 2.2 Cloudflare

Best choice for multi-cloud or hybrid deployments.

#### Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| **SSL/TLS** | Full (strict) | End-to-end encryption with origin CA certificate |
| **Min TLS Version** | TLS 1.2 | Compliance requirement |
| **Cache Level** | Standard | Cache static assets, bypass API |
| **Edge Cache TTL** | Respect origin headers | Origin controls caching via `Cache-Control` |
| **Browser Cache TTL** | 4 hours | Respects origin headers; override for static assets |
| **Auto Minify** | JavaScript, CSS, HTML | Reduces payload size automatically |
| **Brotli** | On | Better compression than gzip for text assets |
| **HTTP/2** | On | Multiplexing improves concurrent asset loading |
| **Argo Smart Routing** | On | Optimises origin routing (additional cost) |
| **DDoS Protection** | Under Attack mode | Auto-enabled during Layer 7 attacks |
| **WAF** | OWASP Core Ruleset | SQL injection, XSS, RFI protection |

#### Page Rules

```
cdn.apexmail.ee/assets/*         → Cache Level: Cache Everything, Edge TTL: 1y
cdn.apexmail.ee/fonts/*          → Cache Level: Cache Everything, Edge TTL: 1y
cdn.apexmail.ee/images/*         → Cache Level: Cache Everything, Edge TTL: 1y
cdn.apexmail.ee/js/*             → Cache Level: Cache Everything, Edge TTL: 1y
cdn.apexmail.ee/css/*            → Cache Level: Cache Everything, Edge TTL: 1y
cdn.apexmail.ee/api/*            → Cache Level: Bypass, Security: On
cdn.apexmail.ee/*.html           → Cache Level: Bypass (dynamic content)
```

---

## 3. Cache Headers Configuration

### 3.1 Static Assets (Aggressive Caching)

Set these headers on origin responses for static assets served from S3/GCS:

| Header | Value | Effect |
|--------|-------|--------|
| `Cache-Control` | `public, max-age=31536000, immutable` | Cache for 1 year; browser must not revalidate |
| `ETag` | `{file-hash}` | Conditional requests for cache validation |
| `Content-Type` | Correct MIME type | Ensures proper rendering |

**S3 object metadata example:**

```json
{
  "CacheControl": "public, max-age=31536000, immutable",
  "ContentType": "text/css",
  "ContentEncoding": "br"
}
```

### 3.2 Fingerprinted vs Non-Fingerprinted Assets

| Strategy | Example | Cache Header |
|----------|---------|--------------|
| **Fingerprinted** (recommended) | `styles.a1b2c3d4.css` | `immutable`, 1 year TTL |
| **Versioned** | `styles.v1.2.3.css` | `immutable`, 1 year TTL |
| **Non-fingerprinted** | `styles.css` | `max-age=3600`, `must-revalidate` |

**Recommendation:** Use content-hash fingerprinted filenames (e.g., `[name].[contenthash:8].[ext]` in webpack/Rollup). This enables infinite caching: each new build produces a new URL, so the old URL never needs invalidation.

### 3.3 API Endpoints (No Caching or Short TTL)

| Header | Value | When |
|--------|-------|------|
| `Cache-Control` | `no-store, no-cache, must-revalidate, proxy-revalidate` | API responses with dynamic data |
| `Cache-Control` | `private, max-age=60` | Short-lived user-specific data (e.g., rate limit status) |
| `Surrogate-Control` | `no-store` | Instructs CDN not to cache even if `Cache-Control` allows |

### 3.4 Tracking Pixel (Special Case)

Tracking pixels (`/v1/tracking/pixel.gif`) must NOT be cached:

```
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0
```

---

## 4. Helm Chart Ingress Configuration

The ApexMail reverse proxy ([`deploy/nginx/nginx.conf`](../../deploy/nginx/nginx.conf)) is the CDN-facing origin and supports CDN integration.

### 4.1 Values Configuration

```yaml
# deploy/helm/apexmail/values.yaml (excerpt)
ingress:
  enabled: true
  className: nginx

  # Primary domain — serves both API and static assets
  host: api.apexmail.ee

  # CDN domain — serves static assets via CDN
  cdnHost: cdn.apexmail.ee

  # TLS
  tls:
    - hosts:
        - api.apexmail.ee
        - cdn.apexmail.ee
      secretName: apexmail-tls

  # Annotations for CDN integration
  annotations:
    # Cloudflare
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    # Enable real IP from CDN (Cloudflare/CloudFront)
    nginx.ingress.kubernetes.io/use-forwarded-headers: "true"
    # Rate limiting per CDN IP
    nginx.ingress.kubernetes.io/limit-rps: "5000"
```

### 4.2 API vs Static Asset Routing

```yaml
# Static assets — served via CDN origin pointing to S3/GCS
# These are NOT routed through the ingress; the CDN fetches directly
# from the object store.
#
# The ingress handles only API traffic and (optionally) non-cached assets.

# API routes
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: apexmail-api-ingress
  annotations:
    # CDN-bypass: set no-cache headers on API responses
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "Cache-Control: no-store, no-cache, must-revalidate";
      more_set_headers "Surrogate-Control: no-store";
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - api.apexmail.ee
      secretName: apexmail-tls
  rules:
    - host: api.apexmail.ee
      http:
        paths:
          # API endpoints
          - path: /v1/auth
            pathType: Prefix
            backend:
              service:
                name: api-server
                port:
                  number: 3000
          - path: /v1/email
            pathType: Prefix
            backend:
              service:
                name: api-server
                port:
                  number: 3000
          - path: /health/live
            pathType: Prefix
            backend:
              service:
                name: api-server
                port:
                  number: 3000
          - path: /v1/tracking
            pathType: Prefix
            backend:
              service:
                name: tracking-service
                port:
                  number: 3001
```

### 4.3 Subdomain Separation (Recommended)

```
┌─────────────────────────────────────────────────────┐
│ DNS Record Layout                                    │
│                                                      │
│ api.apexmail.ee     CNAME → ingress.k8s.apexmail.ee │
│ cdn.apexmail.ee     CNAME → cloudfront.net          │
│                      (or apexmail.cdn.cloudflare.net) │
│ track.apexmail.ee   CNAME → ingress.k8s.apexmail.ee │
│                                                      │
│ Subdomains:                                          │
│   api.apexmail.ee    → API server (no cache)         │
│   cdn.apexmail.ee    → CDN (static assets)           │
│   track.apexmail.ee  → Tracking (no cache)           │
└─────────────────────────────────────────────────────┘
```

### 4.4 Single Domain with Path-Based Routing (Alternative)

If using a single domain, configure ingress path-based rules and CDN caching behaviour:

```yaml
# Single-domain approach
rules:
  - host: app.apexmail.ee
    http:
      paths:
        # Static assets — CDN edge will cache these
        - path: /assets
          pathType: Prefix
          backend:
            service:
              name: cdn-origin
              port:
                number: 80
        # API — bypass CDN cache
        - path: /v1
          pathType: Prefix
          backend:
            service:
              name: api-server
              port:
                number: 3000
```

> **Note:** The path-based approach works but is less flexible. Subdomain separation allows independent scaling, distinct TLS configurations, and simpler CDN cache rules.

---

## 5. CDN Cache Invalidation

### 5.1 When to Invalidate

| Trigger | Action | Method |
|---------|--------|--------|
| New deployment (fingerprinted assets) | No invalidation needed | Assets have new URLs |
| New deployment (non-fingerprinted assets) | Invalidate `/assets/*`, `/css/*`, `/js/*` | API call |
| Static content update (images, fonts) | Invalidate specific paths | Targeted invalidation |
| Security incident | Invalidate everything | Full invalidation |

### 5.2 CloudFront Invalidation

```bash
# Invalidate specific paths
aws cloudfront create-invalidation \
  --distribution-id E1XAMPLE12345 \
  --paths "/assets/*" "/css/*" "/js/*"

# Invalidate everything (use sparingly — costs more)
aws cloudfront create-invalidation \
  --distribution-id E1XAMPLE12345 \
  --paths "/*"
```

### 5.3 Cloudflare Cache Purge

```bash
# Purge by URL
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"files":["https://cdn.apexmail.ee/assets/style.css"]}'

# Purge everything
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purge_everything":true}'
```

---

## 6. Security Considerations

| Concern | Mitigation |
|---------|------------|
| **Origin exposure** | Restrict ingress to CDN IP ranges only (CloudFront: [AWS IP ranges](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html); Cloudflare: [IP list](https://www.cloudflare.com/ips/)) |
| **Hotlink protection** | Enable referer header check in CDN; block direct S3/GCS URL access |
| **CORS** | Set `Access-Control-Allow-Origin: https://app.apexmail.ee` on CDN responses |
| **TLS** | Enforce TLS 1.2+; redirect HTTP → HTTPS at CDN edge |
| **DDoS** | Enable CDN DDoS protection; set rate limits on origin ingress |
| **Signed URLs** | Use CloudFront signed URLs or Cloudflare Token Authentication for private assets |
