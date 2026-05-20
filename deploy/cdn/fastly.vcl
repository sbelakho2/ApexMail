# =============================================================================
# ApexMail — Fastly VCL Configuration (SCALE-H-05)
# =============================================================================
# Fastly CDN configuration for serving ApexMail static assets from edge
# locations. This VCL handles:
#   - Static asset caching with appropriate TTLs
#   - API request forwarding (no caching)
#   - Security headers
#   - Gzip/Brotli compression
#   - Stale-while-revalidate for HTML pages
#
# Usage:
#   Upload this VCL to your Fastly service via the Fastly UI or CLI:
#     fastly vcl upload --service-id=$FASTLY_SERVICE_ID --version=active \
#       --name=apexmail-cdn --file=deploy/cdn/fastly.vcl
# =============================================================================

# ── ACLs ──────────────────────────────────────────────────────────────────────
# Define allowed purge IPs (your CI/CD servers and admin IPs)
# acl purge_ips {
#     "10.0.0.0/8";
#     "172.16.0.0/12";
# }

# ── Backend Definition ───────────────────────────────────────────────────────
# backend ApexMailOrigin {
#     .host = "api.apexmail.ee";
#     .port = "443";
#     .ssl = 1;
#     .ssl_cert_hostname = "api.apexmail.ee";
#     .ssl_check_cert = 1;
#     .between_bytes_timeout = 10s;
#     .connect_timeout = 5s;
#     .first_byte_timeout = 15s;
#     .max_connections = 200;
# }

# ── vcl_recv: Request Processing ─────────────────────────────────────────────
sub vcl_recv {
    # Force HTTPS
    if (req.method != "PURGE" && fastly_info.visits_this_service == 0 && req.http.Fastly-SSL != "true") {
        error 801 "Force TLS";
    }

    # Allow PURGE from authorized IPs only
    if (req.method == "PURGE") {
        # acl purge_ips ~ client.ip
        return (pass);
    }

    # ── API endpoints: bypass cache entirely ──────────────────────────────
    if (req.url ~ "^/v1/" || req.url ~ "^/t/" || req.url ~ "^/api/enterprise/") {
        return (pass);
    }

    # ── Static assets: strip cookies for better cache hit ratio ───────────
    if (req.url ~ "^/assets/" || req.url ~ "^/fonts/" || req.url ~ "^/images/") {
        unset req.http.Cookie;
    }

    # ── Enable compression ────────────────────────────────────────────────
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(css|js|html|json|xml|svg|txt)$") {
            if (req.http.Accept-Encoding ~ "br") {
                set req.http.Accept-Encoding = "br";
            } elsif (req.http.Accept-Encoding ~ "gzip") {
                set req.http.Accept-Encoding = "gzip";
            }
        }
    }

    # ── Health checks: don't cache ────────────────────────────────────────
    if (req.url ~ "^/health" || req.url ~ "^/v1/health") {
        return (pass);
    }

    return (lookup);
}

# ── vcl_fetch: Backend Response Processing ───────────────────────────────────
sub vcl_fetch {
    # ── Static assets: long-lived cache ───────────────────────────────────
    if (req.url ~ "^/assets/") {
        set beresp.ttl = 365d;
        set beresp.grace = 1d;
        set beresp.cacheable = true;
        unset beresp.http.Set-Cookie;
        return (deliver);
    }

    if (req.url ~ "^/fonts/" || req.url ~ "^/images/") {
        set beresp.ttl = 7d;
        set beresp.grace = 1d;
        set beresp.cacheable = true;
        unset beresp.http.Set-Cookie;
        return (deliver);
    }

    # ── CSS/JS: medium cache ──────────────────────────────────────────────
    if (req.url ~ "\.(css|js)$") {
        set beresp.ttl = 1d;
        set beresp.grace = 1h;
        set beresp.cacheable = true;
        unset beresp.http.Set-Cookie;
        return (deliver);
    }

    # ── HTML pages: short cache with stale-while-revalidate ───────────────
    if (beresp.http.Content-Type ~ "text/html") {
        set beresp.ttl = 5m;
        set beresp.grace = 10m;
        set beresp.stale_if_error = 1h;
        return (deliver);
    }

    # ── API responses: do not cache ───────────────────────────────────────
    if (req.url ~ "^/v1/" || req.url ~ "^/t/" || req.url ~ "^/api/enterprise/") {
        set beresp.ttl = 0s;
        set beresp.cacheable = false;
        return (pass);
    }

    # ── Default: 1 hour cache ─────────────────────────────────────────────
    set beresp.ttl = 1h;
    set beresp.grace = 30m;
    return (deliver);
}

# ── vcl_deliver: Response Modification ───────────────────────────────────────
sub vcl_deliver {
    # ── Security Headers ──────────────────────────────────────────────────
    set resp.http.Strict-Transport-Security = "max-age=63072000; includeSubDomains; preload";
    set resp.http.X-Content-Type-Options = "nosniff";
    set resp.http.X-Frame-Options = "DENY";
    set resp.http.Referrer-Policy = "strict-origin-when-cross-origin";
    set resp.http.Permissions-Policy = "camera=(), microphone=(), geolocation=(), payment=()";

    # ── Cache hit/miss header (useful for debugging) ──────────────────────
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }

    # ── Remove server identification ──────────────────────────────────────
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Fastly-Request-ID;

    return (deliver);
}

# ── vcl_error: Custom Error Pages ────────────────────────────────────────────
sub vcl_error {
    if (obj.status == 801) {
        set obj.status = 301;
        set obj.response = "Moved Permanently";
        set obj.http.Location = "https://" req.http.host req.url;
        return (deliver);
    }

    # Custom 503 page
    if (obj.status == 503) {
        set obj.response = "Service Temporarily Unavailable";
        synthetic {"
            <!DOCTYPE html>
            <html>
            <head><title>ApexMail — Temporarily Unavailable</title></head>
            <body style="font-family:sans-serif;text-align:center;padding:50px">
                <h1>Temporarily Unavailable</h1>
                <p>We're experiencing a brief interruption. Please try again in a moment.</p>
            </body>
            </html>
        "};
        return (deliver);
    }
}
