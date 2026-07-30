# Stage 1: Build
FROM nginx:1.27-alpine AS runtime

LABEL org.opencontainers.image.title="ApexMail Status Page"
LABEL org.opencontainers.image.description="Independently hosted ApexMail service status page"
LABEL org.opencontainers.image.version="1.0.0"

RUN apk add --no-cache curl jq openssl bash tzdata

COPY status_page.html /usr/share/nginx/html/index.html
COPY check_services.sh /usr/local/bin/check_services.sh
COPY nginx.status.conf /etc/nginx/conf.d/default.conf
COPY healthcheck.sh /usr/local/bin/healthcheck.sh

RUN chmod +x /usr/local/bin/check_services.sh /usr/local/bin/healthcheck.sh

RUN echo '*/1 * * * * /usr/local/bin/check_services.sh > /usr/share/nginx/html/data.json 2>/var/log/check_services.err' > /etc/crontabs/root

HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD /usr/local/bin/healthcheck.sh

EXPOSE 8080

CMD ["sh", "-c", "crond && nginx -g 'daemon off;'"]
