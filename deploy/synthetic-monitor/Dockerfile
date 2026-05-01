FROM python:3.12-alpine

COPY synthetic_probe.py /usr/local/bin/synthetic_probe
RUN chmod 0555 /usr/local/bin/synthetic_probe \
    && addgroup -S -g 65532 synthetic \
    && adduser -S -D -H -u 65532 -G synthetic synthetic

USER 65532:65532
EXPOSE 9128
ENTRYPOINT ["python3", "/usr/local/bin/synthetic_probe"]
