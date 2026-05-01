FROM python:3.12-alpine

WORKDIR /app

COPY clickhouse_exporter.py /usr/local/bin/clickhouse_exporter
RUN chmod 0555 /usr/local/bin/clickhouse_exporter

USER 65532:65532
EXPOSE 9116

ENTRYPOINT ["/usr/local/bin/clickhouse_exporter"]