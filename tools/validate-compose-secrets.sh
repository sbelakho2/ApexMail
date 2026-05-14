#!/bin/bash
set -euo pipefail

missing=0

for path in \
  secrets/postgres_password.txt \
  secrets/redis_password.txt \
  secrets/clickhouse_password.txt
do
  if [ ! -s "$path" ]; then
    echo "missing required non-empty secret file: $path" >&2
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "create local development secrets before starting Docker Compose" >&2
  exit 1
fi

echo "compose secret validation passed"
