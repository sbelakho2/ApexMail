#!/bin/sh
set -e

if [ -f /usr/share/nginx/html/data.json ]; then
    AGE=$(($(date +%s) - $(stat -c %Y /usr/share/nginx/html/data.json 2>/dev/null || echo 0)))
    if [ "$AGE" -lt 120 ]; then
        exit 0
    fi
fi

curl -sf http://localhost:8080/health > /dev/null 2>&1
