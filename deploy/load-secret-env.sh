#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 TARGET_ENV FILE_ENV COMMAND [ARG...]" >&2
    echo "   or: $0 TARGET_ENV FILE_ENV [TARGET_ENV FILE_ENV ...] -- COMMAND [ARG...]" >&2
    exit 64
}

load_secret() {
    target_env="$1"
    file_env="$2"

    eval "secret_file=\${$file_env:-}"
    eval "secret_value=\${$target_env:-}"

    if [ -n "$secret_file" ]; then
        if [ ! -f "$secret_file" ]; then
            echo "ERROR: Secret file for $target_env not found at $secret_file" >&2
            exit 1
        fi
        secret_value="$(tr -d '\r\n' < "$secret_file")"
    fi

    if [ -z "$secret_value" ]; then
        echo "ERROR: Neither $target_env nor $file_env is set" >&2
        exit 1
    fi

    export "$target_env=$secret_value"
    unset "$file_env"
}

if [ "$#" -lt 3 ]; then
    usage
fi

has_delimiter=0
for arg in "$@"; do
    if [ "$arg" = "--" ]; then
        has_delimiter=1
        break
    fi
done

if [ "$has_delimiter" -eq 1 ]; then
    while [ "$1" != "--" ]; do
        if [ "$#" -lt 3 ] || [ "$2" = "--" ]; then
            usage
        fi
        load_secret "$1" "$2"
        shift 2
    done
    shift
    if [ "$#" -lt 1 ]; then
        usage
    fi
else
    load_secret "$1" "$2"
    shift 2
fi

exec "$@"