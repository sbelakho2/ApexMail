#!/bin/sh
set -eu
umask 077

if [ -u "$0" ] || [ -g "$0" ]; then
    echo "ERROR: Refusing to run with setuid/setgid permissions: $0" >&2
    exit 126
fi

usage() {
    echo "Usage: $0 TARGET_ENV FILE_ENV COMMAND [ARG...]" >&2
    echo "   or: $0 TARGET_ENV FILE_ENV [TARGET_ENV FILE_ENV ...] -- COMMAND [ARG...]" >&2
    exit 64
}

validate_env_name() {
    case "$1" in
        ''|[0-9]*|*[!A-Za-z0-9_]* )
            echo "ERROR: Invalid environment variable name: $1" >&2
            exit 64
            ;;
    esac
}

lookup_env() {
    validate_env_name "$1"
    printenv "$1" 2>/dev/null || true
}

load_secret() {
    target_env="$1"
    file_env="$2"

    secret_file="$(lookup_env "$file_env")"
    secret_value="$(lookup_env "$target_env")"

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