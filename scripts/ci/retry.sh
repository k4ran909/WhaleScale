#!/bin/sh
# Runs a command, retrying up to three more times with growing pauses:
# module, tool and package downloads fail now and then on transient
# network errors (e.g. sum.golang.org resetting HTTP/2 streams).
n=1
until "$@"; do
  if [ "$n" -ge 4 ]; then
    echo "failed after $n attempts: $*" >&2
    exit 1
  fi
  echo "attempt $n failed; retrying in $((n * 10))s: $*" >&2
  sleep $((n * 10))
  n=$((n + 1))
done
