#!/bin/bash
# Waits until host:port ($1, $2) accepts TCP connections, for up to $3
# seconds (default 60): service containers start alongside the steps.
host=$1 port=$2 limit=${3:-60}
for _ in $(seq "$limit"); do
  if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
    exit 0
  fi
  sleep 1
done
echo "$host:$port not reachable after ${limit}s" >&2
exit 1
