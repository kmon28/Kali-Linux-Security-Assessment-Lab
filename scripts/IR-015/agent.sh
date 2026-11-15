#!/usr/bin/env bash
# IR-015 harmless simulation agent. Never connects to a network endpoint.
# Newly authored portfolio example; not a byte-for-byte copy of the VM original.
set -eu
out="${HOME}/IR015/evidence/agent.log"
mkdir -p "$(dirname "$out")"
while :; do
  printf '%s IR015 simulated agent running\n' "$(date -Is)" >> "$out"
  sleep 10
done
