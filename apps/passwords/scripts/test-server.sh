#!/usr/bin/env bash
# A throwaway Vaultwarden for the core's integration tests, on https://127.0.0.1:8087.
#
#   apps/passwords/scripts/test-server.sh start|stop|reset
#
# Data, a test CA and the server certificate live in target/vaultwarden-test/ (removed
# by `reset`). Only loopback is bound. Then run the tests with:
#
#   NIXE_PW_TEST_SERVER=https://127.0.0.1:8087 \
#   NIXE_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
#     cargo test -p nixe-passwords-core -- --ignored --nocapture
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
dir="$root/target/vaultwarden-test"
name=nixe-vw-test
image=vaultwarden/server:1.37.4

certs() {
  [[ -f $dir/ca.pem && -f $dir/data/cert.pem ]] && return
  mkdir -p "$dir/data"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=nixe-passwords test CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
    -keyout "$dir/ca-key.pem" -out "$dir/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj /CN=127.0.0.1 \
    -keyout "$dir/data/key.pem" -out "$dir/leaf.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >"$dir/leaf.ext"
  openssl x509 -req -in "$dir/leaf.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca-key.pem" \
    -CAcreateserial -days 365 -extfile "$dir/leaf.ext" -out "$dir/data/cert.pem" 2>/dev/null
}

start() {
  certs
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --user "$(id -u):$(id -g)" -p 127.0.0.1:8087:8080 \
    -v "$dir/data:/data" \
    -e ROCKET_PORT=8080 -e 'ROCKET_TLS={certs="/data/cert.pem",key="/data/key.pem"}' \
    -e DOMAIN=https://127.0.0.1:8087 -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
    -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=1000 \
    -e UNAUTHENTICATED_RATELIMIT_SECONDS=1 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
    "$image" >/dev/null
  for _ in $(seq 30); do
    curl -sf --cacert "$dir/ca.pem" https://127.0.0.1:8087/alive >/dev/null && { echo "running on https://127.0.0.1:8087"; return; }
    sleep 1
  done
  echo "Vaultwarden didn't start; see: docker logs $name" >&2
  exit 1
}

case ${1:-start} in
  start) start ;;
  stop) docker rm -f "$name" >/dev/null 2>&1 || true ;;
  reset) docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$dir" ;;
  *) echo "usage: $0 start|stop|reset" >&2; exit 2 ;;
esac
