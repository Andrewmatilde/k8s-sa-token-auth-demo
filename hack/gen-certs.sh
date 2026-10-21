#!/usr/bin/env bash
# Generates a demo CA and a server certificate for internal-api.
# Usage: hack/gen-certs.sh [out-dir] [extra SAN DNS names...]
set -euo pipefail
OUT=${1:-certs}; shift || true
mkdir -p "$OUT"
SANS="DNS:localhost,IP:127.0.0.1,DNS:internal-api,DNS:internal-api.internal-api,DNS:internal-api.internal-api.svc,DNS:internal-api.internal-api.svc.cluster.local"
for n in "$@"; do SANS="$SANS,DNS:$n"; done

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=internal-api-demo-ca" \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=internal-api" \
  -keyout "$OUT/tls.key" -out "$OUT/tls.csr" 2>/dev/null
printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$SANS" > "$OUT/ext.cnf"
openssl x509 -req -in "$OUT/tls.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -extfile "$OUT/ext.cnf" -out "$OUT/tls.crt" 2>/dev/null
rm -f "$OUT/tls.csr" "$OUT/ext.cnf" "$OUT/ca.srl"
echo "wrote $OUT/{ca.crt,ca.key,tls.crt,tls.key}"
