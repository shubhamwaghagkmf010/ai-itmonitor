#!/bin/sh
# Generates (idempotently) a private internal Certificate Authority and a server
# certificate for this deployment, using only OpenSSL (free, open source, already
# installed everywhere). Re-running is safe - it only (re)creates what is missing
# unless --force is passed.
#
# Why a private CA at all: no public CA (free or paid) will ever issue a browser-
# trusted certificate for a private IP address (e.g. 192.168.1.0) - that is a
# cryptographic/policy fact, not a product limitation. So for IP-based access we
# run our own tiny CA and have each endpoint (agent-managed PCs) trust its single
# root certificate, which the agent installer does automatically. Browsers/PCs
# that never ran the agent will still see a one-time trust warning for the IP
# unless the root cert (certs/ca/ca.crt) is imported there too.
#
# When a real public domain is ready, re-run with DOMAIN=yourdomain.example set -
# it adds the domain as an extra name on the SAME server certificate so both the
# IP and the domain work during transition; the final, publicly-trusted cert for
# the domain itself should come from Let's Encrypt (DNS-01), wired separately.
#
# Usage:
#   SERVER_IP=<this-machine-ip> ./scripts/setup_tls.sh   # REQUIRED - see below
#   SERVER_IP=1.2.3.4 ./scripts/setup_tls.sh     # different IP
#   DOMAIN=monitor.example.com ./scripts/setup_tls.sh   # also add a domain SAN
#   ./scripts/setup_tls.sh --force               # regenerate the server cert now

set -e

SERVER_IP="${SERVER_IP:?Set SERVER_IP to this machine's real IP, e.g. SERVER_IP=192.168.1.0 sh scripts/setup_tls.sh}"
DOMAIN="${DOMAIN:-}"
FORCE=0
for arg in "$@"; do
  if [ "$arg" = "--force" ]; then FORCE=1; fi
done

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CA_DIR="$ROOT_DIR/certs/ca"
SRV_DIR="$ROOT_DIR/certs/server"
mkdir -p "$CA_DIR" "$SRV_DIR"

# --- 1) Root CA (created once; reused forever unless deleted) -----------------
if [ ! -f "$CA_DIR/ca.key" ] || [ ! -f "$CA_DIR/ca.crt" ]; then
  echo "[*] Generating a new internal root CA (one-time)..."
  openssl genrsa -out "$CA_DIR/ca.key" 4096
  openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 3650 \
    -subj "/O=AI-ITMonitor/CN=AI-ITMonitor Internal Root CA" \
    -out "$CA_DIR/ca.crt"
  chmod 600 "$CA_DIR/ca.key"
  echo "[*] Root CA created: $CA_DIR/ca.crt (public, safe to distribute)"
  echo "[*] Root CA key:     $CA_DIR/ca.key  (PRIVATE - never commit, never share)"
else
  echo "[*] Root CA already exists - reusing $CA_DIR/ca.crt"
fi

# --- 2) Server certificate for this deployment (IP, +optional domain) ---------
if [ -f "$SRV_DIR/server.crt" ] && [ "$FORCE" -ne 1 ]; then
  echo "[*] Server certificate already exists - pass --force to regenerate."
  echo "    (Do this whenever SERVER_IP/DOMAIN changes.)"
  exit 0
fi

SAN="IP:${SERVER_IP},DNS:localhost"
if [ -n "$DOMAIN" ]; then
  SAN="${SAN},DNS:${DOMAIN}"
fi
echo "[*] Issuing server certificate for SAN: $SAN"

openssl genrsa -out "$SRV_DIR/server.key" 2048
openssl req -new -key "$SRV_DIR/server.key" \
  -subj "/O=AI-ITMonitor/CN=${SERVER_IP}" \
  -out "$SRV_DIR/server.csr"

cat > "$SRV_DIR/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${SAN}
EOF

openssl x509 -req -in "$SRV_DIR/server.csr" \
  -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
  -days 825 -sha256 -extfile "$SRV_DIR/server.ext" \
  -out "$SRV_DIR/server.crt"

rm -f "$SRV_DIR/server.csr" "$SRV_DIR/server.ext"
chmod 600 "$SRV_DIR/server.key"

echo "[*] Server certificate issued: $SRV_DIR/server.crt (valid 825 days)"
echo "[*] Restart nginx (docker compose up -d --force-recreate frontend) to pick it up."
