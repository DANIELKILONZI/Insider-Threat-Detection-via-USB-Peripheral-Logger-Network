#!/usr/bin/env bash
# deploy/gen_certs.sh – Generate the mTLS PKI for ITDN
#
# Creates:
#   ca.crt / ca.key              – Root CA (sign everything)
#   server.crt / server.key      – Server certificate (signed by CA)
#   agent-<name>.crt / .key      – One certificate per agent hostname
#
# Usage:
#   chmod +x deploy/gen_certs.sh
#   ./deploy/gen_certs.sh                         # server + one agent ("agent-01")
#   ./deploy/gen_certs.sh agent-laptop agent-ws2  # extra agents
#
# Requirements: openssl ≥ 1.1.1
# Output directory: ./certs/  (created if absent)

set -euo pipefail

CERTS_DIR="${CERTS_DIR:-./certs}"
CA_SUBJECT="${CA_SUBJECT:-/C=US/ST=Security/O=ITDN/CN=ITDN-CA}"
SERVER_CN="${SERVER_CN:-siem.internal}"
DAYS_CA=3650    # 10 years for the root CA
DAYS_LEAF=825   # 2.25 years for leaf certs (Apple/browser compatibility)

mkdir -p "$CERTS_DIR"

# ─── Helper ───────────────────────────────────────────────────────────────────

gen_leaf() {
  local name="$1"
  local cn="$2"
  local ext_san="$3"    # optional SAN extension line

  echo "  → Generating leaf cert: ${name}"

  # Key
  openssl genrsa -out "${CERTS_DIR}/${name}.key" 4096 2>/dev/null

  # CSR
  openssl req -new \
    -key  "${CERTS_DIR}/${name}.key" \
    -subj "/C=US/ST=Security/O=ITDN/CN=${cn}" \
    -out  "${CERTS_DIR}/${name}.csr" 2>/dev/null

  # Extension file (subjectAltName is required by modern TLS stacks)
  local ext_file
  ext_file="$(mktemp)"
  cat > "$ext_file" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = ${ext_san:-DNS:${cn}}
EOF

  # Sign with CA
  openssl x509 -req \
    -in   "${CERTS_DIR}/${name}.csr" \
    -CA   "${CERTS_DIR}/ca.crt" \
    -CAkey "${CERTS_DIR}/ca.key" \
    -CAcreateserial \
    -days "$DAYS_LEAF" \
    -extfile "$ext_file" \
    -out  "${CERTS_DIR}/${name}.crt" 2>/dev/null

  rm -f "$ext_file" "${CERTS_DIR}/${name}.csr"
  echo "    ${CERTS_DIR}/${name}.crt  +  ${CERTS_DIR}/${name}.key"
}

# ─── 1. Root CA ───────────────────────────────────────────────────────────────

if [[ -f "${CERTS_DIR}/ca.crt" ]]; then
  echo "[SKIP] CA already exists at ${CERTS_DIR}/ca.crt – delete it to regenerate"
else
  echo "[1/3] Generating Root CA …"
  openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -nodes \
    -key  "${CERTS_DIR}/ca.key" \
    -subj "$CA_SUBJECT" \
    -days "$DAYS_CA" \
    -extensions v3_ca \
    -out  "${CERTS_DIR}/ca.crt" 2>/dev/null
  echo "  → ${CERTS_DIR}/ca.crt  +  ${CERTS_DIR}/ca.key"
fi

# ─── 2. Server certificate ────────────────────────────────────────────────────

echo "[2/3] Generating server certificate (CN=${SERVER_CN}) …"
gen_leaf "server" "$SERVER_CN" "DNS:${SERVER_CN},DNS:localhost,IP:127.0.0.1"

# ─── 3. Agent certificates ────────────────────────────────────────────────────

# Default agents if none provided on command line
AGENTS=("${@:-agent-01}")

echo "[3/3] Generating agent certificates …"
for agent in "${AGENTS[@]}"; do
  gen_leaf "$agent" "$agent" "DNS:${agent}"
done

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "Done! Certificates written to ${CERTS_DIR}/"
echo ""
echo "Server deployment:"
echo "  Copy ${CERTS_DIR}/ca.crt      → /etc/itdn/ca.crt        (CA cert)"
echo "  Copy ${CERTS_DIR}/server.crt  → /etc/itdn/server.crt    (server cert)"
echo "  Copy ${CERTS_DIR}/server.key  → /etc/itdn/server.key    (server key)"
echo ""
echo "Per-agent deployment (example for agent-01):"
echo "  Copy ${CERTS_DIR}/ca.crt         → /etc/itdn/siem-ca.crt   (trust anchor)"
echo "  Copy ${CERTS_DIR}/agent-01.crt   → /etc/itdn/agent.crt     (client cert)"
echo "  Copy ${CERTS_DIR}/agent-01.key   → /etc/itdn/agent.key     (client key)"
echo ""
echo "  Set env: ITDN_SERVER_CERT=/etc/itdn/siem-ca.crt"
echo "           ITDN_AGENT_CERT=/etc/itdn/agent.crt"
echo "           ITDN_AGENT_KEY=/etc/itdn/agent.key"
