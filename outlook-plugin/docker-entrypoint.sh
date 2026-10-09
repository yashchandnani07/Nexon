#!/bin/sh
# docker-entrypoint.sh — generate a self-signed SSL cert on first run if none exists.
# The cert directory can be bind-mounted from the host so a pre-trusted cert is reused.
set -e

CERT_DIR="${HOME}/.office-addin-dev-certs"

if [ ! -f "${CERT_DIR}/localhost.key" ] || [ ! -f "${CERT_DIR}/localhost.crt" ]; then
    echo "[FraudShield Plugin] No SSL certificate found — generating self-signed cert..."
    mkdir -p "${CERT_DIR}"

    # Write an OpenSSL config that includes the SAN extension
    cat > /tmp/ssl.cnf << 'EOF'
[req]
distinguished_name = req_dn
x509_extensions    = v3_req
prompt             = no

[req_dn]
CN = localhost
O  = FraudShield Dev
OU = FraudShield

[v3_req]
keyUsage         = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

    openssl req -x509 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/localhost.key" \
        -out    "${CERT_DIR}/localhost.crt" \
        -days 3650 -nodes \
        -config /tmp/ssl.cnf 2>/dev/null

    rm -f /tmp/ssl.cnf

    echo "[FraudShield Plugin] Certificate created: ${CERT_DIR}/localhost.crt"
    echo ""
    echo "  ⚠  Outlook requires a TRUSTED certificate."
    echo "  To trust this cert on Windows (one-time setup):"
    echo "    docker cp fraudshield_plugin:/root/.office-addin-dev-certs/localhost.crt ."
    echo "    certutil -addstore Root localhost.crt"
    echo ""
else
    echo "[FraudShield Plugin] Using existing certificate from ${CERT_DIR}"
fi

exec "$@"
