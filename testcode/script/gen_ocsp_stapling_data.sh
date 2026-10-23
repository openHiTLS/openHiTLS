#!/bin/bash
# Regenerates the OCSP stapling test data under
# testcode/testdata/tls/certificate/der/ocsp_stapling/:
#   - certificate chain: root -> inter -> server (EE), plus an OCSP signer
#     certificate that carries the OCSPSigning EKU (the authorized responder).
#   - three signed OCSP responses:
#       ee_ocsp_issuer.der  - CertID for "server", signed by its issuer "inter"
#       ee_ocsp_signer.der  - CertID for "server", signed by the "signer" cert
#       inter_ocsp.der      - CertID for "inter",  signed by the "signer" cert
# Uses OpenSSL to create the certificates and the OCSP responses.
set -e

HITLS_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT_DIR=${HITLS_ROOT}/testcode/testdata/tls/certificate/der/ocsp_stapling
TMP=$(mktemp -d)
trap 'rm -rf ${TMP}' EXIT

OPENSSL=${OPENSSL:-/home/lm/openssl/github/openssl/apps/openssl}
if [ -x "${OPENSSL}" ]; then
    export LD_LIBRARY_PATH=$(dirname "$(dirname "${OPENSSL}")"):${LD_LIBRARY_PATH}
else
    OPENSSL=openssl
fi
if [ -f /etc/ssl/openssl.cnf ]; then
    export OPENSSL_CONF=/etc/ssl/openssl.cnf
fi

DAYS=3650

# EC key helper: $1 = key file (PEM)
gen_ec_key() {
    "${OPENSSL}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" >/dev/null 2>&1
}

# Certificate extensions
cat > "${TMP}/ext.cnf" <<'EOF'
[ inter_ext ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign

[ server_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[ signer_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
EOF

mkdir -p "${OUT_DIR}"

# ---- root CA (self-signed) ----
gen_ec_key "${TMP}/root.key.pem"
"${OPENSSL}" req -new -x509 -key "${TMP}/root.key.pem" -subj "/CN=OCSP Stapling Root CA" -days "${DAYS}" \
    -out "${TMP}/root.pem" >/dev/null 2>&1

# ---- intermediate CA (issued by root) ----
gen_ec_key "${TMP}/inter.key.pem"
"${OPENSSL}" req -new -key "${TMP}/inter.key.pem" -subj "/CN=OCSP Stapling Intermediate CA" -out "${TMP}/inter.csr" \
    >/dev/null 2>&1
"${OPENSSL}" x509 -req -in "${TMP}/inter.csr" -CA "${TMP}/root.pem" -CAkey "${TMP}/root.key.pem" \
    -CAcreateserial -extfile "${TMP}/ext.cnf" -extensions inter_ext -days "${DAYS}" -out "${TMP}/inter.pem" \
    >/dev/null 2>&1

# ---- server (EE, issued by inter) ----
gen_ec_key "${TMP}/server.key.pem"
"${OPENSSL}" req -new -key "${TMP}/server.key.pem" -subj "/CN=ocsp-stapling-server" -out "${TMP}/server.csr" \
    >/dev/null 2>&1
"${OPENSSL}" x509 -req -in "${TMP}/server.csr" -CA "${TMP}/inter.pem" -CAkey "${TMP}/inter.key.pem" \
    -CAcreateserial -extfile "${TMP}/ext.cnf" -extensions server_ext -days "${DAYS}" -out "${TMP}/server.pem" \
    >/dev/null 2>&1

# ---- OCSP signer (issued by inter, carries OCSPSigning EKU) ----
gen_ec_key "${TMP}/signer.key.pem"
"${OPENSSL}" req -new -key "${TMP}/signer.key.pem" -subj "/CN=OCSP Stapling Signer" -out "${TMP}/signer.csr" \
    >/dev/null 2>&1
"${OPENSSL}" x509 -req -in "${TMP}/signer.csr" -CA "${TMP}/inter.pem" -CAkey "${TMP}/inter.key.pem" \
    -CAcreateserial -extfile "${TMP}/ext.cnf" -extensions signer_ext -days "${DAYS}" -out "${TMP}/signer.pem" \
    >/dev/null 2>&1

# ---- RSA server (EE, issued by inter) for RSA-key-exchange tests ----
"${OPENSSL}" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${TMP}/rsa_server.key.pem" >/dev/null 2>&1
"${OPENSSL}" req -new -key "${TMP}/rsa_server.key.pem" -subj "/CN=ocsp-stapling-rsa-server" \
    -out "${TMP}/rsa_server.csr" >/dev/null 2>&1
"${OPENSSL}" x509 -req -in "${TMP}/rsa_server.csr" -CA "${TMP}/inter.pem" -CAkey "${TMP}/inter.key.pem" \
    -CAcreateserial -extfile "${TMP}/ext.cnf" -extensions server_ext -days "${DAYS}" -out "${TMP}/rsa_server.pem" \
    >/dev/null 2>&1

# ---- OCSP responses ----
# index rows (OpenSSL CA_DB): type exp_date rev_date serial file name
server_serial=$("${OPENSSL}" x509 -in "${TMP}/server.pem" -noout -serial | cut -d= -f2)
inter_serial=$("${OPENSSL}" x509 -in "${TMP}/inter.pem" -noout -serial | cut -d= -f2)
printf 'V\t260101000000Z\t\t%s\t\t/CN=server\n' "${server_serial}" > "${TMP}/server.index"
printf 'V\t260101000000Z\t\t%s\t\t/CN=inter\n' "${inter_serial}" > "${TMP}/inter.index"

# CertID for "server" (issuer = inter), signed by its issuer (CA as responder).
"${OPENSSL}" ocsp -index "${TMP}/server.index" -rsigner "${TMP}/inter.pem" -rkey "${TMP}/inter.key.pem" \
    -CA "${TMP}/root.pem" -issuer "${TMP}/inter.pem" -cert "${TMP}/server.pem" \
    -respout "${TMP}/ee_ocsp_issuer.der" -no_nonce >/dev/null 2>&1
# CertID for "server" (issuer = inter), signed by the OCSPSigning signer.
"${OPENSSL}" ocsp -index "${TMP}/server.index" -rsigner "${TMP}/signer.pem" -rkey "${TMP}/signer.key.pem" \
    -CA "${TMP}/root.pem" -issuer "${TMP}/inter.pem" -cert "${TMP}/server.pem" \
    -respout "${TMP}/ee_ocsp_signer.der" -no_nonce >/dev/null 2>&1
# CertID for "inter" (issuer = root), signed by the OCSPSigning signer.
"${OPENSSL}" ocsp -index "${TMP}/inter.index" -rsigner "${TMP}/signer.pem" -rkey "${TMP}/signer.key.pem" \
    -CA "${TMP}/root.pem" -issuer "${TMP}/root.pem" -cert "${TMP}/inter.pem" \
    -respout "${TMP}/inter_ocsp.der" -no_nonce >/dev/null 2>&1
# CertID for "rsa_server" (issuer = inter), signed by the OCSPSigning signer.
rsa_server_serial=$("${OPENSSL}" x509 -in "${TMP}/rsa_server.pem" -noout -serial | cut -d= -f2)
printf 'V\t260101000000Z\t\t%s\t\t/CN=rsa_server\n' "${rsa_server_serial}" > "${TMP}/rsa_server.index"
"${OPENSSL}" ocsp -index "${TMP}/rsa_server.index" -rsigner "${TMP}/signer.pem" -rkey "${TMP}/signer.key.pem" \
    -CA "${TMP}/root.pem" -issuer "${TMP}/inter.pem" -cert "${TMP}/rsa_server.pem" \
    -respout "${TMP}/rsa_ee_ocsp.der" -no_nonce >/dev/null 2>&1

# ---- export DER ----
for name in root inter server signer rsa_server; do
    "${OPENSSL}" x509 -in "${TMP}/${name}.pem" -outform DER -out "${OUT_DIR}/${name}.der"
    "${OPENSSL}" pkcs8 -topk8 -nocrypt -in "${TMP}/${name}.key.pem" -outform DER \
        -out "${OUT_DIR}/${name}.key.der" >/dev/null 2>&1
done
cp "${TMP}/ee_ocsp_issuer.der" "${TMP}/ee_ocsp_signer.der" "${TMP}/inter_ocsp.der" "${TMP}/rsa_ee_ocsp.der" "${OUT_DIR}/"

echo "generated OCSP stapling test data in ${OUT_DIR}:"
ls -l "${OUT_DIR}"
