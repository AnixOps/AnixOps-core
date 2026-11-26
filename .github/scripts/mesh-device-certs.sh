#!/usr/bin/env bash
# Makes a private CA and a server certificate for "localhost" signed by it,
# for the device service smoke test (mesh-device-mock-control.py):
#   DIR/ca.pem, DIR/leaf.pem, DIR/leaf.key
# The device trusts only DIR/ca.pem (--ca-file), as with a panel behind a
# private CA. Uses the openssl on the runner (LibreSSL on macOS, Git's on
# Windows).
#
#   mesh-device-certs.sh DIR

set -euo pipefail

dir="${1:?usage: $0 DIR}"
mkdir -p "${dir}"
# Git's openssl on Windows would turn "/CN=…" into a Windows path.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

cat > "${dir}/openssl.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = placeholder
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
authorityKeyIdentifier = keyid
CNF

openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 2 \
  -subj "/CN=anixops-mesh-ci-ca" -config "${dir}/openssl.cnf" -extensions ca \
  -keyout "${dir}/ca.key" -out "${dir}/ca.pem"
openssl req -new -nodes -newkey rsa:2048 -sha256 \
  -subj "/CN=localhost" -config "${dir}/openssl.cnf" \
  -keyout "${dir}/leaf.key" -out "${dir}/leaf.csr"
openssl x509 -req -sha256 -days 2 -in "${dir}/leaf.csr" \
  -CA "${dir}/ca.pem" -CAkey "${dir}/ca.key" -CAcreateserial \
  -extfile "${dir}/openssl.cnf" -extensions leaf -out "${dir}/leaf.pem"
rm -f "${dir}/ca.key" "${dir}/leaf.csr"
