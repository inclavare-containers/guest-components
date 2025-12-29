#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

cd rpm-provenance

for bundle in *.intoto.jsonl; do
  echo "Processing provenance bundle: ${bundle}"

  # Extract DSSE envelope from the Sigstore bundle (support both v0.3+ layouts)
  jq '.dsseEnvelope // .content.dsseEnvelope' "${bundle}" > dsse-envelope.json

  # Extract signing certificate (leaf cert) and convert to PEM.
  # Prefer top-level certificate.rawBytes; fall back to x509CertificateChain[0].rawBytes if present.
  jq -r '.verificationMaterial.certificate.rawBytes // .verificationMaterial.x509CertificateChain.certificates[0].rawBytes' "${bundle}" | base64 -d > cert.der
  openssl x509 -inform DER -in cert.der -out cert.pem

  # Upload an intoto entry which, when attestation storage is enabled on Rekor,
  # stores the decoded DSSE payload bytes.
  rekor-cli upload \
    --rekor_server "${REKOR_URL}" \
    --type intoto \
    --public-key cert.pem \
    --artifact dsse-envelope.json

  rm -f dsse-envelope.json cert.der cert.pem
done

