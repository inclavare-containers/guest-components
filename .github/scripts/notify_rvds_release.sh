#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

rpm_files=()
for dir in build-output-*/RPMS/*/*.rpm build-output-*/SRPMS/*.src.rpm; do
  rpm_files+=("$dir")
done
if [ ${#rpm_files[@]} -eq 0 ]; then
  echo "No RPM artifacts found, skip notifying RVDS."
  exit 0
fi

prov_found=false
for p in build-output-*/*.intoto.jsonl *.intoto.jsonl; do
  if compgen -G "$p" > /dev/null 2>&1; then
    prov_found=true
    break
  fi
done
if [ "$prov_found" = false ]; then
  echo "No provenance bundles found, cannot notify RVDS."
  exit 1
fi

base="https://github.com/${REPO}/releases/download/${TAG}"
urls=()
for f in "${rpm_files[@]}"; do
  fname="$(basename "$f")"
  urls+=("\"${base}/${fname}\"")
done
urls_json="[${urls[*]}]"

prov_files=()
for p in build-output-*/*.intoto.jsonl *.intoto.jsonl; do
  if [ -f "$p" ]; then
    prov_files+=("$p")
  fi
done

slsa_entries=()
for pf in "${prov_files[@]}"; do
  encoded="$(base64 -w0 "$pf")"
  slsa_entries+=("\"${encoded}\"")
done
slsa_json="[${slsa_entries[*]}]"

# Use jq to safely create the JSON payload file, preventing any formatting or escaping issues
echo '{}' | jq --arg slsa "${slsa_json}" --arg urls "${urls_json}" \
  '.artifact_type = "rpm" | .slsa_provenance = ($slsa | fromjson) | .artifacts_download_url = ($urls | fromjson)' > rvds_payload.json

echo "Sending release event to RVDS at ${RVDS_ENDPOINT}"
curl --fail --show-error --silent \
  -H "Content-Type: application/json" \
  -X POST "${RVDS_ENDPOINT%/}/rvds/rv-publish-event" \
  --data "@rvds_payload.json"

