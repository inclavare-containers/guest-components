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

manifest_found=false
for p in rv-release-manifest/*.release-manifest.bundle.json build-output-*/*.release-manifest.bundle.json *.release-manifest.bundle.json; do
  if compgen -G "$p" > /dev/null 2>&1; then
    manifest_found=true
    break
  fi
done
if [ "$manifest_found" = false ]; then
  echo "No RV release manifest bundles found, cannot notify RVDS."
  exit 1
fi

base="https://github.com/${REPO}/releases/download/${TAG}"
urls=()
for f in "${rpm_files[@]}"; do
  fname="$(basename "$f")"
  urls+=("\"${base}/${fname}\"")
done
urls_json="[${urls[*]}]"

manifest_files=()
for p in rv-release-manifest/*.release-manifest.bundle.json build-output-*/*.release-manifest.bundle.json *.release-manifest.bundle.json; do
  if [ -f "$p" ]; then
    manifest_files+=("$p")
  fi
done

manifest_entries=()
for pf in "${manifest_files[@]}"; do
  encoded="$(base64 -w0 "$pf")"
  manifest_entries+=("\"${encoded}\"")
done
manifest_json="[${manifest_entries[*]}]"

# Use jq to safely create the JSON payload file, preventing any formatting or escaping issues
echo '{}' | jq --arg manifests "${manifest_json}" --arg urls "${urls_json}" \
  '.artifact_type = "rpm" | .rv_release_manifest_bundles = ($manifests | fromjson) | .artifacts_download_url = ($urls | fromjson)' > rvds_payload.json

echo "Sending release event to RVDS at ${RVDS_ENDPOINT}"
curl --fail --show-error --silent \
  -H "Content-Type: application/json" \
  -X POST "${RVDS_ENDPOINT%/}/rvds/rv-publish-event" \
  --data "@rvds_payload.json"

