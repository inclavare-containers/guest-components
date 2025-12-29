#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

RPM_ROOT="${RPM_ROOT:-.}"

mkdir -p rpm-provenance

# Search for RPMs under RPM_ROOT, matching typical rpmbuild layout */RPMS/*/*.rpm.
mapfile -t rpms < <(find "$RPM_ROOT" -type f -path "*/RPMS/*/*.rpm" -print | sort)
if [ ${#rpms[@]} -eq 0 ]; then
  echo "No RPMs found under $RPM_ROOT (pattern */RPMS/*/*.rpm)" >&2
  exit 1
fi

for rpm in "${rpms[@]}"; do
  echo "Processing RPM: $rpm"

  workdir="$(mktemp -d)"
  # Extract RPM contents into temporary directory.
  rpm2cpio "$rpm" | (cd "$workdir" && cpio -idmv >/dev/null 2>&1)

  subjects_txt="$workdir/subjects.txt"
  : > "$subjects_txt"

  pushd "$workdir" >/dev/null
  # Generate sha256 for each file inside the RPM.
  # Subject name format: "<absolute-path-inside-rpm>"
  while IFS= read -r -d '' f; do
    rel="${f#./}"
    sha="$(sha256sum "$f" | awk '{print $1}')"
    echo "$sha  /$rel" >> "$subjects_txt"
  done < <(find . -type f -print0 | sort -z)
  popd >/dev/null

  # Additionally, generate a "name index hash" for the RPM package itself.
  # Key name: "package-name"
  # Key value: Hash("<package-basename>"), e.g. "attestation-agent-1.4.5-1.an23.x86_64.rpm".
  # We reuse sha256 here and compute it over the exact package basename string.
  pkg_name="${rpm##*/}"
  pkg_hash="$(printf "%s" "$pkg_name" | sha256sum | awk '{print $1}')"
  echo "$pkg_hash  package-name" >> "$subjects_txt"

  if [ ! -s "$subjects_txt" ]; then
    echo "No files found inside $rpm, skipping." >&2
    rm -rf "$workdir"
    continue
  fi

  subjects_b64_file="subjects.sha256sum.base64"
  base64 -w0 "$subjects_txt" > "$subjects_b64_file"

  rpm_base="$(basename "$rpm")"
  prov_name="rpm-provenance/${rpm_base}.files.intoto.jsonl"

  "$GITHUB_WORKSPACE/$BUILDER_BINARY" attest \
    --subjects-filename "$subjects_b64_file" \
    -g "$prov_name"

  rm -rf "$workdir"
done

ls -l rpm-provenance

