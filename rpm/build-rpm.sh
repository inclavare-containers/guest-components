#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build native RPMs in the target distribution, using the checked-out sources.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
distro=${1:-an23}
arch=$(uname -m)
case "$arch" in
  x86_64|aarch64) ;;
  *) echo "Unsupported native architecture: $arch" >&2; exit 2 ;;
esac
case "$distro" in
  al8) base_image=alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest ;;
  an23) base_image=registry.openanolis.cn/openanolis/anolisos:23.4 ;;
  *) echo "Usage: $0 [al8|an23]" >&2; exit 2 ;;
esac
base_image=${BASE_IMAGE:-$base_image}
output_dir=${OUTPUT_DIR:-$repo_root/rpm-output/$distro/$arch}
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
image=guest-components-rpm-builder:$distro-$arch

# Only tracked paths are included; their current working-tree contents are used.
# This also works in a checkout of a release tag and avoids copying build caches.
(cd "$repo_root" && git ls-files -z | tar --null -T - -czf "$output_dir/source.tar.gz")
docker build --build-arg "BASE_IMAGE=$base_image" -t "$image" "$repo_root/rpm"
docker run --rm \
  -v "$output_dir:/output" \
  -v "guest-components-rpm-registry-$distro-$arch:/opt/cargo/registry" \
  -v "guest-components-rpm-git-$distro-$arch:/opt/cargo/git" \
  -v "guest-components-rpm-target-$distro-$arch:/work/target" \
  "$image"
printf 'RPMs: %s/RPMS/%s/\n' "$output_dir" "$arch"
