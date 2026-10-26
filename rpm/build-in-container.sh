#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
mkdir -p /work /build/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
tar -xzf /output/source.tar.gz -C /work
cd /work
arch=$(rpm --eval '%{_arch}')
version=$(awk '/^Version:/ {print $2; exit}' trustiflux.spec)
make create-tarball
cp "/tmp/v${version}.tar.gz" "/tmp/guest-components-v${version}-vendor.tar.gz" /build/SOURCES/
rpmbuild -ba trustiflux.spec --define '_topdir /build' --define 'with_rustup 1' --define 'debug_package %{nil}' --define 'debugsource_package %{nil}'

# Check package metadata and executable dependencies on the actual build platform.
for package in /build/RPMS/"$arch"/*.rpm; do
  test "$(rpm -qp --qf '%{ARCH}' "$package")" = "$arch"
done
dnf install -y /build/RPMS/"$arch"/*.rpm
attestation-agent --version
confidential-data-hub --version
trustiflux-api-server --version
mkdir -p /output/RPMS /output/SRPMS
cp -a /build/RPMS/. /output/RPMS/
cp -a /build/SRPMS/. /output/SRPMS/
