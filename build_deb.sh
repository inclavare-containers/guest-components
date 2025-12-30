#!/bin/bash
set -e

VERSION="1.4.6"
RELEASE="1"
PKGBASE="trustiflux"
ARCH="amd64"

ROOT=$(pwd)

#######################################
# 1. Build Rust binaries
#######################################
echo "[1] Building Rust binaries..."

OPENSSL_NO_VENDOR=1 cargo build -p attestation-agent --bin ttrpc-aa --release \
  --no-default-features --features bin,ttrpc,rust-crypto,coco_as,kbs,system-attester,instance_info,csv-attester,hygon-dcu-attester \
  --target x86_64-unknown-linux-gnu

cargo build -p attestation-agent --bin ttrpc-aa-client --release \
  --no-default-features --features bin,ttrpc,eventlog \
  --target x86_64-unknown-linux-gnu

cargo build -p confidential-data-hub --release --bin cdh-oneshot \
  --no-default-features --features bin,aliyun,kbs \
  --target x86_64-unknown-linux-gnu


#######################################
# 2. Create attestation-agent package layout
#######################################
echo "[2] Building attestation-agent .deb package..."

PKGDIR=attestation-agent_${VERSION}-${RELEASE}_${ARCH}
rm -rf $PKGDIR
mkdir -p $PKGDIR/DEBIAN

mkdir -p $PKGDIR/usr/bin
mkdir -p $PKGDIR/etc/trustiflux
mkdir -p $PKGDIR/lib/systemd/system
mkdir -p $PKGDIR/usr/lib/dracut/modules.d/99attestation-agent

install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa $PKGDIR/usr/bin/attestation-agent
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa-client $PKGDIR/usr/bin/attestation-agent-client
install -m 644 dist/rpm/attestation-agent.toml $PKGDIR/etc/trustiflux/
install -m 644 dist/rpm/attestation-agent.service $PKGDIR/lib/systemd/system/

install -m 755 dist/dracut/modules.d/99attestation-agent/module-setup.sh $PKGDIR/usr/lib/dracut/modules.d/99attestation-agent/
install -m 644 dist/dracut/modules.d/99attestation-agent/* $PKGDIR/usr/lib/dracut/modules.d/99attestation-agent/ || true

cat > $PKGDIR/DEBIAN/control <<EOF
Package: attestation-agent
Version: ${VERSION}-${RELEASE}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: YOU <you@example.com>
Description: Attestation Agent running inside TEE.
EOF


#######################################
# 3. Create confidential-data-hub package layout
#######################################
echo "[3] Building confidential-data-hub .deb package..."

PKGDIR2=confidential-data-hub_${VERSION}-${RELEASE}_${ARCH}
rm -rf $PKGDIR2
mkdir -p $PKGDIR2/DEBIAN

mkdir -p $PKGDIR2/usr/bin
mkdir -p $PKGDIR2/etc/trustiflux
mkdir -p $PKGDIR2/usr/lib/dracut/modules.d/99confidential-data-hub

install -m 755 target/x86_64-unknown-linux-gnu/release/cdh-oneshot $PKGDIR2/usr/bin/confidential-data-hub
install -m 644 dist/rpm/confidential-data-hub.toml $PKGDIR2/etc/trustiflux/
install -m 755 dist/dracut/modules.d/99confidential-data-hub/module-setup.sh $PKGDIR2/usr/lib/dracut/modules.d/99confidential-data-hub/
install -m 644 dist/dracut/modules.d/99confidential-data-hub/* $PKGDIR2/usr/lib/dracut/modules.d/99confidential-data-hub/ || true

cat > $PKGDIR2/DEBIAN/control <<EOF
Package: confidential-data-hub
Version: ${VERSION}-${RELEASE}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: YOU <you@example.com>
Depends:
Description: Confidential Data Hub running inside TEE.
EOF

#######################################
# 4. Create .deb packages
#######################################
echo "[4] Creating .deb files..."

dpkg-deb --build attestation-agent_${VERSION}-${RELEASE}_${ARCH}
dpkg-deb --build confidential-data-hub_${VERSION}-${RELEASE}_${ARCH}

echo "[OK] Done. Generated:"
echo "  ./attestation-agent_${VERSION}-${RELEASE}_${ARCH}.deb"
echo "  ./confidential-data-hub_${VERSION}-${RELEASE}_${ARCH}.deb"
