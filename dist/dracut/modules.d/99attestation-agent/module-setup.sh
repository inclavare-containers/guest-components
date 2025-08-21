#!/usr/bin/env bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst_multiple /usr/bin/attestation-agent
    inst_simple $moddir/attestation-agent.service /usr/lib/systemd/system/attestation-agent.service
    inst_simple $moddir/attestation-agent.toml /etc/trustiflux/attestation-agent.toml
    inst_simple $moddir/attestation-agent-platform-detect.service /usr/lib/systemd/system/attestation-agent-platform-detect.service
    inst_simple $moddir/attestation-agent-platform-detect.sh /usr/bin/attestation-agent-platform-detect.sh
}

installkernel() {
    # Install kernel modules regardless of the hostonly mode
    hostonly='' instmods tdx_guest csv-guest
}
