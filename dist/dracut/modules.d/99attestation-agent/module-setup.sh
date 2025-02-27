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
    systemctl --root "$initdir" enable attestation-agent.service
}

installkernel() {
    # Install kernel modules regardless of the hostonly mode
    hostonly='' instmods tdx_guest
}
