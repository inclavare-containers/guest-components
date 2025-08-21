#!/bin/bash

set -x
set -e

is_tdx_guest() {
    if grep tdx_guest /proc/cpuinfo >/dev/null ; then
        return 0
    else
        return 1
    fi
}

is_csv_guest() {
    if dmesg | grep -i "HYGON CSV" >/dev/null ; then
        return 0
    else
        return 1
    fi
}

CONFIG_FILE="/etc/trustiflux/attestation-agent.toml"

if is_tdx_guest; then
    modprobe tdx-guest
elif is_csv_guest; then
    modprobe csv-guest
else
    sed -i 's/enable_eventlog = true/enable_eventlog = false/' ${CONFIG_FILE}
fi
