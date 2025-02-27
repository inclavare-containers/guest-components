#!/usr/bin/env bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst_multiple /usr/bin/confidential-data-hub
    inst_simple $moddir/confidential-data-hub.toml /etc/trustiflux/confidential-data-hub.toml
}
