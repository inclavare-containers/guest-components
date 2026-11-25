#!/bin/bash
#
# Copyright (c) 2022 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

[ -n "${DEBUG:-}" ] && set -o xtrace

script_dir=$(dirname $(readlink -f $0))
test_resource_json_name="${2:-aa-offline_fs_kbc-resources.json}"
resource_json_name="aa-offline_fs_kbc-resources.json"
keys_json_name="aa-offline_fs_kbc-keys.json"
target_resource_record_path="/etc/${resource_json_name}"
target_keys_path="/etc/${keys_json_name}"

if [ "${1:-}" = "install" ]; then
    test_keys="${IMAGE_RS_TEST_KBC_KEYS_FILE:-}"
    if [ "$test_resource_json_name" = "aa-offline_fs_kbc-resources-for-icr.json" ]; then
        test_resource_record="${IMAGE_RS_TEST_KBC_RESOURCES_FILE:?set IMAGE_RS_TEST_KBC_RESOURCES_FILE for XRSS tests}"
    else
        test_resource_record="${IMAGE_RS_TEST_KBC_RESOURCES_FILE:-${script_dir}/../test_data/offline-fs-kbc/${test_resource_json_name}}"
    fi

    if ! [ -r "$test_resource_record" ] || { [ -n "$test_keys" ] && ! [ -r "$test_keys" ]; }; then
        echo >&2 "ERROR: offline KBC test fixture files must be readable"
        exit 1
    fi
    sudo install --owner=root --group=root --mode=0640 "${test_resource_record}" "${target_resource_record_path}"
    if [ -n "$test_keys" ]; then
        sudo install --owner=root --group=root --mode=0640 "${test_keys}" "${target_keys_path}"
    fi

    # This is a workaround for CDH to read the aa_kbc_params from a
    # file rather than kernel commandline. This makes a fake environment
    # that CDH will recognize as it is in "peer pod", so aa_kbc param will
    # be read from a file.
    # TODO: when CDH has its own configuration launch file, we can
    # promote this way.
    mkdir -p /run/peerpod
    touch /run/peerpod/daemon.json
    echo "aa_kbc_params = \"offline_fs_kbc::null\"" > /etc/agent-config.toml
elif [ "${1:-}" = "clean" ]; then
    sudo rm "${target_resource_record_path}"
    if [ -n "${IMAGE_RS_TEST_KBC_KEYS_FILE:-}" ]; then
        sudo rm "${target_keys_path}"
    fi

else
    echo >&2 "ERROR: Wrong or missing argument: '${1:-}'"
fi
