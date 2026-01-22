#!/bin/bash

set -euo pipefail
set -o noglob

# Initialize parameters
trustee_address=''
as_addr=''
aa_instance_type=''

usage() {
  echo "This script is used to start Attestation Agent" 1>&2
  echo "" 1>&2
  echo "Usage: $0 --trustee-addr Address of remote trustee" 1>&2
  echo "          --aa-instance-type [aliyun_ecs|aliyun_eas] (optional) Attestation Agent instance type" 1>&2

  exit 1
}

# Parse cmd
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --as-addr)
      as_addr="$2"
      shift 2
      ;;
    --trustee-addr)
      trustee_address="$2"
      shift 2
      ;;
    --aa-instance-type)
      aa_instance_type="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

cat << EOF > /etc/attestation-agent.toml
[token_configs]
[token_configs.coco_as]
url = "${as_addr}"

[token_configs.kbs]
url = "${trustee_address}"

[eventlog_config]
enable_eventlog = true
EOF

if [[ -n "${aa_instance_type}" ]]; then
  cat << EOF >> /etc/attestation-agent.toml
[aa_instance]
instance_type = "${aa_instance_type}"
EOF
fi

attestation-agent -c /etc/attestation-agent.toml