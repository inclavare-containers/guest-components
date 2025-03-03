import os
import sys
import json
import nv_attestation_sdk.attestation as attestation_module
from nv_attestation_sdk.utils import claim_utils

local_nvswitch_att_result_policy = '''
{
  "version":"3.0",
  "authorization-rules":{
    "type": "JWT",
    "overall-claims": {
      "iss": "LOCAL_SWITCH_VERIFIER",
      "x-nvidia-overall-att-result": true,
      "x-nvidia-ver": "2.0"
    },
    "detached-claims":{
      "measres": "success",
      "x-nvidia-switch-arch-check": true,
      "x-nvidia-switch-bios-rim-measurements-available": true,
      "x-nvidia-switch-attestation-report-signature-verified": true,
      "x-nvidia-switch-attestation-report-parsed": true,
      "x-nvidia-switch-attestation-report-nonce-match": true,
      "x-nvidia-switch-attestation-report-cert-chain-validated": true,
      "x-nvidia-switch-bios-rim-schema-validated": true,
      "x-nvidia-switch-bios-rim-signature-verified": true,
      "x-nvidia-switch-bios-rim-cert-validated": true,
      "x-nvidia-switch-bios-rim-fetched": true
    }
  }
}
'''

# Suppress stdout
class Silence:
    def write(self, msg):
        pass
    def flush(self):
        pass
def main(output_filename):
    # Redirect stdout to silence internal messages
    try:
        old_stdout = sys.stdout
        sys.stdout = Silence()
        
        client_name = "AttestationAgent"
        attestation_class = attestation_module.Attestation(client_name)
        
        devices = attestation_module.Devices
        environment = attestation_module.Environment
        
        attestation_class.add_verifier(devices.SWITCH, environment.LOCAL, "", "")
        evidence_list = attestation_class.get_evidence(ppcie_mode=False)
        result = attestation_class.attest(evidence_list)
        
        sys.stdout = old_stdout
        if result:
            token = attestation_class.get_token()
            if token and attestation_class.validate_token(local_nvswitch_att_result_policy):
                claims = {}
                json_array = json.loads(token)
                if len(json_array) >= 2:
                    for key, value in json_array[1].items():
                        for item in value:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    payload = claim_utils.decode_jwt(v)
                                    claims[str(k)] = payload
                with open(output_filename, "w") as f:
                    f.write(json.dumps(claims))
                return
        
        print("NV SWITCH Attestation failed or no token obtained", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python <script>.py <output_filename>")
        sys.exit(1)
    output_filename = sys.argv[1]
    main(output_filename)