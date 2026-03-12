The Confidential Data Hub (CDH) provides resources services like retrieving a
decryption keys and policy files from the Key Broker Service (KBS).

Currently workloads can get resources via CDH from the following providers:

* [CoCo KBS](https://github.com/confidential-containers/trustee/tree/main/kbs)
* AMD SEV based on EFI secret pre-attestation (via [simple-kbs](https://github.com/confidential-containers/simple-kbs))

The CDH service should be configured with one of the following Key Broker Client (KBC) that establish
the interface with the provider:

* `cc_kbc` - for CoCo KBS
* `online_sev_kbc` - for AMD SEV with simple-kbs
* `offline_fs_kbc` - for reading from the system's local filesystem

For more information about configuring CDH, please refer to [this section](../README.md#configuration-file) in the [README.md](../README.md).

## Usage

Users are recommended to access CDH services via the [CoCo Restful API Server](../../api-server-rest/README.md), so 
ensure that both API server and CDH process are running on the local host. By default the API server listen on
port `8006`, whereas resources are HTTP-served from the `cdh/resource` endpoint.

For example, assume that the CDH was configured with `cc_kbc`, to obtain the key `key` which is
tagged as `1` from the `default` repository:

```
$ curl http://127.0.0.1:8006/cdh/resource/default/key/1
```

Notice that a CoCo Pod also has access to the API server as both container and CDH/API-server processes
belong to the same network namespace. Thus, to read a resource from a Pod should be as simple as send a 
HTTP GET request to the CDH endpoint as shown on the following deployment:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cdh-example
spec:
  runtimeClassName: kata-qemu-tdx
  containers:
    - name: bash-curl
      image: storytel/alpine-bash-curl:latest
      imagePullPolicy: Always
      command:
        - sh
        - -c
        - |
          curl http://127.0.0.1:8006/cdh/resource/default/key/1; tail -f /dev/null
```

## Example: offline_fs_kbc

In this example we will use the `offline_fs_kbc` KBC to get resources from the local filesystem. To run this
example we don't need neither a TEE hardware nor VM nor Kubernetes.

By historical and backward-compatilibity reasons, `offline_fs_kbc` reads key/value pairs from both
**/etc/aa-offline_fs_kbc-keys.json** and **/etc/aa-offline_fs_kbc-resources.json** files. Here we
will use **/etc/aa-offline_fs_kbc-resources.json** solely.

First, build the CDH. To faster the build, disable all KMS providers and let enabled only the
KBS resources provider:

```shell
$ make RESOURCE_PROVIDER=kbs KMS_PROVIDER=none
```

Create the resources file (**/etc/aa-offline_fs_kbc-resources.json**) and add the **default/key/1**
key (its value should be encoded in base64):

```json
{
  "default/key/1": "HUlOu8NWz8si11OZUzUJMnjiq/iZyHBJZMSD3BaqgMc="
}
```

Create the CDH configuration file (**cdh_conf.toml**):

```toml
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""
```

Launch the CDH in background:

```shell
$ sudo ../target/x86_64-unknown-linux-gnu/release/confidential-data-hub -c cdh_conf.toml &
```

Next, build the API server and launch it as:

```shell
$ make -C ../api-server-rest
$ sudo ../target/x86_64-unknown-linux-gnu/release/api-server-rest --features=resource &
```

Finally we can obtain the resource **default/key/1** key from CDH:

```shell
$ key=$(curl -s http://127.0.0.1:8006/cdh/resource/default/key/1 | base64)
root_path /cdh, url_path /resource/default/key/1
[2024-03-22T14:43:55Z INFO  confidential_data_hub::hub] get resource called: kbs:///default/key/1
$ echo $key
HUlOu8NWz8si11OZUzUJMnjiq/iZyHBJZMSD3BaqgMc=
```

Notice on the output above that the service returned the raw key's value, i.e., it is already base64 decoded.

## Challenge attestation based resource injection

In addition to the existing pull model (`/cdh/resource/...`), CDH now supports a verifier-driven
push model for confidential data injection. This is useful when a remote verifier wants to attest
the guest first, then inject data into the TEE.

### Security properties

- **Freshness**: verifier sends a challenge nonce to CDH `prepare` API.
- **Attestation binding**: CDH generates evidence with runtime_data:
  `{"nonce":"...","tee-pubkey":{...}}`
- **Confidential transport**: verifier encrypts payload with the TEE public key returned by CDH.
- **One-time session**: each injection session (`session_id`) can be committed only once.

### API workflow

1. Prepare injection

```bash
curl -sS -X POST \
  http://127.0.0.1:8006/cdh/resource-injection/prepare/default/key/1 \
  -H 'content-type: application/json' \
  -d '{"nonce":"<verifier-nonce>"}'
```

Response:

```json
{
  "session_id": "....",
  "nonce": "<verifier-nonce>",
  "tee_pubkey": {
    "kty": "EC",
    "crv": "P-256",
    "alg": "ECDH-ES+A256KW",
    "x": "...",
    "y": "..."
  },
  "evidence": "<base64-encoded-attestation-evidence>"
}
```

2. Verifier validates `evidence` with the same `nonce` and `tee_pubkey` in runtime_data.
3. Verifier encrypts plaintext resource to a KBS-compatible encrypted response JSON.
4. Commit injection

```bash
curl -sS -X POST \
  http://127.0.0.1:8006/cdh/resource-injection/commit/default/key/1 \
  -H 'content-type: application/json' \
  -d '{
    "session_id":"<session-id>",
    "encrypted_resource": {
      "protected": {"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"...","y":"..."}},
      "encrypted_key":"...",
      "iv":"...",
      "ciphertext":"...",
      "tag":"..."
    }
  }'
```

After commit succeeds, CDH decrypts the payload inside the TEE and stores plaintext at:

`/run/confidential-containers/cdh/<repository>/<type>/<tag>`
