# GetResource from an attestation-enabled Aliyun KMS instance

CDH can use a KMS instance with the Trustee remote-attestation module as its
GetResource backend. The `aliyun` feature is required (enabled by default).
This does not change the existing Vault sealed-secret / UnsealSecret interface.

## Prerequisites

- A TDX guest with a working local Attestation Agent ttRPC service.
- An activated KMS software instance with the Trustee attestation module enabled,
  reachable from the guest's VPC, and an existing secret in that instance.
- Either an ECS RAM role accessible through IMDSv2 from inside the guest, or an
  EAS platform credentials URI accessible from the **CDH process** before its
  startup. A business container's environment/network is not
  automatically available across guest isolation.
- Permissions to read the target secret and decrypt with its encryption key.
  `kms:GetKmsInstance` is always required for automatic CA bootstrap/refresh.

## Configure

The control plane renders the following into its existing
`confidential-data-hub.toml` initdata entry. Keep other initdata entries intact.
An example standalone file is [example.aliyun-kms.config.toml](../example.aliyun-kms.config.toml).

```toml
[kbc]
name = "aliyun_kms_kbc"
instance_id = "kst-example"
ecs_ram_role_name = "your-bound-kms-role"
```

For the default ECS credential source both fields are required. Use a **role name**, not a numeric ID or ARN. CDH
does not assume a fixed/default role, list arbitrary roles, bind roles or grant
permissions. The control plane selects and supplies the correct role name.
Do not put the instance ID into `kbc.url`: backend selection is exclusively by
`kbc.name`. A nonempty `kbc.url` or a `kbc.kbs_cert` is a configuration error in
KMS mode. The backend type and all its parameters belong to the same `[kbc]`
table, with no separate `[kms]` section. Existing `cc_kbc` / `offline_fs_kbc` /
`online_sev_kbc` configurations retain their original fields and resource backends.

Optional `kbc.region_id` specifies the **KMS** region. Without it, CDH uses the
IMDS region, so the default deployment is same-region. Region selects the
management endpoint; CDH never infers a region from an instance
ID. The data endpoint is `<instance_id>.cryptoservice.kms.aliyuncs.com`.

Use `[aa].aa_socket` (or the legacy top-level `aa_socket`) for a non-default AA
socket. The GetResource path passes this value explicitly and does not depend on
`ATTESTATION_AGENT_SOCKET` or `AA_KBC_PARAMS` to choose KMS.

### EAS credentials URI

```toml
[kbc]
name = "aliyun_kms_kbc"
instance_id = "kst-example"
region_id = "cn-beijing"
credential_source = "credentials_uri"
# Normally omit this: use the platform's ALIBABA_CLOUD_CREDENTIALS_URI.
# credentials_uri = "http://<trusted-platform-endpoint>/credentials"
```

Bind the custom role in **EAS service configuration**, not `ecs_ram_role_name`.
Its trust principal is `eas.pai.aliyuncs.com`; enable `options.enable_ram_role`
and supply `role_arn` in that service configuration. The role must have the same
KMS runtime permissions as the ECS role. The EAS deployment identity needs
`ram:PassRole`, which is not a CDH runtime permission.

The URI is read from `kbc.credentials_uri` first, then from the CDH process's
`ALIBABA_CLOUD_CREDENTIALS_URI`. It must be trusted deployment configuration,
never a GetResource parameter. HTTP is supported only for the platform's isolated
local credential channel; do not expose it publicly. CDH disables proxies and
redirects, validates the complete STS response and expiration, redacts URI/errors,
and shares the same early-refresh/concurrency cache as ECS. There is no fallback
to IMDS or another identity. `ecs_ram_role_name` is rejected in this mode.

`region_id` is required in URI mode because the credential response does not
provide a KMS region. The control plane can populate it automatically in initdata.
The management API is regional even though the instance data endpoint is not.
Supply the KMS region, not a potentially different EAS region.

The EAS runtime must deliver the URI **at CDH startup, before its first resource**, and
keep it reachable for refresh. If it appears only after starting a container
whose startup depends on that resource, platform integration is required to break
the bootstrap cycle. A working ordinary EAS credential endpoint alone is not proof
that confidential EAS has working TDX/AA or early-boot credential delivery.

### Credentials and CA lifecycle

No CA PEM, access key or STS token is required in these configurations. ECS uses
IMDSv2, caches session credentials in memory, refreshes them before expiration,
and coalesces concurrent refreshes. It never falls back to IMDSv1.

TLS always bootstraps through authenticated HTTPS `GetKmsInstance` at
`kms-vpc.<region_id>.aliyuncs.com`, using ordinary platform-trusted HTTPS roots.
CDH checks the returned instance ID and uses its full `CaCertificateChainPem`
bundle to authenticate the instance data endpoint. No regional KMS CA is bundled.
It never disables hostname/chain verification or trusts a certificate obtained
from an unauthenticated data-plane connection.
CA lookup permission is separate from permission to read secrets. Certificates
and clients are cached in memory per CDH instance for 24 hours; unknown data-plane
issuers trigger a rate-limited management refresh. Refresh failures may retain
previously authenticated trust, but never disable TLS verification. The guest
must reach both management and instance data-plane endpoints; no Internet access
is needed for the documented management VPC endpoint.

## Read a resource

The business resource URI still has the `kbs:///` compatibility prefix:

```bash
RESOURCE_URI='kbs:///my-secret'
RESOURCE_ID=${RESOURCE_URI#kbs:///}
curl --fail --silent --show-error --max-time 50 \
  "http://127.0.0.1:8006/cdh/resource/${RESOURCE_ID}"
```

Or use CDH's existing RPC tool:

```bash
ttrpc-cdh-tool --socket unix:///run/confidential-containers/cdh.sock \
  --timeout 50 get-resource --resource-uri kbs:///my-secret
```

The REST response is `200 application/octet-stream` with the original secret
bytes, not a JSON/base64 envelope. Never log the response or session credentials.
For binary KMS secrets, GetResource decodes the authenticated response's
`SecretDataType=binary` Base64 representation; text values are never decoded.
The existing Vault provider's wire-value behavior is unchanged.
This path supports single-component names and ASCII slash-separated names;
encoded paths, URI authorities, query/fragment components and traversal are
rejected rather than normalized. The same resolver serves startup `credentials`
prefetches. No KBS client is initialized just to start an empty-prefetch KMS CDH.

## Authorization

Use a dedicated role with the correct service trust policy (`ecs.aliyuncs.com`
for ECS, `eas.pai.aliyuncs.com` for EAS), bind
it to the corresponding deployment, and grant only the actions/resources needed for that
deployment. The deployment administrator's provisioning permissions are separate
from the runtime role. In particular, the role does not need to create keys,
create credentials, manage ECS, or modify RAM policies.

`kms:GetSecretValue` must target the secret resource and `kms:Decrypt` its
encryption key. Where supported, constrain the data release with
`kms:RecipientAttestation:Verified`; do not combine it with an unconditional
allow for the same data. `GetChallenge` and the CA management lookup cannot
require an already-verified Recipient. The required runtime permissions and their
actual verification are recorded in the end-to-end test report.

See [GetSecretValue](https://help.aliyun.com/zh/kms/key-management-service/developer-reference/api-kms-2016-01-20-getsecretvalue),
[GetKmsInstance](https://help.aliyun.com/zh/kms/key-management-service/developer-reference/api-kms-2016-01-20-getkmsinstance),
and [remote attestation](https://help.aliyun.com/zh/kms/key-management-service/use-cases/kms-confidential-environment-remote-attestation-best-practices).

## Boundaries and migration

Each CDH deployment selects one GetResource backend. Changing it requires
redeployment; a failed KMS request never falls back to KBS or to a KMS request
without Recipient. No RPC/proto or REST URI changes are required.

The existing Vault attestation provider still accepts file/inline CA and RAM-role
or direct-STS settings. Its `kms_instance_id` field has not been renamed to the
new CDH `kms.instance_id` field. Mirror keys, storage keys, AA token configuration
and sealed-secret signature verification are not implicitly migrated by this
GetResource change.

The current KMS Trustee response is a single RSA-2048 OAEP-SHA256 block, with a
190-byte wrapped-value limit (including Base64 expansion for binary secrets).
Larger credentials require a separately agreed KMS
response format; CDH does not silently truncate. Each read creates fresh evidence
and an ephemeral key pair. No plaintext resource is cached. The new GetResource
path has a 45-second total timeout inside REST's existing 50-second RPC budget.
