# GetResource from an attestation-enabled Aliyun KMS instance

CDH supports an attestation-enabled KMS instance through `aliyun_kms_kbc`.
Existing Vault / UnsealSecret settings are unchanged.

## Configure CDH

Enable the `aliyun` feature (enabled by default), run a local Attestation Agent,
and render the following CDH configuration through initdata:

```toml
[kbc]
name = "aliyun_kms_kbc"
instance_id = "kst-example"          # Optional default
ecs_ram_role_name = "my-kms-role"    # Optional IMDS fallback
# region_id = "cn-beijing"
```

Use a RAM role **name**, not an ARN or numeric ID. There is no built-in default
role. The platform must bind and authorize the role before using IMDSv2.

All three defaults can be omitted. CDH can start with this configuration when callers
supply `sts`, `kms_id`, and `region_id`:

```toml
[kbc]
name = "aliyun_kms_kbc"
```

`region_id` is the **KMS** region for the management API. On ECS it may be omitted
when IMDS supplies the correct same-region value. The selection order is request
`region_id`, configured `region_id`, then ECS IMDS. Supply it by query or configuration
for cross-region access or environments without IMDS. STS does not identify the KMS region, and
CDH never infers a region from the instance ID.

All KMS fields belong to `[kbc]`, not a separate `[kms]` table. KMS mode rejects
`url`, `kbs_cert`, `credential_source`, and `credentials_uri`. There is no EAS
credential service or `ALIBABA_CLOUD_CREDENTIALS_URI` source.

Use `[aa].aa_socket` (or legacy `aa_socket`) for a nondefault local AA socket.
Query parameters never switch a KBS deployment into KMS mode. Existing KBS
configurations retain their original fields and behavior.

## Read a resource

The resource URI retains the `kbs:///` prefix. For `kbs:///my-secret`:

```bash
umask 077
curl --fail --silent --show-error --max-time 50 \
  http://127.0.0.1:8006/cdh/resource/my-secret --output /run/my-secret
```

Request parameters override configuration **independently**:

The optional `type` query parameter can explicitly check the expected backend:

```bash
curl --fail --silent --show-error --max-time 50 \
  'http://127.0.0.1:8006/cdh/resource/my-secret?type=aliyun_kms' --output /run/my-secret
```

Use `aliyun_kms` for KMS or `kbs` for KBS. If supplied, `type` must match the
configured backend; a mismatch returns HTTP 400. Omitting it keeps the configured
backend, so existing callers need not change. It does not require any of the
three parameters below to be supplied together.

| Request | KMS target | Authorization |
| --- | --- | --- |
| No parameters | Configured instance_id | Configured role through IMDSv2 |
| ?sts=<base64-sts> | Configured instance_id | Request STS |
| ?kms_id=<kms-id> | Request kms_id | Configured role through IMDSv2 |
| ?sts=<base64-sts>&kms_id=<kms-id> | Request kms_id | Request STS |
| ?sts=<base64-sts>&kms_id=<kms-id>&region_id=cn-beijing | Request kms_id and region_id | Request STS |

If `sts` is absent, CDH uses `ecs_ram_role_name` from its configuration to obtain
STS through IMDSv2. If `kms_id` is absent, it uses configured `instance_id`.
`region_id` is independently optional and overrides the configuration/IMDS region.
For example, `?region_id=cn-beijing` alone retains the configured instance and role.
Missing both request and configuration values is an error. Explicit empty,
duplicate, malformed or expired values do not trigger identity/target/region fallback.

Success is HTTP 200 with `application/octet-stream` and the original secret bytes,
including binary values. Invalid request options return HTTP 400. KMS or
attestation failures retain the existing REST internal-error mapping. Failed
caller-provided STS never falls back to a configured role.

## Encode and pass STS

`sts` is Base64 of the **complete** credential, not just `SecurityToken`:

```json
{
  "AccessKeyId": "<temporary-access-key-id>",
  "AccessKeySecret": "<temporary-access-key-secret>",
  "SecurityToken": "<temporary-security-token>",
  "Expiration": "<RFC3339-expiration>"
}
```

Expiration is optional; if present, malformed/expired values are rejected.
KMS validates the actual session in all cases. Base64 of the legacy `AK:SK:STS`
representation is also accepted. Standard and URL-safe Base64, with or without
padding, are supported. URL-encode standard Base64, especially `+`, `/`, and `=`.

```text
GET http://127.0.0.1:8006/cdh/resource/my-secret?sts=<url-encoded-base64-sts>&kms_id=<kms-id>&region_id=cn-beijing
```

The example below reads an already-issued credential JSON from a private tmpfs
file and passes curl's URL through stdin, avoiding secrets in curl process
arguments and shell history. This is a client example, not a CDH credential-file
provider:

```bash
umask 077
python3 - <<'PY' | curl --config -
import base64, pathlib, urllib.parse
sts = base64.b64encode(pathlib.Path('/run/kms-sts.json').read_bytes()).decode()
query = urllib.parse.urlencode({'sts': sts, 'kms_id': 'kst-example', 'region_id': 'cn-beijing'})
print('url = "http://127.0.0.1:8006/cdh/resource/my-secret?' + query + '"')
print('output = "/run/my-secret"')
print('fail')
print('silent')
print('show-error')
print('max-time = 50')
print('noproxy = "*"')
PY
```

Base64 is not encryption. Do not log full URLs, enable curl verbose/trace, or put
STS in initdata, reports, shell history or shared caches. Keep REST on the trusted
local channel. The caller obtains and refreshes request STS; CDH does not cache
it globally.

## Transport, permissions and compatibility

Both credential modes obtain the instance CA through authenticated HTTPS
`GetKmsInstance` at `kms-vpc.<region>.aliyuncs.com`. CDH checks the returned instance
ID and strictly verifies data-plane TLS. No CA file or bundled regional CA is
required. The cached transport is scoped to its KMS instance and management region;
a request override cannot reuse another target or region's cache.

The selected identity needs `kms:GetKmsInstance`, `kms:GetChallenge`, and
resource-scoped `kms:GetSecretValue` / `kms:Decrypt` permissions. Require
`kms:RecipientAttestation:Verified` for data release. Request STS changes the RAM
identity only; TEE evidence and recipient encryption are always required.

IMDS credentials are cached, refreshed before expiration, and coalesced across
concurrent requests. CA refresh is rate-limited and never disables certificate
or hostname validation. Errors never select another backend, identity or target.

Upgrade trustiflux-api-server and CDH together. REST calls with overrides use
`GetResourceWithOptions`, so older CDH versions reject the call rather than ignore
authorization fields. Calls without overrides retain the original `GetResource`
RPC; the updated protobuf remains compatible with old clients.

The RPC envelope contains `ResourcePath`, optional `Type`, and an `Options` map.
CDH interprets provider-specific options and validates their names and values.
REST only decodes the query and applies transport bounds/duplicate checks. An
omitted type keeps the configured backend; it never silently switches providers.
