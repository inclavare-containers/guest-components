# Sealed Secrets

## Introduction

In Confidential Containers, secrets can be protected with sealing.
A sealed secret is a way to encapsulate confidential data
such that it can be accessed only inside an enclave
in conjunction with an attestation.

The Confidential Data Hub provides an API for unsealing secrets inside
of a confidential guest.

You can also use the secret cli tool to generate a sealed secret:

```bash
cargo run -p confidential-data-hub --bin secret
```

## Kubernetes Secrets

CoCo’s [threat model](https://github.com/confidential-containers/confidential-containers/blob/main/trust_model_personas.md)
excludes the Kubernetes Control Plane and Host components from the
Trusted Compute Base (TCB).
This means that CoCo workloads should not store sensitive data
with traditional [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/).

Instead, Kubernetes secrets can be created from sealed secrets,
allowing the control plane to orchestrate the secrets without
being able to read them. This is shown in detail below.

The Kata Agent, in conjunction with the CDH, can transparently
provision these secrets as environment variables.

## Comparison to Resource URI

Confidential Containers also uses Resource URIs to refer to secrets.
Unlike resource URIs, sealed secrets contain configuration metadata
that partially decouples unsealing the secret from the general attestation
configuration.

For example, a sealed secret can be unwrapped by an HSM while all other
secret resources are fetched from the KBS.
Sealed secrets can be used to create complex environments where multiple
secrets, fulfilled by different parties, can all travel along with the workload.

## Format

There are two main types of sealed secrets.

### Envelope

This kind of secret uses envelope encryption scheme. An encryption key is used
to encrypt the plaintext secret value. The wrapped secret is stored as part of
the sealed secret.
To unseal the secret, a KMS/KBS is used to unwrap the encryptd key.

$$Sealed Secret := \{Enc_{Sealing key}(Encryption Key), Enc_{Encryption Key}(secret value)\}$$

The format of the KMS type Sealed Secret is
```json
{
	"version": "0.1.0",
	"type": "envelope",
	"provider": "xxx",
	"key_id": "xxx",
	"encrypted_key": "ab27dc=",
	"encrypted_data": "xxx",
	"wrap_type": "A256GCM",
	"iv": "xxx",
	"provider_settings": {
		...
	},
	"annotations": {
		...
	}
}
```
Here,
- `version`: **REQUIRED**. indicates the format version of the Sealed Secret. Currently `0.1.0`.
- `type`: **REQUIRED**. MUST be `envelope`, indicating this is a Envelope type Sealed Secret
- `provider`: **REQUIRED**. indicates the provider of the __sealing key__. This field determines
how to use the `annotations` field and `key_id` field to decrypt the `encrypted_key`
- `key_id`: **REQUIRED**. To uniquely distinguish the __sealing key__ used to encrypt the __encryption key__,
which is always used by the provider driver.
- `encrypted_key`: **REQUIRED**. Encrypted __encryption key__ by the `provider`. Base64 encoded.
- `encrypted_data`: **REQUIRED**. Encrypted __secret value__ by the `encrypted_key`. Base64 encoded.
- `wrap_type`: **REQUIRED**. The algorithm used by __encryption key__ to encrypt the __secret value__.
`A256GCM` (AES256-GCM) preferred.
- `iv`: **REQUIRED**. The Initial Vector used in the process of __encryption key__ encrypting __secret value__.
Base64 encoded.
- `provider_settings`: **REQUIRED**. A key-value map. Provider specific information to create the KMS client.
- `annotations`: **OPTIONAL**. A key-value Map. Provider specific information used by the driver to
decrypt `encrypted_key` into a plaintext of __encryption key__.

### Vault

A vault secret is simply a pointer to a secret that is stored elsewhere,
either in a KMS or KBS.
To fulfill a vault secret, the CDH will retrieve the secret itself from
a secret provider.

Creating a vault secret does not require any encryption.
Simply create the metadata below and provision your secret
to the provider.
```json
{
	"version" : "0.1.0",
	"type": "vault",
	"provider": "xxx",
	"name": "xxx",
	"provider_settings": {
		...
	},
	"annotations": {
		...
	}
}
```
Here,
- `version`: **REQUIRED**. indicates the format version of the Sealed Secret. Currently `0.1.0`.
- `type`: **REQUIRED**. MUST be `vault`, indicating this is a Vault type Sealed Secret.
- `provider`: **REQUIRED**. indicates the provider of the __secret value__. This field determines
how to use the `annotations` field and `name` field to get the plaintext of __secret value__.
- `name`: **REQUIRED**. To uniquely distinguish the __secret value__, which is always used by the provider driver.
- `provider_settings`: **REQUIRED**. A key-value map. Provider specific information to create the vault client.
- `annotations`: **OPTIONAL**. A key-value Map. Vault specific information used by the provider driver to
get the plaintext of the __secret value__.

## Integrity Protection of Sealed Secret

Widely used [JWS](https://datatracker.ietf.org/doc/html/rfc7515) is used to protect
the integrity of a Sealed Secret.
A Sealed Secret is the payload of a JWS. A signed Sealed Secret is as following
```
BASE64URL(UTF8(JWS Protected Header)) || '.
    || BASE64URL(JWS Payload) || '.'
    || BASE64URL(JWS Signature)
```

We can leverage the ["kid"](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4)
field to specify the public key used to verify this signature.

A public P-256 JWK, identified by a `kid`, must be available to verify the
ES256 signature. The key can either be provisioned under
`/run/confidential-containers/cdh/sealed-secret` or retrieved from OpenAnolis
Trustee when the `kid` is a `kbs://` or `kbs+<plugin>://` Resource URI.

Signature verification is enabled by default. During migration only, legacy
fake-signed values can be accepted by setting
`skip_sealed_secret_verification = true` in the CDH configuration (or
`SKIP_SEALED_SECRET_VERIFICATION=true` in the environment). This disables the
integrity check and should not be used for newly created secrets.

## Usage in CoCo

The `secret` CLI creates signed sealed secrets. For example:

```bash
cargo run -p confidential-data-hub --bin secret -- seal \
    --signing-kid kbs:///default/sealed-signing/my-key \
    --signing-jwk-path ./my-key-private.json \
    vault \
    --resource-uri kbs:///default/secret/my-value \
    --provider kbs
```

Provision only the public JWK at the URI in `--signing-kid`. The private JWK
must remain with the party creating the sealed secret.

Generate a P-256 keypair with the CLI:

```bash
cargo run -p confidential-data-hub --bin secret -- keygen \
    --kid my-signing-key --output-dir ./keys
```

This writes `my-signing-key-private.json` for signing and
`my-signing-key-public.json` for provisioning to OpenAnolis Trustee.

Create a Kubernetes secret from the signed output:

```bash
kubectl create secret generic sealed-secret --from-literal='secret=<sealed-secret>'
```

Use this secret in a workload
```yaml
...
    env:
    - name: PROTECTED_SECRET
      valueFrom:
        secretKeyRef:
          name: sealed-secret
          key: secret
```

Your secret will be provisioned to the `PROTECTED_SECRET` environment variable.

## Supported Providers

| Provider Name      | README                                                      			| Maintainer                |
| ------------------ | -------------------------------------------------------------------- | ------------------------- |
| aliyun       	     |  [aliyun](kms-providers/alibaba.md)                               	| Alibaba                   |
| ehsm       	     |  [ehsm](kms-providers/ehsm-kms.md)                              		| Intel                   	|
| kbs                |                                                                          | CoCo                  |
