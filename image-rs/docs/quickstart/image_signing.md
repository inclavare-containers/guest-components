# Image signing with cosign

This document includes the following:
* Guide to generate a cosign-signed image.
* Guide to config image security policy to enable signature verification of the image.
* Guide to distribute the public key and image security policy via offline-fs-kbs.

## Signing the encrypted/unencrypted image and enable signature verification when running the workload

When an image is being pulled from a container registry, [policy requirements](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#policy-requirements)
can determined whether the image can be accepted.

The requirements can be:

* Directly reject
* Unconditional accept
* Signature verification required

This section shows how to sign an image, and enable signature verification of specific repository.

### Signing an image with cosign

Both encrypted and unencrypted image can be signed.

We need to install `cosign` to sign images. Detailed work process behind `cosign` can be found in [this doc](../../src/signature/policy/cosign/README.md).
Follow [the guide here](https://github.com/sigstore/cosign#installation) to install `cosign`:

After installing `cosign`, we need to generate a key pair to sign images and verify related signatures.

```
# Generate signing key pair
cosign generate-key-pair
```

After typing a password twice, a key pair will be generated, s.t. private key `cosign.key` and public key `cosign.pub`. 
Here, the password is used to encrypt the private key. 
When we use the private key to sign an image, the password is required. Of cource, the password can be empty.

Suppose there is already an image prepared to be signed named `example.org/test`:

```
# sudo docker images
REPOSITORY            TAG                  IMAGE ID       CREATED         SIZE
example.org/test      latest               ff4a8eb070e1   2 weeks ago     1.24MB
```
Now let us sign this image with the newly generated private key

```
cosign sign --key cosign.key [REGISTRY_URL]:cosign-signed
```

Here, `cosign.key` can be replaced with any cosign-generated private key.

Now the image is signed by cosign, and the signature is pushed to the same repository as the image.

To learn more about cosign, please refer to [the github repository](https://github.com/sigstore/cosign).

### Enable cosign image signature verification and retrieve public key via KBC channel

Take [offline file system key broker](../../../attestation-agent/kbc/src/offline_fs_kbc) (Offline-FS-KBC for short) for example.

#### Prepare Attestation-Agent and Offline-FS-KBC

Clone the repository.

```
git clone https://github.com/confidential-containers/guest-components
```

Build Offline-Fs-KBC & AA
```
cd guest-components/attestation-agent
make KBC=offline_fs_kbc

install_dir=/path/to/be/installed
make install
```

#### Add Offline-Fs-KBC resources

All signature verification rules are defined in a `policy.json`. But before we work on
the `policy.json`, there are a few things to be clarified:
* The `policy.json` is provided by the relying party, so we will use Offline-Fs-KBC to provide
this secret file. The channel is secure.
* The verification public key is also retrieved via KBC secure channel.

So the next steps will firstly add the two resources (`policy.json` and public key) to the
Offline-Fs-KBC resources.

Let's continue with the image `example.org/test`, and enable security strategy (including signature verification).

Firstly edit an `policy.json` like

```
{
    "default": [{"type": "reject"}], 
    "transports": {
        "docker": {
            "example.org": [
                {
                    "type": "sigstoreSigned",
                    "keyPath": "kbs:///default/cosign-public-key/test"
                }
            ]
        }
    }
}
```

The `keyPath` URI tells image-rs to request `cosign.pub` from the KBC. Create
the resource file with your policy and public key, then provision it to the guest.
For a guest with an existing resource file, add these entries to it.

```bash
cat > aa-offline_fs_kbc-resources.json <<EOF
{
    "default/security-policy/test": "$(base64 --wrap=0 /path/to/policy.json)",
    "default/cosign-public-key/test": "$(base64 --wrap=0 /path/to/cosign.pub)"
}
EOF
sudo install -m 0600 aa-offline_fs_kbc-resources.json /etc/aa-offline_fs_kbc-resources.json
```

When pulling images from `example.org`, image-rs uses that public key to verify
their signatures. To also decrypt images, provision your own key file as described
in the [Offline-FS-KBC usage guide](../../../attestation-agent/kbc/src/offline_fs_kbc/README.md).

Now let's start the AA with Offline-Fs-KBC

```
attestation-agent --keyprovider_sock 127.0.0.1:50000 --getresource_sock 127.0.0.1:50001
```

Now the attestation-agent can response with the correct resources.
