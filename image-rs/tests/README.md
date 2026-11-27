# Integration Test for Image-rs

This integration test has two main sub-type test sets:
* Image decryption using [ocicrypt-rs](../../ocicrypt-rs)
* Image signature verification.

And both of test set will use the following key broker client:
* `Offline-fs-kbc`

## Image Decryption

Implemented in `image_decryption.rs`.

Image decryption will cover `Offline-fs-kbc`:
* `Offline-fs-kbc` uses `ghcr.io/confidential-containers/test-container:encrypted`

Each test suite will follow these steps:

* Pull manifest of the image without verification of signature.
* Pull layers of the mentioned image.
* Ocicrypt-rs will ask the Attestation-Agent to decrypt the Layer Encryption Key (LEK for short), which is 
encrypted using Key Encryption Key (KEK for short). KEK is stored in KBS.
* Ocicrypt-rs decrypt the layers using LEK. Finish the image pulling.

Different KBCs use different protocol format, so different KBSs are needed to
encrypt the images. To genetate KBS encrypted image, please refer to the following link:

* [Using Offline-fs-kbs](../../attestation-agent/kbc/src/offline_fs_kbc/README.md)

## Image Signature Verification

Implemented in `signature_verification.rs`.

Image Signature Verification includes the following four tests
s.t.

| |signed image|unsigned image|
|---|---|---|
|protected registry|protected_signed_allow, protected_signed_deny|protected_unsigned_deny|
|unprotected registry|-|unprotected_unsigned_allow|

Here
* `protected_signed_allow`: Allow pulling image from a protected registry, including `Simple Signing` and `Cosign`
* `protected_signed_deny`: Deny pulling image from a protected registry, including 
    * `Simple Signing` with an unknown signature
    * `Cosign` with a wrong public key
* `protected_unsigned_deny`: Deny pulling an unsigned image from a protected registry
* `unprotected_unsigned_allow`: Allow pulling an unsigned image from a unprotected registry

In `signature_verification.rs`, the tests are organized due different kinds
of KBCs, which means for each given KBC, all four tests mentioned will be
covered.

## Registry Credential Retrievement

Implemented in `credential.rs`.

Registry Credential Retrievement will do the following steps to test this feature.
- Get `auth.json` from the Attestation Agent. The test KBC is `Offline-Fs-Kbc`.
- Try to pull images from private registry using the matched credential in `auth.json`

Use dedicated test images and registry credentials passed to the integration test from its runtime environment. The cases exercise registry matching and repository-prefix matching.

Set `IMAGE_RS_TEST_KBC_KEYS_FILE` to the key bundle for live tests that decrypt images through the offline KBC. Tests that only pull unencrypted images do not need a key bundle. Set `IMAGE_RS_TEST_KBC_RESOURCES_FILE` for the XRSS suite, for tests that fetch registry authentication through KBS, or to override the resources used by other suites. Use the same settings for setup and cleanup. The files must match the images under test.

For the live JWE test, set `IMAGE_RS_TEST_JWE_DECRYPT_CONFIG` to the matching decrypt configuration, with an optional password file in the usual `path:file=/path/to/passwordfile` form. Set `IMAGE_RS_TEST_JWE_IMAGE` to override the default test image. Provision all test credentials outside the repository.

The CDH `image-pull` integration test uses the standard CDH socket. Run it in a
disposable guest with its own `/run`. Set `RUN_LIVE_IMAGE_PULL_TESTS=1` and pass a
comma-separated list of JSON bundle paths in `OFFLINE_FS_KBC_EXTRA_FILE_PATH`
for the encrypted or private-registry cases. Set `CDH_TEST_ENCRYPTED_IMAGE` to
the BusyBox image wrapped using `A256GCM`. Set `CDH_TEST_PRIVATE_REGISTRY_IMAGE`
to the BusyBox image in the private test registry and provide the registry
authentication as the `default/credential/test` resource. CDH reads the
provided fixture files in place. The public and signed image references can
be overridden with `CDH_TEST_PUBLIC_IMAGE` and `CDH_TEST_COSIGN_IMAGE`.
