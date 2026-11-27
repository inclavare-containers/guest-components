# ocicrypt-rs
This repo contains the rust version of the [containers/ocicrypt](https://github.com/containers/ocicrypt) library.

## JWE RSA recipients

Use `RSA-OAEP-256` for RSA recipients when creating or reading encrypted image
layers. If an RSA JWK declares an `alg` value, set it to `RSA-OAEP-256`.

