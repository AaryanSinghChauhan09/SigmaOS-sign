# SigmaOS-sign

`sigmasign` creates and verifies detached Ed25519 signatures for files. It
requires an explicit key for every operation; an unconfigured signer or
verifier never reports success.

## Use

Generate a raw 32-byte private key and matching 32-byte public key:

```sh
sigmasign keygen signing.key signing.pub
```

Sign a file. The signature is written beside it with the `.sig` extension:

```sh
sigmasign sign signing.key package.tar
```

Verify using the public key:

```sh
sigmasign verify signing.pub package.tar
```

Key files are created only when the destination does not already exist. On
Unix, newly generated private keys are owner-readable and owner-writable
(`0600`). Store private keys securely and distribute public keys through a
trusted channel. The raw key files do not contain identity or provenance
metadata.

## Development

```sh
cargo check
```

The library exposes `SigningKey`, `VerifyKey`, `Signer`, and `Verifier` for
explicit-key use in Rust applications.
