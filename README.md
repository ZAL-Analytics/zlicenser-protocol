# zlicenser-protocol

The shared protocol crate for the [zlicenser](https://github.com/zal-analytics/zlicenser) licensing framework. Both the client library and the vendor server depend on this.

It covers everything that crosses the wire: the four protocol messages, canonical CBOR wire encoding, cryptographic primitives (AEAD, KDF, Ed25519 signatures, BLAKE3, Shamir secret sharing), hardware fingerprinting for Linux, RFC 3161 trusted timestamping, and the signed evidence bundle format.

If you're building a third-party implementation of the zlicenser protocol, this crate plus the mdBook spec in `docs/` is everything you need. Nothing is hidden behind workspace-internal boundaries.

## Features

| Feature | Description | Default |
|---|---|---|
| `validate` | Server-side fingerprint validation, no I/O | yes |
| `tsa-verify` | RFC 3161 timestamp token verification | yes |
| `collect-linux` | Client-side hardware fingerprint collection (Linux only) | no |
| `tpm` | TPM 2.0 support via tss-esapi | no |
| `tsa-clients` | TSA client implementations (makes network calls) | no |

The server depends on this crate with `features = ["validate", "tsa-clients"]`. The client depends on it with `features = ["validate", "collect-linux", "tsa-verify"]`. Same crate, different feature sets, no unnecessary code compiled on either side.

## System dependencies

Most features have no system dependencies beyond a Rust toolchain. The `tpm` feature is the exception.

### Fedora

```bash
sudo dnf install tpm2-tss-devel tpm2-abrmd
```

### Ubuntu

```bash
sudo apt-get install libtss2-dev tpm2-abrmd
```

## Platform

Linux x86_64 only. Hardware fingerprinting and the shim execution model are built on Linux-specific kernel interfaces. Other platforms are not in scope for this project. zlicenser-pro, a future commercial release, may support Windows and macOS.

## Related repositories

- [zlicenser](https://github.com/zal-analytics/zlicenser): client library, TUI, and GUI apps
- [zlicenser-server](https://github.com/zal-analytics/zlicenser-server): server library and vendor backend

## License

Apache-2.0, see [LICENSE](LICENSE).
