# zlicenser-protocol

Shared protocol types, wire formats, cryptographic primitives, and hardware fingerprinting for the [zlicenser](https://github.com/zal-analytics/zlicenser) licensing framework.

## Overview

This crate is the authoritative source for everything that crosses the wire between a `zlicenser` client and a `zlicenser-server` vendor backend. It is consumed by both as a crates.io dependency with different feature sets.

## Related repositories

- [zlicenser](https://github.com/zal-analytics/zlicenser): client library and user-facing apps
- [zlicenser-server](https://github.com/zal-analytics/zlicenser-server): server library and vendor backend

## Features

| Feature | Description | Default |
|---|---|---|
| `validate` | Server-side fingerprint validation (no I/O) | yes |
| `tsa-verify` | RFC 3161 timestamp token verification | yes |
| `collect-linux` | Client-side hardware fingerprint collection (Linux) | no |
| `tpm` | Optional TPM 2.0 support | no |
| `tsa-clients` | TSA client implementations (network) | no |

## System dependencies for the `tpm` feature

The `tpm` feature requires TPM 2.0 system libraries to be installed before building.

### Fedora

```bash
sudo dnf install tpm2-tss-devel tpm2-abrmd
```

### Ubuntu

```bash
sudo apt-get update
sudo apt-get install libtss2-dev tpm2-abrmd
```

### Verify installation

```bash
# Fedora
rpm -qa | grep -E 'tss2|tpm2'

# Ubuntu
dpkg -l | grep -E 'tss2|tpm2'
```

## License

Apache-2.0, see [LICENSE](LICENSE).
