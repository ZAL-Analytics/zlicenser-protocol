# zlicenser-protocol

Shared protocol types and communication logic between [zlicenser](https://github.com/arsalan-anwari/zlicenser) (client-side) and [zlicenser-server](https://github.com/arsalan-anwari/zlicenser-server) (vendor-side backend).

> This crate is under development. Crate name reserved in the meantime.

---

## What is this crate?

`zlicenser-protocol` is the shared library that both the vendor-hosted server and the end-user client depend on. It defines the wire types, request/response structures, and communication logic used across the zlicenser ecosystem.

The broader zlicenser project is an open-source Rust licensing framework for commercial software. It produces per-customer encrypted builds bound to a hardware fingerprint, so every copy a vendor ships is cryptographically attributable to the customer who received it — running entirely in user space, with no kernel modules or elevated privileges required.

## Role in the ecosystem

| Crate | Role |
|---|---|
| [`zlicenser`](https://github.com/arsalan-anwari/zlicenser) | Client-side: hardware fingerprinting, decryption shim, launcher, and vendor GUI |
| [`zlicenser-server`](https://github.com/arsalan-anwari/zlicenser-server) | Server-side: license management, usage tracking, request validation, and payment/timekeeping |
| `zlicenser-protocol` *(this crate)* | Shared: wire types, request/response structs, and communication logic used by both sides |

## Planned scope

- License issuance request and response types
- Revocation and re-enrollment message types
- Hardware fingerprint envelope format
- Serialization and versioning helpers
- Shared error and status codes

## Status

| Component | Status |
|---|---|
| Wire types | Planned |
| Request / response structs | Planned |
| Fingerprint envelope | Planned |
| Serialization helpers | Planned |
| Versioning | Planned |

---

## License

Apache-2.0. See [LICENSE](LICENSE).
