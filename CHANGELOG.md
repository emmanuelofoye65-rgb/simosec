# Changelog

## 0.1.0

Initial public release.

- Core pipeline: `SecurityEngine` + `SecurityLayer` interface, fail-fast,
  order-preserving, framework-agnostic.
- `PayloadSizeLayer` — configurable request size limit, rejects oversized
  payloads before any other processing.
- `SignatureLayer` — real HMAC-SHA256 signature verification
  (`CryptoUtils`), bound to request body + timestamp + userId, with
  clock-skew replay protection.
- `ValidationLayer` — structural validation and payload sanitization.
- `SandboxLayer` — dry-run simulation against mock account state.
- `RateLimitLayer` — sliding-window rate limiting backed by a pluggable
  `StorageAdapter`.
- `QuantumQuarantineLayer` — transparent, rule-based anomaly scoring with
  persistent known-device/IP history to avoid false positives for
  returning users.
- `AuthorizationLayer` — known-user, restricted-action, and per-user limit
  enforcement.
- `LoggingLayer` — structured audit logging with a pluggable sink.
- `StorageAdapter` interface with `MemoryStorage` (default) and
  `RedisStorage` (in-memory-backed until a real client is wired in).
- `SecurityConfig` for shared, tunable thresholds across layers.
- Full test suite covering signature verification, storage persistence,
  and payload size limits.
