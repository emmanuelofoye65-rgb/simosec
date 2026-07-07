# SIMOSEC

**Modular security engine for APIs and fintech apps.**

SIMOSEC (Simu Security Engine Core) is a pluggable, middleware-based
security pipeline for wallets, payment APIs, and any backend that needs
defense-in-depth against tampering, replay, abuse, and fraud — without
pulling in a heavyweight framework or an opaque ML black box.

Every request flows through an ordered chain of small, single-purpose
layers. Each layer either allows, flags, or blocks the request; the engine
fails fast the moment a layer blocks, and stays transparent about exactly
why a decision was made.

```dart
final result = await engine.process(context);
// result.verdict   -> allowed / flagged / blocked
// result.riskScore -> 0.0 .. 1.0
// result.flags     -> ['high_amount', 'new_device', ...]
```

## Features

- **Real HMAC-SHA256 signatures** — requests are cryptographically bound to
  their body, timestamp, and user ID, with constant-time verification and
  clock-skew replay protection. No simulated or placeholder crypto.
- **Payload size limiting** — oversized requests are rejected before any
  other layer runs, blunting size-based denial-of-service attempts.
- **Structural validation & sanitization** — malformed or empty payloads
  are rejected early; accepted payloads are sanitized for downstream use.
- **Dry-run sandboxing** — simulates a transaction against mock account
  state before it ever reaches your real backend.
- **Sliding-window rate limiting** — per-user and per-IP, backed by a
  pluggable storage layer so limits hold across multiple server instances.
- **Explainable anomaly detection** — a transparent, rule-based risk
  scorer (amount, frequency, device change, IP anomalies), not an opaque
  ML model. Known devices/IPs persist per user, so returning users aren't
  repeatedly flagged as suspicious.
- **Authorization enforcement** — known-user checks, restricted actions,
  and per-user transaction limits.
- **Structured audit logging** — every request's final outcome is logged
  through a pluggable sink.
- **Pluggable storage** — `MemoryStorage` out of the box; swap in Redis or
  any other backend by implementing one small interface.
- **Zero framework lock-in** — plain Dart, no HTTP framework dependency;
  drop it into any backend (`shelf`, `dart_frog`, a Cloud Function, etc).

## Architecture

```
lib/
├── core/
│   ├── security_engine.dart   # Orchestrates the pipeline
│   └── security_layer.dart    # The SecurityLayer interface
├── layers/
│   ├── payload_size_layer.dart     # 1. Request size limit (fail fast)
│   ├── signature_layer.dart        # 2. HMAC-SHA256 signature verification
│   ├── validation_layer.dart       # 3. Structural validation + sanitization
│   ├── sandbox_layer.dart          # 4. Dry-run simulation vs. mock state
│   ├── rate_limit_layer.dart       # 5. Per-user/IP rate limiting
│   ├── quantum_layer.dart          # 6. Rule-based anomaly detection
│   ├── authorization_layer.dart    # 7. User/action/limit enforcement
│   └── logging_layer.dart          # 8. Audit logging
├── models/
│   ├── request_context.dart   # Everything about the incoming request
│   ├── security_config.dart   # Shared, tunable thresholds
│   └── security_result.dart   # The verdict returned by a layer/engine
├── storage/
│   ├── storage_adapter.dart   # Pluggable key/value store interface
│   ├── memory_storage.dart    # Default, single-process implementation
│   └── redis_storage.dart     # Shared-store implementation for multi-instance deployments
└── utils/
    ├── validators.dart        # Small structural validation helpers
    ├── crypto_utils.dart      # HMAC-SHA256 signing/verification
    └── helpers.dart           # Sanitization + math helpers
```

Each layer implements a single method:

```dart
Future<SecurityResult> check(RequestContext context);
```

The `SecurityEngine` runs layers **in order** and **stops immediately** the
moment one blocks the request (fail-fast). `PayloadSizeLayer` runs first so
oversized requests are rejected before any signature or validation work is
done — this both saves CPU and blunts payload-size denial-of-service
attempts.

Adding a new layer requires no changes to the engine or existing layers —
just implement `SecurityLayer` and add it to the list:

```dart
class MyCustomLayer implements SecurityLayer {
  @override
  String get name => 'MyCustomLayer';

  @override
  Future<SecurityResult> check(RequestContext context) async {
    return SecurityResult.allow(message: 'OK');
  }
}
```

## Installation

```yaml
dependencies:
  simosec: ^0.1.0
```

```bash
dart pub add simosec
```

## Usage

```dart
import 'package:simosec/simosec.dart';

Future<void> main() async {
  const secret = 'my-shared-secret';
  const config = SecurityConfig(); // 1 MB payload limit, 0.8/0.5 risk thresholds

  final engine = SecurityEngine(layers: [
    PayloadSizeLayer(config: config),
    SignatureLayer(secret: secret),
    ValidationLayer(),
    SandboxLayer(mockBalances: {'user_1': 500.0}),
    RateLimitLayer(maxRequests: 20, storage: MemoryStorage()),
    QuantumQuarantineLayer(storage: MemoryStorage(), config: config),
    AuthorizationLayer(knownUserIds: {'user_1'}),
    LoggingLayer(),
  ]);

  // A client signs {body, timestamp, userId} with HMAC-SHA256 and sends
  // both the signature and the timestamp it signed with.
  final body = {'action': 'transfer', 'amount': 100, 'to': 'user_2'};
  final timestamp = DateTime.now().toUtc();
  final signature = CryptoUtils.signRequest(secret, {
    'body': body,
    'timestamp': timestamp.toIso8601String(),
    'userId': 'user_1',
  });

  final context = RequestContext(
    headers: {
      'X-Signature': signature,
      'X-Timestamp': timestamp.toIso8601String(),
    },
    body: body,
    userId: 'user_1',
    ipAddress: '203.0.113.10',
    deviceId: 'device-abc-123',
  );

  final result = await engine.process(context);

  if (result.allowed) {
    print('Allowed: ${result.message}');
  } else {
    print('Blocked: ${result.message}');
  }
}
```

See [`example/main.dart`](example/main.dart) for a fuller walkthrough
covering allow, block, and flag outcomes, and
[`example/manual_validation.dart`](example/manual_validation.dart) for an
extensive scenario/edge-case validation script.

### Signature verification (HMAC-SHA256)

`SignatureLayer` verifies HMAC-SHA256 signatures via `package:crypto` (see
`CryptoUtils`). The signed payload always covers three things together, so
a signature can't be replayed against a different body, time window, or
user:

- **request body** (`context.body`)
- **timestamp** — the client-claimed signing time, carried in the
  `X-Timestamp` header (`context.signedTimestamp`), distinct from
  `context.timestamp` (the server's own receipt time, used for rate
  limiting/logging)
- **userId** (`context.userId`)

Requests are rejected when the signature is missing, the `X-Timestamp`
header is missing/malformed, the timestamp is outside `SignatureLayer`'s
`maxClockSkew` (default 5 minutes — basic replay protection), or the
computed signature doesn't match (constant-time comparison).

### Persistent storage

`RateLimitLayer` and `QuantumQuarantineLayer` read/write state through a
pluggable `StorageAdapter` rather than holding it in a local `Map`:

```dart
abstract class StorageAdapter {
  Future<void> set(String key, dynamic value);
  Future<dynamic> get(String key);
  Future<void> delete(String key);
}
```

- **`MemoryStorage`** — the default. Zero setup, single-process,
  dependency-free. Good for local dev, tests, and single-instance
  deployments.
- **`RedisStorage`** — the shape for a shared, multi-instance backend.
  SIMOSEC doesn't take a hard dependency on a Redis client so the core
  package stays lightweight; wire a real client (e.g. `package:redis`)
  behind the same three methods for production.

Pass the **same** `StorageAdapter` instance to every engine
instance/process that should share rate-limit counters and device/IP
history (e.g. multiple API server instances behind a load balancer).

### Configuration

```dart
class SecurityConfig {
  final int maxPayloadSize;    // default 1 MiB
  final double blockThreshold; // default 0.8
  final double flagThreshold;  // default 0.5
}
```

Pass one `SecurityConfig` to `PayloadSizeLayer` and `QuantumQuarantineLayer`
to keep thresholds consistent; individual layers still accept explicit
overrides (e.g. `QuantumQuarantineLayer(blockThreshold: 0.9)`) when you need
one layer to diverge from the shared config.

## Performance

Benchmarked with 1,000 sequential signed requests through the full 8-layer
pipeline (signature verification, validation, sandbox simulation, rate
limiting, anomaly scoring, authorization, logging) on a single core:

| Metric  | Latency   |
| ------- | --------- |
| Average | ~0.48 ms  |
| p50     | ~0.22 ms  |
| p95     | ~1.9 ms   |
| Max     | ~6.4 ms   |

Reproduce locally:

```bash
dart run example/manual_validation.dart
```

## Production notes

- Keep the shared HMAC secret out of source control (use a secrets
  manager / environment variable).
- Use `MemoryStorage` for single-instance deployments, or wire a real
  Redis (or other shared store) client into `RedisStorage` for
  multi-instance deployments so rate-limit and anomaly-detection state is
  consistent across instances.
- `SandboxLayer`'s mock balances and `AuthorizationLayer`'s known-user set
  are in-memory placeholders for demo purposes — back these with your real
  account/user store in production.
- `LoggingLayer` uses `print` by default — pass a custom `sink` to forward
  logs to your real logging/observability stack.

## Development

```bash
dart pub get
dart analyze
dart test
dart run example/main.dart
dart run example/manual_validation.dart
```

## CI

Every push to `main` and every pull request runs three jobs automatically
via [GitHub Actions](.github/workflows/ci.yml):

| Job | What it does |
| --- | --- |
| **Analyze & Test (stable)** | `dart format` check → `dart analyze` → `dart test` |
| **Analyze & Test (beta)** | Same checks on the Dart beta channel, so you catch breakage early |
| **Version bump reminder** | Compares `pubspec.yaml` version against pub.dev; **fails the build** if the version is already published — a hard reminder to bump before you release |

A green CI badge on `main` means the package analyzes cleanly, all 21
tests pass, and the version is ready to publish.

**Rules for contributors:**

- All three jobs must be green before merging to `main`.
- Any new public API needs a doc comment — `dart analyze` will catch it.
- Any new layer or behavior needs a test — `dart test` will catch regressions.

## Publishing a new version to pub.dev

Follow this checklist every time you want to ship a new release:

### 1. Make and merge your changes

Develop on a branch, open a PR, confirm CI is green, then merge.

### 2. Bump the version in `pubspec.yaml`

SIMOSEC follows [semantic versioning](https://semver.org):

| Change type | Example bump |
| --- | --- |
| Bug fix or docs only | `0.1.0` → `0.1.1` |
| New layer / new API (backward-compatible) | `0.1.0` → `0.2.0` |
| Breaking change to existing API | `0.1.0` → `1.0.0` |

```yaml
# pubspec.yaml
version: 0.2.0   # was 0.1.0
```

### 3. Update `CHANGELOG.md`

Add a section at the top following the existing format:

```markdown
## 0.2.0

- Added `ThrottleLayer` for per-endpoint rate limiting.
- Fixed: `SignatureLayer` now rejects empty `X-Timestamp` headers.
```

### 4. Push to main — CI runs automatically

The version-check job will now show **green** (new version ≠ published
version). If it's still red, you forgot to bump the version.

### 5. Log in to pub.dev (one-time setup per machine)

```bash
dart pub login
# Opens a browser tab — sign in with your Google account
```

### 6. Publish

Run this from inside the `simosec/` directory:

```bash
dart pub publish
```

You'll see a file listing and a confirmation prompt:

```
Publishing simosec 0.2.0 to https://pub.dev ...
Do you want to publish simosec 0.2.0? (y/N)
```

Type `y` and press Enter. The package is live within seconds.

### 7. Tag the release on GitHub

```bash
git tag v0.2.0
git push origin v0.2.0
```

Then create a GitHub Release from the tag so users can see a clean
changelog entry alongside the pub.dev listing.

---

**Never publish without a green CI run and a version bump.**
The `version-check` job is there to enforce this — treat a red badge as
a hard stop.

## Contributing

Issues and pull requests are welcome. Please run `dart analyze` and
`dart test` before submitting a PR, and keep new layers documented and
covered by tests.

## License

[MIT](LICENSE)
