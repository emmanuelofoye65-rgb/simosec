import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_result.dart';
import '../storage/memory_storage.dart';
import '../storage/storage_adapter.dart';

/// LAYER 5 — Tracks request frequency per user/IP and blocks excessive
/// requests using a sliding-window counter, backed by a pluggable
/// [StorageAdapter].
///
/// Defaults to [MemoryStorage] (single-process, dependency-free). Pass a
/// shared [StorageAdapter] (e.g. a Redis-backed one) to keep rate-limit
/// state consistent across multiple server instances.
class RateLimitLayer implements SecurityLayer {
  @override
  String get name => 'RateLimitLayer';

  /// Maximum number of requests allowed per key within [window] before
  /// subsequent requests are blocked.
  final int maxRequests;

  /// The sliding time window over which requests are counted.
  final Duration window;

  /// Persistent store of per-key hit timestamps. Defaults to
  /// [MemoryStorage]; pass a shared adapter for multi-instance
  /// deployments so rate-limit counters aren't reset per instance.
  final StorageAdapter storage;

  /// Creates a rate-limit layer, defaulting to [MemoryStorage] unless a
  /// shared [storage] adapter is provided.
  RateLimitLayer({
    this.maxRequests = 20,
    this.window = const Duration(minutes: 1),
    StorageAdapter? storage,
  }) : storage = storage ?? MemoryStorage();

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final now = context.timestamp;

    final userKey =
        context.userId != null ? 'ratelimit:user:${context.userId}' : null;
    final ipKey = 'ratelimit:ip:${context.ipAddress}';

    final userCount = userKey != null ? await _recordAndCount(userKey, now) : 0;
    final ipCount = await _recordAndCount(ipKey, now);

    final requestCount = userCount > ipCount ? userCount : ipCount;
    context.setMeta('requestFrequency', requestCount);

    if (requestCount > maxRequests) {
      return SecurityResult.block(
        message: 'Rate limit exceeded ($requestCount requests within '
            '${window.inSeconds}s)',
        flags: const ['rate_limit_exceeded'],
        riskScore: 0.85,
      );
    }

    return SecurityResult.allow(message: 'Within rate limit');
  }

  /// Records a hit for [key] at [now] and returns the number of hits still
  /// within [window]. Stores the sliding-window hit list (as epoch millis)
  /// directly via [storage], so state survives across requests/instances
  /// when backed by a shared adapter.
  Future<int> _recordAndCount(String key, DateTime now) async {
    final raw = await storage.get(key);
    final hits = <int>[
      if (raw is List)
        for (final v in raw)
          if (v is int) v,
    ];

    hits.removeWhere(
      (t) =>
          now.difference(DateTime.fromMillisecondsSinceEpoch(t, isUtc: true)) >
          window,
    );
    hits.add(now.millisecondsSinceEpoch);

    await storage.set(key, hits);
    return hits.length;
  }
}
