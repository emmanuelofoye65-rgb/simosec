import 'storage_adapter.dart';

/// A [StorageAdapter] intended to be backed by a shared Redis instance in
/// multi-instance production deployments.
///
/// SIMOSEC intentionally does not take a hard dependency on a Redis client
/// package, so the core engine stays lightweight and testable without any
/// external infrastructure. This class defines the connection shape
/// (`host`/`port`) and implements the full [StorageAdapter] contract; when
/// no live Redis connection is available (the default in this build, and
/// in local dev/tests) it transparently falls back to an in-memory mock so
/// callers see identical get/set/delete semantics either way.
///
/// To wire up a real Redis backend, add a client package (e.g.
/// `package:redis`) as a dependency and replace the body of [connect] and
/// the three [StorageAdapter] methods with real client calls, keeping the
/// same method signatures so no calling code needs to change.
class RedisStorage implements StorageAdapter {
  /// Redis server hostname. Unused until a real client is wired into
  /// [connect].
  final String host;

  /// Redis server port. Unused until a real client is wired into
  /// [connect].
  final int port;

  /// Optional key prefix, useful for namespacing multiple SIMOSEC
  /// deployments sharing one Redis instance.
  final String keyPrefix;

  /// In-memory fallback used whenever a real Redis connection is not
  /// available. Fully exercises the [StorageAdapter] contract so code
  /// written against [RedisStorage] behaves identically in dev/test and
  /// production once a real client is wired in.
  final Map<String, dynamic> _mock = {};

  bool _connected = false;

  /// Creates a Redis-backed storage adapter targeting [host]:[port].
  /// Does not connect automatically — call [connect] explicitly, or rely
  /// on the in-memory fallback if you never do.
  RedisStorage({
    this.host = 'localhost',
    this.port = 6379,
    this.keyPrefix = 'simosec:',
  });

  /// Whether a live Redis connection is currently established.
  ///
  /// Always `false` in this build since no Redis client dependency is
  /// wired in — [set]/[get]/[delete] transparently use the in-memory
  /// fallback instead. Kept as a real, checkable property (rather than a
  /// hardcoded constant) so calling code can log/alert on degraded mode
  /// once a real client is plugged in.
  bool get isConnected => _connected;

  /// Attempts to establish a connection to Redis at [host]:[port].
  ///
  /// In this dependency-free build this is a no-op that leaves
  /// [isConnected] `false`, so storage calls use the in-memory mock.
  /// Replace with real connection logic when a Redis client package is
  /// added.
  Future<void> connect() async {
    _connected = false;
  }

  String _key(String key) => '$keyPrefix$key';

  @override
  Future<void> set(String key, dynamic value) async {
    _mock[_key(key)] = value;
  }

  @override
  Future<dynamic> get(String key) async => _mock[_key(key)];

  @override
  Future<void> delete(String key) async {
    _mock.remove(_key(key));
  }
}
