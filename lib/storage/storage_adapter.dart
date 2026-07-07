/// A pluggable key/value storage interface used by layers that need state
/// to persist beyond a single process (rate-limit counters, known-device
/// history, known-IP history, etc).
///
/// Implement this against whatever backing store fits your deployment —
/// Redis, a database, a distributed cache — and pass it into the layers
/// that accept a `storage` parameter. [MemoryStorage] is the zero-setup
/// default, suitable for single-instance deployments, local dev, and
/// tests. For multi-instance production deployments, use a shared
/// implementation (see [RedisStorage]) so state is consistent across
/// instances.
abstract class StorageAdapter {
  /// Stores [value] under [key], overwriting any existing value.
  Future<void> set(String key, dynamic value);

  /// Retrieves the value stored under [key], or `null` if absent.
  Future<dynamic> get(String key);

  /// Removes the value stored under [key], if any.
  Future<void> delete(String key);
}
