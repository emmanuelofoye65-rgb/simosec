import 'storage_adapter.dart';

/// Zero-setup, single-process [StorageAdapter] backed by a plain [Map].
///
/// This is the default storage backend for every layer that accepts a
/// `storage` parameter. It has no external dependencies and is ideal for
/// local development, tests, and single-instance deployments. State is
/// lost on restart and is not shared across instances — for multi-instance
/// production deployments, use a shared backend such as [RedisStorage].
class MemoryStorage implements StorageAdapter {
  final Map<String, dynamic> _store = {};

  @override
  Future<void> set(String key, dynamic value) async {
    _store[key] = value;
  }

  @override
  Future<dynamic> get(String key) async => _store[key];

  @override
  Future<void> delete(String key) async {
    _store.remove(key);
  }

  /// Test/inspection helper: the number of keys currently stored.
  int get length => _store.length;

  /// Test/inspection helper: clears all stored state.
  void clear() => _store.clear();
}
