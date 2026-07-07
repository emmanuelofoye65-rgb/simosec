/// The unit of work that flows through the security pipeline.
///
/// A [RequestContext] represents a single incoming request (e.g. an API
/// call, a wallet transaction, a login attempt) as it travels through each
/// [SecurityLayer]. It is intentionally mutable in one place only —
/// [metadata] — so layers can pass derived data (like computed risk
/// features) to later layers without redesigning the model.
class RequestContext {
  /// Raw request headers (e.g. `Authorization`, `X-Signature`).
  final Map<String, String> headers;

  /// The request payload. Typically a decoded JSON map, but left as
  /// `dynamic` so the engine can be used for any transport shape.
  final dynamic body;

  /// The authenticated (or claimed) user performing the request.
  /// May be null for anonymous/unauthenticated requests.
  final String? userId;

  /// The originating IP address of the request.
  final String ipAddress;

  /// A stable identifier for the originating device, used for
  /// device-change and fraud heuristics.
  final String deviceId;

  /// When the request was received.
  final DateTime timestamp;

  /// Free-form bag for cross-layer state. Layers may read and write to
  /// this map to share derived information (e.g. computed risk scores,
  /// sanitized payloads) with layers that run later in the pipeline.
  final Map<String, dynamic> metadata;

  /// Creates a request context. [ipAddress] and [deviceId] are required;
  /// everything else is optional and defaults sensibly (e.g. [timestamp]
  /// defaults to the current UTC time).
  RequestContext({
    Map<String, String>? headers,
    this.body,
    this.userId,
    required this.ipAddress,
    required this.deviceId,
    DateTime? timestamp,
    Map<String, dynamic>? metadata,
  })  : headers = headers ?? const {},
        timestamp = timestamp ?? DateTime.now().toUtc(),
        metadata = metadata ?? <String, dynamic>{};

  /// Convenience getter for the signature/auth header, checked in a
  /// case-insensitive way since header casing varies by client/proxy.
  String? get signature =>
      headers['X-Signature'] ??
      headers['x-signature'] ??
      headers['Authorization'] ??
      headers['authorization'];

  /// The timestamp the *client* claims to have signed the request at,
  /// carried in the `X-Timestamp` header. This is distinct from
  /// [timestamp] (the server's receipt time, used for rate limiting and
  /// logging): signature verification must use the timestamp the client
  /// actually signed, not the time the server happened to receive the
  /// request, or every signature would fail to verify.
  ///
  /// Returns `null` if the header is missing or not a valid ISO-8601
  /// timestamp.
  DateTime? get signedTimestamp {
    final raw = headers['X-Timestamp'] ?? headers['x-timestamp'];
    if (raw == null) return null;
    return DateTime.tryParse(raw);
  }

  /// Reads a value from [metadata], returning null if absent.
  T? getMeta<T>(String key) => metadata[key] as T?;

  /// Writes a value into [metadata]. Used by layers to hand derived data
  /// (e.g. `riskFeatures`, `sanitizedBody`) to downstream layers.
  void setMeta(String key, dynamic value) {
    metadata[key] = value;
  }

  @override
  String toString() {
    return 'RequestContext('
        'userId: $userId, '
        'ipAddress: $ipAddress, '
        'deviceId: $deviceId, '
        'timestamp: ${timestamp.toIso8601String()})';
  }
}
