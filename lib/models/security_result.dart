/// The overall verdict a [SecurityResult] can carry.
///
/// A layer (or the engine as a whole) can either let a request through,
/// block it outright, or allow it while flagging it for further review.
enum SecurityVerdict {
  /// The request passed every layer with no significant concerns.
  allowed,

  /// The request was rejected outright by a layer.
  blocked,

  /// The request was allowed to continue but marked for manual review.
  flagged,
}

/// The outcome produced by a single [SecurityLayer] or by the
/// [SecurityEngine] after running the full pipeline.
///
/// This is intentionally a plain, immutable data class so it is cheap to
/// create, easy to log, and trivial to serialize if needed later.
class SecurityResult {
  /// Whether the request is allowed to continue through the pipeline.
  final bool allowed;

  /// A normalized risk score between 0.0 (no risk) and 1.0 (maximum risk).
  final double riskScore;

  /// Human-readable flags describing why a layer reacted the way it did.
  /// Example: `"missing_signature"`, `"rate_limit_exceeded"`.
  final List<String> flags;

  /// A short human-readable explanation of the decision.
  final String message;

  /// The verdict derived from [allowed] and [riskScore]. Layers can set
  /// this explicitly, or rely on [SecurityResult.allow]/[block]/[flag]
  /// factories which set it consistently.
  final SecurityVerdict verdict;

  /// The name of the layer that produced this result. Populated by the
  /// engine when aggregating results; individual layers may leave it null.
  final String? layerName;

  /// Creates a result. Prefer the [allow], [block], or [flag] factories
  /// for consistent verdict/allowed pairing.
  const SecurityResult({
    required this.allowed,
    required this.riskScore,
    required this.flags,
    required this.message,
    required this.verdict,
    this.layerName,
  });

  /// Convenience constructor for a fully allowed result.
  factory SecurityResult.allow({
    double riskScore = 0.0,
    List<String> flags = const [],
    String message = 'OK',
    String? layerName,
  }) {
    return SecurityResult(
      allowed: true,
      riskScore: riskScore,
      flags: flags,
      message: message,
      verdict: SecurityVerdict.allowed,
      layerName: layerName,
    );
  }

  /// Convenience constructor for a blocked (rejected) result.
  factory SecurityResult.block({
    double riskScore = 1.0,
    List<String> flags = const [],
    required String message,
    String? layerName,
  }) {
    return SecurityResult(
      allowed: false,
      riskScore: riskScore,
      flags: flags,
      message: message,
      verdict: SecurityVerdict.blocked,
      layerName: layerName,
    );
  }

  /// Convenience constructor for a result that is allowed to continue but
  /// flagged for review (e.g. suspicious but not conclusive).
  factory SecurityResult.flag({
    required double riskScore,
    List<String> flags = const [],
    required String message,
    String? layerName,
  }) {
    return SecurityResult(
      allowed: true,
      riskScore: riskScore,
      flags: flags,
      message: message,
      verdict: SecurityVerdict.flagged,
      layerName: layerName,
    );
  }

  /// Returns a copy of this result with the given [layerName] attached.
  SecurityResult withLayerName(String name) {
    return SecurityResult(
      allowed: allowed,
      riskScore: riskScore,
      flags: flags,
      message: message,
      verdict: verdict,
      layerName: name,
    );
  }

  @override
  String toString() {
    return 'SecurityResult('
        'layer: ${layerName ?? '-'}, '
        'verdict: ${verdict.name}, '
        'allowed: $allowed, '
        'riskScore: ${riskScore.toStringAsFixed(2)}, '
        'flags: $flags, '
        'message: "$message")';
  }

  /// Serializes this result to a JSON-compatible map.
  Map<String, dynamic> toJson() {
    return {
      'allowed': allowed,
      'riskScore': riskScore,
      'flags': flags,
      'message': message,
      'verdict': verdict.name,
      'layerName': layerName,
    };
  }
}
