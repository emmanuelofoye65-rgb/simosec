/// Centralized, tunable configuration shared across layers.
///
/// Individual layers still accept their own constructor overrides (e.g.
/// [PayloadSizeLayer.maxPayloadSize]) for fine-grained control, but default
/// to the values here when no explicit override is given. Pass a single
/// [SecurityConfig] instance to every layer you build to keep thresholds
/// consistent across the pipeline.
class SecurityConfig {
  /// Maximum accepted request payload size, in bytes. Requests larger than
  /// this are rejected by [PayloadSizeLayer] before any other processing.
  final int maxPayloadSize;

  /// Risk score above which [QuantumQuarantineLayer] blocks a request
  /// outright.
  final double blockThreshold;

  /// Risk score above which [QuantumQuarantineLayer] flags a request for
  /// review without blocking it.
  final double flagThreshold;

  /// Creates a configuration. Defaults to a 1 MB payload limit and
  /// block/flag thresholds of 0.8/0.5.
  const SecurityConfig({
    this.maxPayloadSize = 1024 * 1024, // 1 MB
    this.blockThreshold = 0.8,
    this.flagThreshold = 0.5,
  })  : assert(maxPayloadSize > 0, 'maxPayloadSize must be positive'),
        assert(
          flagThreshold <= blockThreshold,
          'flagThreshold must be <= blockThreshold',
        );

  /// Returns a copy of this configuration with the given fields replaced.
  SecurityConfig copyWith({
    int? maxPayloadSize,
    double? blockThreshold,
    double? flagThreshold,
  }) {
    return SecurityConfig(
      maxPayloadSize: maxPayloadSize ?? this.maxPayloadSize,
      blockThreshold: blockThreshold ?? this.blockThreshold,
      flagThreshold: flagThreshold ?? this.flagThreshold,
    );
  }

  @override
  String toString() {
    return 'SecurityConfig('
        'maxPayloadSize: $maxPayloadSize, '
        'blockThreshold: $blockThreshold, '
        'flagThreshold: $flagThreshold)';
  }
}
