import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_config.dart';
import '../models/security_result.dart';
import '../storage/memory_storage.dart';
import '../storage/storage_adapter.dart';
import '../utils/helpers.dart';
import '../utils/validators.dart';

/// Feature vector extracted from a request for anomaly scoring.
/// Exposed publicly so consumers can inspect why a score was assigned.
class RiskFeatures {
  /// The transaction amount extracted from the request body, or `0.0`
  /// when no amount field is present.
  final double amount;

  /// How many requests this key (user/IP) has made within the current
  /// rate-limit window, as populated by [RateLimitLayer] via metadata.
  final int requestFrequency;

  /// Whether this is the first time this device has been seen for the
  /// requesting user.
  final bool isNewDevice;

  /// Whether this is the first time this IP address has been seen for
  /// the requesting user.
  final bool isIpAnomaly;

  /// Creates a feature vector for anomaly scoring.
  const RiskFeatures({
    required this.amount,
    required this.requestFrequency,
    required this.isNewDevice,
    required this.isIpAnomaly,
  });

  /// Serializes this feature vector to a JSON-compatible map.
  Map<String, dynamic> toJson() => {
        'amount': amount,
        'requestFrequency': requestFrequency,
        'isNewDevice': isNewDevice,
        'isIpAnomaly': isIpAnomaly,
      };
}

/// LAYER 6 — QuantumQuarantineLayer: a lightweight, rule-based anomaly
/// detector. Despite the name, this deliberately avoids heavy AI/ML —
/// it's a transparent, explainable scoring function over a handful of
/// simple features:
///
/// - transaction amount
/// - request frequency (populated by [RateLimitLayer] via metadata)
/// - device change (is this device new for the user?)
/// - IP anomalies (is this IP new/unexpected for the user?)
///
/// Known devices/IPs per user are tracked in a pluggable [StorageAdapter],
/// so "new device" detection is accurate across restarts and, when backed
/// by a shared adapter, across multiple server instances — a returning
/// user is only ever flagged as "new_device" the very first time a given
/// device is seen, never again afterwards.
///
/// Scoring rules:
/// - High amount + new device increases the score.
/// - High request frequency increases the score.
/// - New/unexpected IP increases the score.
///
/// Thresholds (from [SecurityConfig] unless overridden):
/// - score > blockThreshold (default 0.8) → block
/// - score > flagThreshold (default 0.5)  → flag (allowed, but marked for review)
/// - else                                  → allow
class QuantumQuarantineLayer implements SecurityLayer {
  @override
  String get name => 'QuantumQuarantineLayer';

  /// Amount above which a transaction is considered "high value" for
  /// scoring purposes.
  final double highAmountThreshold;

  /// Request-frequency threshold above which volume is considered
  /// suspicious for scoring purposes (independent of the hard rate
  /// limit enforced in [RateLimitLayer]).
  final int highFrequencyThreshold;

  /// Persistent store of known devices/IPs per user. Defaults to
  /// [MemoryStorage]; pass a shared adapter for multi-instance
  /// deployments so device/IP history isn't lost or duplicated per
  /// instance.
  final StorageAdapter storage;

  /// Risk score above which a request is blocked outright. Defaults to
  /// [SecurityConfig.blockThreshold] unless explicitly overridden.
  final double blockThreshold;

  /// Risk score above which a request is allowed but flagged for review.
  /// Defaults to [SecurityConfig.flagThreshold] unless explicitly
  /// overridden.
  final double flagThreshold;

  /// Creates an anomaly-detection layer, defaulting to [MemoryStorage]
  /// and the thresholds in [config] unless explicitly overridden.
  QuantumQuarantineLayer({
    this.highAmountThreshold = 1000,
    this.highFrequencyThreshold = 10,
    StorageAdapter? storage,
    SecurityConfig config = const SecurityConfig(),
    double? blockThreshold,
    double? flagThreshold,
  })  : storage = storage ?? MemoryStorage(),
        blockThreshold = blockThreshold ?? config.blockThreshold,
        flagThreshold = flagThreshold ?? config.flagThreshold;

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final body = context.getMeta<dynamic>('sanitizedBody') ?? context.body;
    final amount = Validators.extractAmount(body) ?? 0.0;
    final requestFrequency = context.getMeta<int>('requestFrequency') ?? 1;

    final isNewDevice = await _isNewDevice(context);
    final isIpAnomaly = await _isIpAnomaly(context);

    final features = RiskFeatures(
      amount: amount,
      requestFrequency: requestFrequency,
      isNewDevice: isNewDevice,
      isIpAnomaly: isIpAnomaly,
    );
    context.setMeta('riskFeatures', features.toJson());

    final score = _computeRiskScore(features);
    context.setMeta('riskScore', score);

    // Record this device/IP as known for the user going forward, so
    // repeat requests from the same device/IP are no longer "new".
    await _rememberDeviceAndIp(context);

    final flags = <String>[];
    if (features.amount > highAmountThreshold) flags.add('high_amount');
    if (features.isNewDevice) flags.add('new_device');
    if (features.isIpAnomaly) flags.add('ip_anomaly');
    if (features.requestFrequency > highFrequencyThreshold) {
      flags.add('high_frequency');
    }

    if (score > blockThreshold) {
      return SecurityResult.block(
        message: 'Anomaly score too high (${score.toStringAsFixed(2)})',
        flags: flags,
        riskScore: score,
      );
    }

    if (score > flagThreshold) {
      return SecurityResult.flag(
        message:
            'Request flagged for review (score ${score.toStringAsFixed(2)})',
        flags: flags,
        riskScore: score,
      );
    }

    return SecurityResult.allow(
      message: 'No significant anomaly detected',
      riskScore: score,
      flags: flags,
    );
  }

  Future<bool> _isNewDevice(RequestContext context) async {
    final userId = context.userId;
    if (userId == null) return true;
    final devices = await _readSet('quantum:devices:$userId');
    if (devices.isEmpty) return true;
    return !devices.contains(context.deviceId);
  }

  Future<bool> _isIpAnomaly(RequestContext context) async {
    final userId = context.userId;
    if (userId == null) return true;
    final ips = await _readSet('quantum:ips:$userId');
    if (ips.isEmpty) return true;
    return !ips.contains(context.ipAddress);
  }

  Future<void> _rememberDeviceAndIp(RequestContext context) async {
    final userId = context.userId;
    if (userId == null) return;

    final devices = await _readSet('quantum:devices:$userId');
    devices.add(context.deviceId);
    await storage.set('quantum:devices:$userId', devices.toList());

    final ips = await _readSet('quantum:ips:$userId');
    ips.add(context.ipAddress);
    await storage.set('quantum:ips:$userId', ips.toList());
  }

  Future<Set<String>> _readSet(String key) async {
    final raw = await storage.get(key);
    if (raw is List) return raw.map((e) => e.toString()).toSet();
    return <String>{};
  }

  /// Simple, explainable weighted-rule scoring function (no ML model).
  double _computeRiskScore(RiskFeatures features) {
    double score = 0.0;

    // High amount alone raises risk moderately.
    if (features.amount > highAmountThreshold) {
      score += 0.3;
    }

    // High amount + new device is a strong combined signal.
    if (features.amount > highAmountThreshold && features.isNewDevice) {
      score += 0.3;
    } else if (features.isNewDevice) {
      score += 0.15;
    }

    // Excess request frequency raises risk.
    if (features.requestFrequency > highFrequencyThreshold) {
      score += 0.25;
    }

    // Unexpected IP raises risk.
    if (features.isIpAnomaly) {
      score += 0.2;
    }

    return Helpers.clampRisk(score);
  }
}
