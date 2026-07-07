import 'dart:math';

/// Miscellaneous helpers shared across layers: payload sanitization and
/// small math utilities for the risk engine.
///
/// Signing/verification lives in [CryptoUtils] (real HMAC-SHA256, via
/// `package:crypto`) rather than here.
class Helpers {
  Helpers._();

  /// Recursively strips control characters and trims strings within a
  /// payload (map, list, or scalar), returning a sanitized deep copy.
  /// This is a lightweight defense against injection-style payloads —
  /// it does not replace proper output encoding at the data-sink layer.
  static dynamic sanitize(dynamic value) {
    if (value is String) {
      final withoutControlChars = value.replaceAll(
        RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F]'),
        '',
      );
      return withoutControlChars.trim();
    }
    if (value is Map) {
      return value.map((key, val) => MapEntry(key, sanitize(val)));
    }
    if (value is List) {
      return value.map(sanitize).toList();
    }
    return value;
  }

  /// Clamps [value] into the inclusive `[0.0, 1.0]` risk-score range.
  static double clampRisk(double value) {
    return min(1.0, max(0.0, value));
  }
}
