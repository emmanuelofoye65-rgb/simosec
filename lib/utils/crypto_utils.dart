import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Real cryptographic signing/verification for SIMOSEC requests, backed by
/// HMAC-SHA256 via `package:crypto`.
///
/// Callers build a canonical `payload` map containing everything the
/// signature should cover — in SIMOSEC's case, the request body, the
/// timestamp, and the userId (see [SignatureLayer]) — and sign/verify that
/// map as a whole. Keeping signing/verification generic over "a payload
/// map" (rather than hardcoding body/timestamp/userId in this file) makes
/// the utility reusable for other signed-message use cases too.
class CryptoUtils {
  CryptoUtils._();

  /// Computes an HMAC-SHA256 signature (as a lowercase hex string) over
  /// [payload], keyed with [secret].
  static String signRequest(String secret, Map<String, dynamic> payload) {
    final message = _canonicalize(payload);
    final hmac = Hmac(sha256, utf8.encode(secret));
    return hmac.convert(utf8.encode(message)).toString();
  }

  /// Verifies that [signature] is the correct HMAC-SHA256 signature for
  /// [payload] under [secret], using a constant-time comparison to avoid
  /// timing side-channels.
  static bool verifySignature(
    String secret,
    Map<String, dynamic> payload,
    String? signature,
  ) {
    if (signature == null || signature.trim().isEmpty) return false;
    final expected = signRequest(secret, payload);
    return _constantTimeEquals(expected, signature.trim());
  }

  /// Encodes [value] into a stable string form so hashing is deterministic
  /// regardless of map key insertion order.
  static String _canonicalize(dynamic value) {
    if (value == null) return 'null';
    if (value is Map) {
      final sortedKeys = value.keys.map((k) => k.toString()).toList()..sort();
      final buffer = StringBuffer('{');
      for (final key in sortedKeys) {
        buffer.write('$key:${_canonicalize(value[key])};');
      }
      buffer.write('}');
      return buffer.toString();
    }
    if (value is Iterable) {
      return '[${value.map(_canonicalize).join(',')}]';
    }
    try {
      return jsonEncode(value);
    } catch (_) {
      return value.toString();
    }
  }

  static bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return result == 0;
  }
}
