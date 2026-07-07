import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_result.dart';
import '../utils/crypto_utils.dart';

/// LAYER 2 — Validates request authenticity using real HMAC-SHA256
/// signature verification (see [CryptoUtils]).
///
/// The signature is computed over a canonical payload containing the
/// **request body**, the **client-claimed timestamp** (`X-Timestamp`
/// header), and the **userId** — so a signature cannot be replayed against
/// a different body, a different time window, or a different user.
///
/// Requests are rejected when:
/// - The `X-Signature` header is missing or empty.
/// - The `X-Timestamp` header is missing or not a valid ISO-8601 timestamp.
/// - The timestamp is outside [maxClockSkew] of the server's receipt time
///   (basic replay protection — a valid, old signature can't be replayed
///   indefinitely).
/// - The computed HMAC-SHA256 signature does not match.
class SignatureLayer implements SecurityLayer {
  @override
  String get name => 'SignatureLayer';

  /// Shared secret used for HMAC-SHA256 signing/verification.
  final String secret;

  /// Maximum allowed difference between the client-claimed timestamp and
  /// the server's receipt time, before a signature is rejected as stale
  /// (basic replay-attack mitigation). Set to `null` to disable this
  /// check (not recommended for production).
  final Duration? maxClockSkew;

  /// Creates a signature layer that verifies requests against [secret].
  SignatureLayer({
    required this.secret,
    this.maxClockSkew = const Duration(minutes: 5),
  });

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final signature = context.signature;

    if (signature == null || signature.trim().isEmpty) {
      return SecurityResult.block(
        message: 'Missing request signature',
        flags: const ['missing_signature'],
        riskScore: 1.0,
      );
    }

    final signedAt = context.signedTimestamp;
    if (signedAt == null) {
      return SecurityResult.block(
        message: 'Missing or malformed X-Timestamp header',
        flags: const ['missing_timestamp'],
        riskScore: 1.0,
      );
    }

    if (maxClockSkew != null) {
      final skew = context.timestamp.difference(signedAt).abs();
      if (skew > maxClockSkew!) {
        return SecurityResult.block(
          message: 'Signature timestamp outside allowed clock skew '
              '(${skew.inSeconds}s)',
          flags: const ['stale_timestamp'],
          riskScore: 0.95,
        );
      }
    }

    final payload = <String, dynamic>{
      'body': context.body,
      'timestamp': signedAt.toIso8601String(),
      'userId': context.userId ?? '',
    };

    final isValid = CryptoUtils.verifySignature(secret, payload, signature);

    if (!isValid) {
      return SecurityResult.block(
        message: 'Invalid request signature',
        flags: const ['invalid_signature'],
        riskScore: 1.0,
      );
    }

    return SecurityResult.allow(message: 'Signature verified (HMAC-SHA256)');
  }
}
