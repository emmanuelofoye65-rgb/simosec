import 'dart:convert';

import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_config.dart';
import '../models/security_result.dart';

/// LAYER 1 — Rejects oversized request payloads before any other work is
/// done.
///
/// This is deliberately the **first** layer in the pipeline: it is the
/// cheapest possible check (a single size measurement) and runs before
/// signature verification, sanitization, or any other processing that
/// would otherwise spend CPU on a payload that's going to be rejected
/// anyway. This also blunts a class of denial-of-service attempts where an
/// attacker sends huge bodies specifically to make expensive downstream
/// work (HMAC computation, deep sanitization) costly.
class PayloadSizeLayer implements SecurityLayer {
  @override
  String get name => 'PayloadSizeLayer';

  /// Maximum accepted payload size, in bytes. Defaults to
  /// [SecurityConfig.maxPayloadSize] (1 MB) unless overridden.
  final int maxPayloadSize;

  /// Creates a payload size layer, defaulting to [config]'s
  /// `maxPayloadSize` unless [maxPayloadSize] is explicitly given.
  PayloadSizeLayer({
    SecurityConfig config = const SecurityConfig(),
    int? maxPayloadSize,
  }) : maxPayloadSize = maxPayloadSize ?? config.maxPayloadSize;

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final size = _estimateSizeBytes(context.body);
    context.setMeta('payloadSize', size);

    if (size > maxPayloadSize) {
      return SecurityResult.block(
        message: 'Payload size ($size bytes) exceeds maximum allowed '
            '($maxPayloadSize bytes)',
        flags: const ['payload_too_large'],
        riskScore: 0.9,
      );
    }

    return SecurityResult.allow(message: 'Payload size within limits');
  }

  /// Estimates the on-the-wire size of [body] in bytes. Strings are
  /// measured directly (as UTF-8); everything else is measured via its
  /// JSON encoding, which is the shape the payload would actually take
  /// over the wire in a typical JSON API.
  int _estimateSizeBytes(dynamic body) {
    if (body == null) return 0;
    if (body is String) return utf8.encode(body).length;
    try {
      return utf8.encode(jsonEncode(body)).length;
    } catch (_) {
      return utf8.encode(body.toString()).length;
    }
  }
}
