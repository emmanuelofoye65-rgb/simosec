import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_result.dart';
import '../utils/helpers.dart';
import '../utils/validators.dart';

/// LAYER 2 — Validates input structure and sanitizes the payload.
///
/// Rejects malformed or empty payloads before they reach any deeper
/// (and more expensive) layers. On success, the sanitized body is stored
/// back into [RequestContext.metadata] under `sanitizedBody` so
/// downstream layers can use the cleaned-up version instead of the raw
/// input.
class ValidationLayer implements SecurityLayer {
  @override
  String get name => 'ValidationLayer';

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final body = context.body;

    if (Validators.isEmptyPayload(body)) {
      return SecurityResult.block(
        message: 'Request payload is empty',
        flags: const ['empty_payload'],
        riskScore: 0.9,
      );
    }

    if (!Validators.isStructurallyValidMap(body)) {
      return SecurityResult.block(
        message: 'Request payload is malformed (expected a JSON object)',
        flags: const ['malformed_payload'],
        riskScore: 0.9,
      );
    }

    final sanitized = Helpers.sanitize(body);
    context.setMeta('sanitizedBody', sanitized);

    return SecurityResult.allow(message: 'Payload structurally valid');
  }
}
