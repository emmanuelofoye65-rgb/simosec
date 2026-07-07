/// Small, dependency-free validation helpers shared across layers.
///
/// Kept intentionally simple: SIMOSEC avoids pulling in external
/// validation/JSON packages so the engine stays lightweight and easy to
/// embed anywhere.
class Validators {
  Validators._();

  /// Returns true if [value] is null, an empty string, an empty map, or
  /// an empty list/iterable.
  static bool isEmptyPayload(dynamic value) {
    if (value == null) return true;
    if (value is String) return value.trim().isEmpty;
    if (value is Map) return value.isEmpty;
    if (value is Iterable) return value.isEmpty;
    return false;
  }

  /// Returns true if [body] looks like a well-formed map payload, i.e. it
  /// is a `Map` and every key is a non-empty `String`.
  static bool isStructurallyValidMap(dynamic body) {
    if (body is! Map) return false;
    for (final key in body.keys) {
      if (key is! String || key.trim().isEmpty) return false;
    }
    return true;
  }

  /// Extracts a numeric amount from a request body map, checking a few
  /// common field names. Returns null if no numeric amount is found.
  static double? extractAmount(dynamic body) {
    if (body is! Map) return null;
    for (final key in const ['amount', 'value', 'total']) {
      final raw = body[key];
      if (raw is num) return raw.toDouble();
      if (raw is String) {
        final parsed = double.tryParse(raw);
        if (parsed != null) return parsed;
      }
    }
    return null;
  }

  /// Returns true if [action] is present in [restrictedActions]
  /// (case-insensitive).
  static bool isRestrictedAction(
    String? action,
    Set<String> restrictedActions,
  ) {
    if (action == null) return false;
    final normalized = action.toLowerCase();
    return restrictedActions.any((a) => a.toLowerCase() == normalized);
  }

  /// A minimal signature format sanity check. This does NOT perform real
  /// cryptographic verification — see `CryptoUtils.verifySignature` for
  /// that. This just guards against obviously malformed values (empty,
  /// too short, whitespace-only).
  static bool looksLikeSignature(String? signature) {
    if (signature == null) return false;
    final trimmed = signature.trim();
    if (trimmed.isEmpty) return false;
    if (trimmed.length < 8) return false;
    return true;
  }
}
