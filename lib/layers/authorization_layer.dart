import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_result.dart';
import '../utils/validators.dart';

/// LAYER 6 — Enforces authorization rules on top of authenticated,
/// validated, and risk-scored requests.
///
/// Rules enforced:
/// - The user must exist (be a known/registered user).
/// - The user must not attempt a restricted action.
/// - The user must not exceed their configured per-user transaction limit.
class AuthorizationLayer implements SecurityLayer {
  @override
  String get name => 'AuthorizationLayer';

  /// The set of user IDs known to the system. In a real deployment this
  /// would be a lookup against a user store; kept in-memory here to stay
  /// dependency-free.
  final Set<String> knownUserIds;

  /// Actions that no user is permitted to perform through this pipeline
  /// (e.g. administrative operations that must go through a separate,
  /// more privileged flow).
  final Set<String> restrictedActions;

  /// Per-user transaction ceilings. Falls back to [defaultUserLimit] when
  /// a user has no specific override.
  final Map<String, double> userLimits;

  /// Transaction ceiling applied when a user has no entry in [userLimits].
  final double defaultUserLimit;

  /// Creates an authorization layer for the given [knownUserIds].
  AuthorizationLayer({
    required this.knownUserIds,
    this.restrictedActions = const {'admin_override', 'delete_ledger'},
    Map<String, double>? userLimits,
    this.defaultUserLimit = 2000,
  }) : userLimits = userLimits ?? {};

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final userId = context.userId;

    if (userId == null || !knownUserIds.contains(userId)) {
      return SecurityResult.block(
        message: 'User does not exist or is not recognized',
        flags: const ['unknown_user'],
        riskScore: 0.9,
      );
    }

    final body = context.getMeta<dynamic>('sanitizedBody') ?? context.body;
    final action = body is Map ? body['action']?.toString() : null;

    if (Validators.isRestrictedAction(action, restrictedActions)) {
      return SecurityResult.block(
        message: 'Action "$action" is restricted for this user',
        flags: const ['restricted_action'],
        riskScore: 0.95,
      );
    }

    final amount = context.getMeta<double>('sandboxAmount') ??
        Validators.extractAmount(body);
    final limit = userLimits[userId] ?? defaultUserLimit;

    if (amount != null && amount > limit) {
      return SecurityResult.block(
        message: 'Transaction exceeds authorized limit for user',
        flags: const ['limit_exceeded'],
        riskScore: 0.85,
      );
    }

    return SecurityResult.allow(message: 'Authorization checks passed');
  }
}
