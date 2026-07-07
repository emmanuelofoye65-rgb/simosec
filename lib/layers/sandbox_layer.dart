import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_result.dart';
import '../utils/validators.dart';

/// LAYER 3 — Simulates execution against mock state, without ever
/// touching a real database.
///
/// Acts as a "dry-run validator": it checks whether the requested
/// transaction *would* succeed against a mock balance/rule set, and
/// rejects it early if it obviously couldn't (e.g. insufficient funds).
/// This lets the pipeline catch invalid transactions cheaply, before any
/// real backend call is ever made.
class SandboxLayer implements SecurityLayer {
  @override
  String get name => 'SandboxLayer';

  /// Mock balances keyed by userId, simulating account state.
  final Map<String, double> mockBalances;

  /// Mock per-user transaction ceiling, simulating a business rule.
  final double maxTransactionAmount;

  /// Creates a sandbox layer, seeding demo balances when [mockBalances]
  /// is not provided.
  SandboxLayer({
    Map<String, double>? mockBalances,
    this.maxTransactionAmount = 10000,
  }) : mockBalances = mockBalances ??
            {
              // Seed data for demo/testing purposes only.
              'user_1': 500.0,
              'user_2': 5000.0,
            };

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final body = context.getMeta<dynamic>('sanitizedBody') ?? context.body;
    final amount = Validators.extractAmount(body);

    // Non-transactional requests (no amount field) simply pass through
    // the sandbox untouched.
    if (amount == null) {
      return SecurityResult.allow(message: 'No transaction to simulate');
    }

    if (amount <= 0) {
      return SecurityResult.block(
        message: 'Transaction amount must be positive',
        flags: const ['invalid_amount'],
        riskScore: 0.7,
      );
    }

    if (amount > maxTransactionAmount) {
      return SecurityResult.block(
        message: 'Transaction exceeds maximum allowed amount',
        flags: const ['amount_over_limit'],
        riskScore: 0.9,
      );
    }

    final userId = context.userId;
    final balance = userId != null ? mockBalances[userId] : null;

    if (balance != null && amount > balance) {
      return SecurityResult.block(
        message: 'Simulated dry-run failed: amount exceeds mock balance',
        flags: const ['insufficient_mock_balance'],
        riskScore: 0.8,
      );
    }

    context.setMeta('sandboxAmount', amount);
    return SecurityResult.allow(message: 'Dry-run simulation passed');
  }
}
