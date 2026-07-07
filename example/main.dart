// Example usage for SIMOSEC (Simu Security Engine Core).
//
// Run with:
//   dart run example/main.dart
//
// This demonstrates:
//   - Creating the SecurityEngine with real HMAC-SHA256 signing
//   - Registering all 8 layers in order (incl. PayloadSizeLayer)
//   - Sending a few sample requests
//   - Reading the allow/block/flag result

import 'package:simosec/simosec.dart';

/// Signs [body] for [userId] at [timestamp] and returns the headers a real
/// client would send: `X-Signature` and `X-Timestamp`.
Map<String, String> signedHeaders({
  required String secret,
  required Map<String, dynamic> body,
  required String userId,
  required DateTime timestamp,
}) {
  final signature = CryptoUtils.signRequest(secret, {
    'body': body,
    'timestamp': timestamp.toIso8601String(),
    'userId': userId,
  });
  return {
    'X-Signature': signature,
    'X-Timestamp': timestamp.toIso8601String(),
  };
}

Future<void> main() async {
  // 1. Configure shared state used by a couple of the layers.
  const sharedSecret = 'simosec-demo-secret';
  const config = SecurityConfig();

  final knownUsers = {'user_1', 'user_2'};

  // Shared storage backend for rate limiting and device/IP history. Using
  // MemoryStorage here (single-process default); swap for a RedisStorage
  // instance in a real multi-instance deployment.
  final rateLimitStorage = MemoryStorage();
  final quantumStorage = MemoryStorage();

  final sandboxLayer = SandboxLayer(
    mockBalances: {
      'user_1': 500.0, // low balance, easy to trigger a block
      'user_2': 5000.0, // healthy balance
    },
  );

  final rateLimitLayer = RateLimitLayer(
    maxRequests: 5,
    window: const Duration(seconds: 30),
    storage: rateLimitStorage,
  );

  final quantumLayer = QuantumQuarantineLayer(
    storage: quantumStorage,
    config: config,
  );

  final authorizationLayer = AuthorizationLayer(
    knownUserIds: knownUsers,
    userLimits: {'user_2': 10000},
  );

  final loggingLayer = LoggingLayer();

  // 2. Build the engine with all layers, in execution order.
  final engine = SecurityEngine(
    layers: [
      PayloadSizeLayer(config: config),
      SignatureLayer(secret: sharedSecret),
      ValidationLayer(),
      sandboxLayer,
      rateLimitLayer,
      quantumLayer,
      authorizationLayer,
      loggingLayer,
    ],
  );

  // 3. Build a sample request body, signed with a real HMAC-SHA256
  //    signature over {body, timestamp, userId}.
  final body = {'action': 'transfer', 'amount': 250, 'to': 'user_2'};
  final timestamp1 = DateTime.now().toUtc();

  final goodRequest = RequestContext(
    headers: signedHeaders(
      secret: sharedSecret,
      body: body,
      userId: 'user_1',
      timestamp: timestamp1,
    ),
    body: body,
    userId: 'user_1',
    ipAddress: '203.0.113.10',
    deviceId: 'device-abc-123',
    timestamp: timestamp1,
  );

  final result1 = await engine.process(goodRequest);
  print('--- Request 1 (valid, low amount) ---');
  print(result1);

  // 4. A request that should be blocked: amount exceeds the mock balance.
  final bigBody = {'action': 'transfer', 'amount': 4000, 'to': 'user_2'};
  final timestamp2 = DateTime.now().toUtc();

  final bigRequest = RequestContext(
    headers: signedHeaders(
      secret: sharedSecret,
      body: bigBody,
      userId: 'user_1',
      timestamp: timestamp2,
    ),
    body: bigBody,
    userId: 'user_1',
    ipAddress: '203.0.113.10',
    deviceId: 'device-abc-123',
    timestamp: timestamp2,
  );

  final result2 = await engine.process(bigRequest);
  print('\n--- Request 2 (amount exceeds mock balance) ---');
  print(result2);

  // 5. A request with a missing signature — rejected at Layer 2.
  final unsignedRequest = RequestContext(
    headers: const {},
    body: body,
    userId: 'user_1',
    ipAddress: '203.0.113.10',
    deviceId: 'device-abc-123',
  );

  final result3 = await engine.process(unsignedRequest);
  print('\n--- Request 3 (missing signature) ---');
  print(result3);

  // 6. A request from a brand-new device with a high amount — should be
  // flagged or blocked by the QuantumQuarantineLayer.
  final riskyBody = {'action': 'transfer', 'amount': 1500, 'to': 'user_1'};
  final timestamp4 = DateTime.now().toUtc();

  final riskyRequest = RequestContext(
    headers: signedHeaders(
      secret: sharedSecret,
      body: riskyBody,
      userId: 'user_2',
      timestamp: timestamp4,
    ),
    body: riskyBody,
    userId: 'user_2',
    ipAddress: '198.51.100.77', // new/unseen IP for user_2
    deviceId: 'brand-new-device-999',
    timestamp: timestamp4,
  );

  final result4 = await engine.process(riskyRequest);
  print('\n--- Request 4 (high amount + new device/IP) ---');
  print(result4);

  // 7. A payload that exceeds the configured size limit — rejected before
  // any other layer runs, at Layer 1 (PayloadSizeLayer).
  final oversizedBody = {'action': 'transfer', 'note': 'x' * 2000, 'amount': 1};
  final timestamp5 = DateTime.now().toUtc();

  final oversizedRequest = RequestContext(
    headers: signedHeaders(
      secret: sharedSecret,
      body: oversizedBody,
      userId: 'user_1',
      timestamp: timestamp5,
    ),
    body: oversizedBody,
    userId: 'user_1',
    ipAddress: '203.0.113.10',
    deviceId: 'device-abc-123',
    timestamp: timestamp5,
  );

  final oversizedEngine = SecurityEngine(
    layers: [
      PayloadSizeLayer(config: const SecurityConfig(maxPayloadSize: 1024)),
      SignatureLayer(secret: sharedSecret),
      ValidationLayer(),
      sandboxLayer,
      rateLimitLayer,
      quantumLayer,
      authorizationLayer,
      loggingLayer,
    ],
  );
  final result5 = await oversizedEngine.process(oversizedRequest);
  print('\n--- Request 5 (payload exceeds 1KB size limit) ---');
  print(result5);
}
