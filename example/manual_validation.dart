// Manual validation script for SIMOSEC.
//
// Exercises the full pipeline against the scenarios required for
// production validation:
//   A. Valid request                       -> ALLOW
//   B. Invalid signature                   -> BLOCK
//   C. High frequency requests              -> BLOCK (RateLimitLayer)
//   D. Large transaction + new device       -> FLAG or BLOCK (QuantumQuarantineLayer)
//   E. Sandbox failure (insufficient funds) -> BLOCK
//   Plus edge cases: empty request, missing fields, null values,
//   oversized payload, persistent storage across engine instances.
//
// Run with:
//   dart run example/manual_validation.dart

import 'package:simosec/simosec.dart';

const secret = 'validation-secret';

SecurityEngine buildEngine({
  int rateLimitMax = 5,
  Map<String, double>? balances,
  StorageAdapter? rateLimitStorage,
  StorageAdapter? quantumStorage,
  SecurityConfig config = const SecurityConfig(),
}) {
  return SecurityEngine(
    layers: [
      PayloadSizeLayer(config: config),
      SignatureLayer(secret: secret),
      ValidationLayer(),
      SandboxLayer(
          mockBalances: balances ?? {'user_1': 500.0, 'user_2': 5000.0}),
      RateLimitLayer(
        maxRequests: rateLimitMax,
        window: const Duration(seconds: 30),
        storage: rateLimitStorage,
      ),
      QuantumQuarantineLayer(storage: quantumStorage, config: config),
      AuthorizationLayer(
          knownUserIds: {'user_1', 'user_2'}, userLimits: {'user_2': 10000}),
      LoggingLayer(),
    ],
  );
}

RequestContext signedRequest({
  required Map<String, dynamic>? body,
  String? userId,
  String ip = '203.0.113.10',
  String deviceId = 'device-known-1',
  bool badSignature = false,
  bool omitTimestamp = false,
  DateTime? timestamp,
}) {
  final uid = userId ?? 'user_1';
  final at = timestamp ?? DateTime.now().toUtc();
  final signature = badSignature
      ? 'deadbeefdeadbeefdeadbeefdeadbeef'
      : CryptoUtils.signRequest(secret, {
          'body': body,
          'timestamp': at.toIso8601String(),
          'userId': uid,
        });
  return RequestContext(
    headers: {
      'X-Signature': signature,
      if (!omitTimestamp) 'X-Timestamp': at.toIso8601String(),
    },
    body: body,
    userId: uid,
    ipAddress: ip,
    deviceId: deviceId,
  );
}

int _pass = 0;
int _fail = 0;

void expectVerdict(
  String label,
  SecurityResult result,
  Set<SecurityVerdict> acceptable,
) {
  final ok = acceptable.contains(result.verdict);
  final status = ok ? 'PASS' : 'FAIL';
  if (ok) {
    _pass++;
  } else {
    _fail++;
  }
  print('[$status] $label -> ${result.verdict.name} '
      '(allowed=${result.allowed}, risk=${result.riskScore.toStringAsFixed(2)}, '
      'flags=${result.flags}, msg="${result.message}")');
}

void expectTrue(String label, bool condition, {String? detail}) {
  final status = condition ? 'PASS' : 'FAIL';
  if (condition) {
    _pass++;
  } else {
    _fail++;
  }
  print('[$status] $label${detail != null ? ' ($detail)' : ''}');
}

Future<void> main() async {
  print('=== SIMOSEC Manual Validation ===\n');

  // ---------------------------------------------------------------------
  // A. VALID REQUEST -> ALLOW
  // ---------------------------------------------------------------------
  print('--- A. Valid request ---');
  {
    final engine = buildEngine();
    final req = signedRequest(
        body: {'action': 'transfer', 'amount': 50, 'to': 'user_2'});
    final result = await engine.process(req);
    expectVerdict('Valid request with proper HMAC-SHA256 signature', result,
        {SecurityVerdict.allowed});
  }

  // ---------------------------------------------------------------------
  // B. INVALID SIGNATURE -> BLOCK
  // ---------------------------------------------------------------------
  print('\n--- B. Invalid signature ---');
  {
    final engine = buildEngine();
    final req = signedRequest(
      body: {'action': 'transfer', 'amount': 50, 'to': 'user_2'},
      badSignature: true,
    );
    final result = await engine.process(req);
    expectVerdict(
        'Tampered/invalid signature', result, {SecurityVerdict.blocked});
    expectTrue(
      'Blocked with flag "invalid_signature"',
      result.flags.contains('invalid_signature'),
      detail: 'flags=${result.flags}',
    );
  }

  // ---------------------------------------------------------------------
  // B2. TAMPERED BODY AFTER SIGNING -> BLOCK (proves real HMAC coverage)
  // ---------------------------------------------------------------------
  print('\n--- B2. Body tampered after signing ---');
  {
    final engine = buildEngine();
    final at = DateTime.now().toUtc();
    final originalBody = {'action': 'transfer', 'amount': 50, 'to': 'user_2'};
    final signature = CryptoUtils.signRequest(secret, {
      'body': originalBody,
      'timestamp': at.toIso8601String(),
      'userId': 'user_1',
    });
    final tampered = RequestContext(
      headers: {'X-Signature': signature, 'X-Timestamp': at.toIso8601String()},
      body: {'action': 'transfer', 'amount': 999999, 'to': 'user_2'},
      userId: 'user_1',
      ipAddress: '203.0.113.10',
      deviceId: 'device-known-1',
      timestamp: at,
    );
    final result = await engine.process(tampered);
    expectVerdict('Amount tampered after signature computed', result,
        {SecurityVerdict.blocked});
  }

  // ---------------------------------------------------------------------
  // B3. STALE TIMESTAMP -> BLOCK (replay protection)
  // ---------------------------------------------------------------------
  print('\n--- B3. Stale timestamp (replay attack simulation) ---');
  {
    final engine = buildEngine();
    final staleTime =
        DateTime.now().toUtc().subtract(const Duration(minutes: 30));
    final req = signedRequest(
      body: {'action': 'transfer', 'amount': 50, 'to': 'user_2'},
      timestamp: staleTime,
    );
    final result = await engine.process(req);
    expectVerdict('30-minute-old signature rejected as stale', result,
        {SecurityVerdict.blocked});
    expectTrue(
      'Blocked with flag "stale_timestamp"',
      result.flags.contains('stale_timestamp'),
      detail: 'flags=${result.flags}',
    );
  }

  // ---------------------------------------------------------------------
  // C. HIGH FREQUENCY REQUEST -> BLOCK (RateLimitLayer)
  // ---------------------------------------------------------------------
  print('\n--- C. High frequency requests ---');
  {
    final engine = buildEngine(rateLimitMax: 3);
    SecurityResult? last;
    for (var i = 0; i < 6; i++) {
      final req = signedRequest(body: {'action': 'ping', 'amount': 1});
      last = await engine.process(req);
    }
    expectVerdict('6th request after exceeding rate limit of 3', last!,
        {SecurityVerdict.blocked});
    if (!last.flags.contains('rate_limit_exceeded')) {
      print('  [WARN] expected flag "rate_limit_exceeded", got ${last.flags}');
    }
  }

  // ---------------------------------------------------------------------
  // C2. RATE LIMIT STATE PERSISTS ACROSS ENGINE INSTANCES (shared storage)
  // ---------------------------------------------------------------------
  print('\n--- C2. Rate limit state persists across engine instances ---');
  {
    final sharedStorage = MemoryStorage();
    final engineA =
        buildEngine(rateLimitMax: 2, rateLimitStorage: sharedStorage);
    final engineB =
        buildEngine(rateLimitMax: 2, rateLimitStorage: sharedStorage);

    await engineA.process(signedRequest(
        body: {'action': 'ping', 'amount': 1}, deviceId: 'device-shared'));
    await engineA.process(signedRequest(
        body: {'action': 'ping', 'amount': 1}, deviceId: 'device-shared'));
    final result = await engineB.process(
      signedRequest(
          body: {'action': 'ping', 'amount': 1}, deviceId: 'device-shared'),
    );
    expectVerdict(
      '3rd request via a different engine instance sharing storage',
      result,
      {SecurityVerdict.blocked},
    );
  }

  // ---------------------------------------------------------------------
  // D. LARGE TRANSACTION + NEW DEVICE -> FLAG or BLOCK
  // ---------------------------------------------------------------------
  print('\n--- D. Large transaction + new device ---');
  {
    final engine = buildEngine(balances: {'user_2': 50000.0});
    final req = signedRequest(
      body: {'action': 'transfer', 'amount': 8000, 'to': 'user_1'},
      userId: 'user_2',
      ip: '198.51.100.200', // never seen before for user_2
      deviceId: 'brand-new-device-xyz',
    );
    final result = await engine.process(req);
    expectVerdict(
      'High amount from unrecognized device/IP',
      result,
      {SecurityVerdict.flagged, SecurityVerdict.blocked},
    );
  }

  // ---------------------------------------------------------------------
  // D2. RETURNING USER'S KNOWN DEVICE IS NOT FLAGGED (persistent history)
  // ---------------------------------------------------------------------
  print('\n--- D2. Returning user on a previously-seen device/IP ---');
  {
    final sharedQuantumStorage = MemoryStorage();
    final engineA = buildEngine(
        balances: {'user_2': 50000.0}, quantumStorage: sharedQuantumStorage);
    final engineB = buildEngine(
        balances: {'user_2': 50000.0}, quantumStorage: sharedQuantumStorage);

    final first = await engineA.process(signedRequest(
      body: {'action': 'transfer', 'amount': 20, 'to': 'user_1'},
      userId: 'user_2',
      ip: '198.51.100.55',
      deviceId: 'user2-regular-device',
    ));
    expectTrue('First-ever request from this device is flagged new_device',
        first.flags.contains('new_device'));

    final second = await engineB.process(signedRequest(
      body: {'action': 'transfer', 'amount': 20, 'to': 'user_1'},
      userId: 'user_2',
      ip: '198.51.100.55',
      deviceId: 'user2-regular-device',
    ));
    expectTrue(
      'Second request from the same device (different engine instance) is NOT flagged new_device',
      !second.flags.contains('new_device') &&
          !second.flags.contains('ip_anomaly'),
      detail: 'flags=${second.flags}',
    );
  }

  // ---------------------------------------------------------------------
  // E. SANDBOX FAILURE (insufficient balance) -> BLOCK
  // ---------------------------------------------------------------------
  print('\n--- E. Sandbox failure (insufficient balance) ---');
  {
    final engine = buildEngine(balances: {'user_1': 100.0});
    final req = signedRequest(
        body: {'action': 'transfer', 'amount': 300, 'to': 'user_2'});
    final result = await engine.process(req);
    expectVerdict(
        'Amount exceeds mock balance', result, {SecurityVerdict.blocked});
    if (!result.flags.contains('insufficient_mock_balance')) {
      print(
          '  [WARN] expected flag "insufficient_mock_balance", got ${result.flags}');
    }
  }

  // ---------------------------------------------------------------------
  // F. PAYLOAD SIZE LIMIT -> BLOCK (PayloadSizeLayer, runs first)
  // ---------------------------------------------------------------------
  print('\n--- F. Payload exceeds configured size limit ---');
  {
    final engine =
        buildEngine(config: const SecurityConfig(maxPayloadSize: 1024));
    final body = {'action': 'transfer', 'amount': 10, 'note': 'x' * 5000};
    final req = signedRequest(body: body);
    final result = await engine.process(req);
    expectVerdict('5KB payload rejected by a 1KB limit', result,
        {SecurityVerdict.blocked});
    expectTrue(
      'Rejected at PayloadSizeLayer (before signature verification)',
      result.layerName == 'PayloadSizeLayer' &&
          result.flags.contains('payload_too_large'),
      detail: 'layer=${result.layerName}, flags=${result.flags}',
    );
  }
  {
    final engine =
        buildEngine(config: const SecurityConfig(maxPayloadSize: 1024 * 1024));
    final req = signedRequest(body: {'action': 'transfer', 'amount': 10});
    final result = await engine.process(req);
    expectVerdict('Small payload allowed under the default 1MB limit', result,
        {SecurityVerdict.allowed});
  }

  // ---------------------------------------------------------------------
  // EDGE CASES
  // ---------------------------------------------------------------------
  print('\n--- Edge case: empty request body ---');
  {
    final engine = buildEngine();
    final req = signedRequest(body: const {});
    final result = await engine.process(req);
    expectVerdict('Empty payload', result, {SecurityVerdict.blocked});
  }

  print('\n--- Edge case: missing fields (no amount/action) ---');
  {
    final engine = buildEngine();
    final req = signedRequest(body: {'note': 'hello'});
    final result = await engine.process(req);
    expectVerdict('Missing amount/action fields (non-transactional)', result,
        {SecurityVerdict.allowed, SecurityVerdict.flagged});
  }

  print('\n--- Edge case: null values in payload ---');
  {
    final engine = buildEngine();
    final body = {'action': null, 'amount': null, 'to': null};
    final req = signedRequest(body: body);
    final result = await engine.process(req);
    // Should not throw; null amount means "no transaction to simulate".
    expectVerdict('Null-valued fields', result,
        {SecurityVerdict.allowed, SecurityVerdict.flagged});
  }

  print('\n--- Edge case: body is not a map at all (null body) ---');
  {
    final engine = buildEngine();
    final req = signedRequest(body: null);
    final result = await engine.process(req);
    expectVerdict('Null body', result, {SecurityVerdict.blocked});
  }

  print('\n--- Edge case: missing X-Timestamp header ---');
  {
    final engine = buildEngine();
    final req = signedRequest(
      body: {'action': 'transfer', 'amount': 10},
      omitTimestamp: true,
    );
    final result = await engine.process(req);
    expectVerdict('Missing timestamp header is rejected', result,
        {SecurityVerdict.blocked});
    expectTrue(
      'Blocked with flag "missing_timestamp"',
      result.flags.contains('missing_timestamp'),
      detail: 'flags=${result.flags}',
    );
  }

  print(
      '\n--- Edge case: moderately large payload (49,000 bytes, under 1MB) ---');
  {
    final engine = buildEngine();
    final bigBody = <String, dynamic>{
      'action': 'transfer',
      'amount': 25,
      'to': 'user_2',
    };
    for (var i = 0; i < 500; i++) {
      bigBody['field_$i'] = 'x' * 90;
    }
    final req = signedRequest(body: bigBody);
    final sw = Stopwatch()..start();
    final result = await engine.process(req);
    sw.stop();
    expectVerdict(
        'Payload well under the 1MB limit (${sw.elapsedMilliseconds}ms)',
        result,
        {SecurityVerdict.allowed, SecurityVerdict.flagged});
    print('  Payload processed in ${sw.elapsedMilliseconds}ms');
  }

  // ---------------------------------------------------------------------
  // STORAGE ADAPTER CONTRACT CHECK
  // ---------------------------------------------------------------------
  print('\n--- Storage adapter contract (Memory + Redis) ---');
  {
    for (final StorageAdapter storage in [MemoryStorage(), RedisStorage()]) {
      await storage.set('k', 'v');
      final readBack = await storage.get('k');
      await storage.delete('k');
      final afterDelete = await storage.get('k');
      expectTrue(
        '${storage.runtimeType} set/get/delete round-trip',
        readBack == 'v' && afterDelete == null,
      );
    }
  }

  // ---------------------------------------------------------------------
  // LOG VERIFICATION
  // ---------------------------------------------------------------------
  print('\n--- Log verification ---');
  {
    final logs = <String>[];
    final logging = LoggingLayer(sink: logs.add);
    final engine = SecurityEngine(
      layers: [
        PayloadSizeLayer(),
        SignatureLayer(secret: secret),
        ValidationLayer(),
        SandboxLayer(),
        RateLimitLayer(),
        QuantumQuarantineLayer(),
        AuthorizationLayer(knownUserIds: {'user_1'}),
        logging,
      ],
      onLayerResult: (ctx, result) {
        print('  [engine-observer] layer=${result.layerName} '
            'verdict=${result.verdict.name} risk=${result.riskScore.toStringAsFixed(2)}');
      },
    );
    final req = signedRequest(
        body: {'action': 'transfer', 'amount': 20, 'to': 'user_2'});
    await engine.process(req);
    final logLineOk = logs.isNotEmpty && logs.first.contains('LoggingLayer');
    print('  LoggingLayer produced ${logs.length} log line(s).');
    if (logLineOk) {
      _pass++;
      print('  [PASS] Log line is structured: ${logs.first}');
    } else {
      _fail++;
      print(
          '  [FAIL] LoggingLayer did not produce expected structured output.');
    }
  }

  // ---------------------------------------------------------------------
  // PERFORMANCE CHECK
  // ---------------------------------------------------------------------
  print('\n--- Performance check (1000 sequential requests) ---');
  {
    final engine = SecurityEngine(
      layers: [
        PayloadSizeLayer(),
        SignatureLayer(secret: secret),
        ValidationLayer(),
        SandboxLayer(),
        RateLimitLayer(
            maxRequests: 100000, window: const Duration(seconds: 30)),
        QuantumQuarantineLayer(),
        AuthorizationLayer(
            knownUserIds: {'user_1', 'user_2'}, userLimits: {'user_2': 10000}),
        LoggingLayer(sink: (_) {}),
      ],
    );
    final durations = <int>[];
    for (var i = 0; i < 1000; i++) {
      final req = signedRequest(
        body: {'action': 'transfer', 'amount': 10 + i % 50, 'to': 'user_2'},
        deviceId: 'device-known-1',
      );
      final sw = Stopwatch()..start();
      await engine.process(req);
      sw.stop();
      durations.add(sw.elapsedMicroseconds);
    }
    durations.sort();
    final totalMicros = durations.fold<int>(0, (a, b) => a + b);
    final avgMicros = totalMicros / durations.length;
    final p50 = durations[(durations.length * 0.50).floor()];
    final p95 = durations[(durations.length * 0.95).floor()];
    final maxMicros = durations.last;

    print('  requests: ${durations.length}');
    print('  avg: ${(avgMicros / 1000).toStringAsFixed(3)} ms');
    print('  p50: ${(p50 / 1000).toStringAsFixed(3)} ms');
    print('  p95: ${(p95 / 1000).toStringAsFixed(3)} ms');
    print('  max: ${(maxMicros / 1000).toStringAsFixed(3)} ms');

    final avgMs = avgMicros / 1000;
    if (avgMs < 1) {
      _pass++;
      print(
          '  [PASS] average latency ${avgMs.toStringAsFixed(3)}ms < 1ms target');
    } else if (avgMs < 50) {
      _pass++;
      print(
          '  [PASS] average latency ${avgMs.toStringAsFixed(3)}ms < 50ms target (above 1ms stretch goal)');
    } else {
      _fail++;
      print(
          '  [FAIL] average latency ${avgMs.toStringAsFixed(3)}ms exceeds 50ms target');
    }
  }

  print('\n=== SUMMARY: $_pass passed, $_fail failed ===');
}
