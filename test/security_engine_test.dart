import 'package:simosec/simosec.dart';
import 'package:test/test.dart';

void main() {
  const secret = 'test-secret';
  final knownUsers = {'user_1'};

  SecurityEngine buildEngine({
    Map<String, double>? balances,
    int rateLimit = 5,
    StorageAdapter? rateLimitStorage,
    StorageAdapter? quantumStorage,
    SecurityConfig config = const SecurityConfig(),
  }) {
    return SecurityEngine(
      layers: [
        PayloadSizeLayer(config: config),
        SignatureLayer(secret: secret),
        ValidationLayer(),
        SandboxLayer(mockBalances: balances ?? {'user_1': 500.0}),
        RateLimitLayer(maxRequests: rateLimit, storage: rateLimitStorage),
        QuantumQuarantineLayer(storage: quantumStorage, config: config),
        AuthorizationLayer(knownUserIds: knownUsers),
        LoggingLayer(sink: (_) {}),
      ],
    );
  }

  /// Builds a fully signed [RequestContext] the way a real client would:
  /// pick a timestamp, sign {body, timestamp, userId} with it, then send
  /// that same timestamp along as a header so the server can verify
  /// against it.
  RequestContext buildRequest(
    Map<String, dynamic> body, {
    String? userId,
    String? deviceId,
    String? ipAddress,
    DateTime? timestamp,
    String? signatureOverride,
  }) {
    final uid = userId ?? 'user_1';
    final at = (timestamp ?? DateTime.now().toUtc());
    final signature = signatureOverride ??
        CryptoUtils.signRequest(secret, {
          'body': body,
          'timestamp': at.toIso8601String(),
          'userId': uid,
        });

    return RequestContext(
      headers: {
        'X-Signature': signature,
        'X-Timestamp': at.toIso8601String(),
      },
      body: body,
      userId: uid,
      ipAddress: ipAddress ?? '127.0.0.1',
      deviceId: deviceId ?? 'device-1',
    );
  }

  group('core pipeline behavior', () {
    test('allows a well-formed, low-risk request', () async {
      final engine = buildEngine();
      final request = buildRequest({'action': 'transfer', 'amount': 50});
      final result = await engine.process(request);
      expect(result.allowed, isTrue);
    });

    test('blocks an empty payload', () async {
      final engine = buildEngine();
      final request = buildRequest({});
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
    });

    test('blocks a transaction exceeding the mock balance', () async {
      final engine = buildEngine(balances: {'user_1': 100.0});
      final request = buildRequest({'action': 'transfer', 'amount': 200});
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('insufficient_mock_balance'));
    });

    test('blocks after exceeding the rate limit', () async {
      final engine = buildEngine(rateLimit: 2);
      SecurityResult? last;
      for (var i = 0; i < 4; i++) {
        final request = buildRequest({'action': 'ping', 'amount': 1});
        last = await engine.process(request);
      }
      expect(last!.allowed, isFalse);
      expect(last.flags, contains('rate_limit_exceeded'));
    });

    test('blocks an unknown user at the authorization layer', () async {
      final engine = buildEngine();
      final request = buildRequest(
        {'action': 'transfer', 'amount': 10},
        userId: 'ghost_user',
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('unknown_user'));
    });

    test('flags a high amount from a new device without blocking', () async {
      final engine = SecurityEngine(
        layers: [
          PayloadSizeLayer(),
          SignatureLayer(secret: secret),
          ValidationLayer(),
          SandboxLayer(mockBalances: {'user_1': 5000.0}),
          RateLimitLayer(),
          QuantumQuarantineLayer(highAmountThreshold: 100),
          AuthorizationLayer(knownUserIds: knownUsers, defaultUserLimit: 5000),
          LoggingLayer(sink: (_) {}),
        ],
      );

      final request = buildRequest({'action': 'transfer', 'amount': 1200});
      final result = await engine.process(request);

      expect(result.allowed, isTrue);
      expect(result.verdict, SecurityVerdict.flagged);
    });
  });

  group('HMAC-SHA256 signature verification', () {
    test('accepts a request with a correctly computed signature', () async {
      final engine = buildEngine();
      final request = buildRequest({'action': 'transfer', 'amount': 50});
      final result = await engine.process(request);
      expect(result.allowed, isTrue);
    });

    test('blocks a request with a missing signature', () async {
      final engine = buildEngine();
      final request = RequestContext(
        headers: {'X-Timestamp': DateTime.now().toUtc().toIso8601String()},
        body: {'action': 'transfer', 'amount': 50},
        userId: 'user_1',
        ipAddress: '127.0.0.1',
        deviceId: 'device-1',
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('missing_signature'));
    });

    test('blocks a request with a missing timestamp header', () async {
      final engine = buildEngine();
      final signature = CryptoUtils.signRequest(secret, {
        'body': {'action': 'transfer', 'amount': 50},
        'timestamp': DateTime.now().toUtc().toIso8601String(),
        'userId': 'user_1',
      });
      final request = RequestContext(
        headers: {'X-Signature': signature},
        body: {'action': 'transfer', 'amount': 50},
        userId: 'user_1',
        ipAddress: '127.0.0.1',
        deviceId: 'device-1',
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('missing_timestamp'));
    });

    test('blocks a tampered body even if the signature "looks" valid',
        () async {
      final engine = buildEngine();
      final at = DateTime.now().toUtc();
      final originalBody = {'action': 'transfer', 'amount': 50};
      final signature = CryptoUtils.signRequest(secret, {
        'body': originalBody,
        'timestamp': at.toIso8601String(),
        'userId': 'user_1',
      });

      // Attacker tampers with the amount after the signature was computed.
      final tamperedRequest = RequestContext(
        headers: {
          'X-Signature': signature,
          'X-Timestamp': at.toIso8601String(),
        },
        body: {'action': 'transfer', 'amount': 999999},
        userId: 'user_1',
        ipAddress: '127.0.0.1',
        deviceId: 'device-1',
      );

      final result = await engine.process(tamperedRequest);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('invalid_signature'));
    });

    test('blocks a signature computed with the wrong secret', () async {
      final engine = buildEngine();
      final at = DateTime.now().toUtc();
      final body = {'action': 'transfer', 'amount': 50};
      final wrongSignature = CryptoUtils.signRequest('wrong-secret', {
        'body': body,
        'timestamp': at.toIso8601String(),
        'userId': 'user_1',
      });

      final request = buildRequest(
        body,
        timestamp: at,
        signatureOverride: wrongSignature,
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('invalid_signature'));
    });

    test('blocks a signature bound to a different userId', () async {
      final engine = buildEngine();
      final at = DateTime.now().toUtc();
      final body = {'action': 'transfer', 'amount': 50};
      // Signed for user_2, but the request claims to be from user_1.
      final signatureForOtherUser = CryptoUtils.signRequest(secret, {
        'body': body,
        'timestamp': at.toIso8601String(),
        'userId': 'user_2',
      });

      final request = buildRequest(
        body,
        userId: 'user_1',
        timestamp: at,
        signatureOverride: signatureForOtherUser,
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('invalid_signature'));
    });

    test('blocks a signature with a stale timestamp (replay protection)',
        () async {
      final engine = buildEngine();
      final staleTime = DateTime.now().toUtc().subtract(
            const Duration(minutes: 30),
          );
      final request = buildRequest(
        {'action': 'transfer', 'amount': 50},
        timestamp: staleTime,
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('stale_timestamp'));
    });

    test('CryptoUtils.signRequest/verifySignature round-trip correctly', () {
      final payload = {
        'body': {'action': 'transfer', 'amount': 50},
        'timestamp': '2026-01-01T00:00:00.000Z',
        'userId': 'user_1',
      };
      final signature = CryptoUtils.signRequest(secret, payload);
      expect(CryptoUtils.verifySignature(secret, payload, signature), isTrue);
      expect(
        CryptoUtils.verifySignature(secret, payload, 'not-the-signature'),
        isFalse,
      );
      expect(CryptoUtils.verifySignature(secret, payload, null), isFalse);
    });
  });

  group('persistent storage behavior', () {
    test('MemoryStorage set/get/delete round-trips values', () async {
      final storage = MemoryStorage();
      await storage.set('key', [1, 2, 3]);
      expect(await storage.get('key'), [1, 2, 3]);
      await storage.delete('key');
      expect(await storage.get('key'), isNull);
    });

    test('RedisStorage implements the same StorageAdapter contract', () async {
      final StorageAdapter storage = RedisStorage();
      await storage.set('key', 'value');
      expect(await storage.get('key'), 'value');
      await storage.delete('key');
      expect(await storage.get('key'), isNull);
    });

    test('rate limit state persists across engine instances sharing storage',
        () async {
      final sharedStorage = MemoryStorage();
      final engineA =
          buildEngine(rateLimit: 2, rateLimitStorage: sharedStorage);
      final engineB =
          buildEngine(rateLimit: 2, rateLimitStorage: sharedStorage);

      await engineA.process(buildRequest({'action': 'ping', 'amount': 1}));
      await engineA.process(buildRequest({'action': 'ping', 'amount': 1}));
      // Third request, routed through a *different* engine instance that
      // shares the same storage backend, should still be rate-limited.
      final result = await engineB.process(
        buildRequest({'action': 'ping', 'amount': 1}),
      );

      expect(result.allowed, isFalse);
      expect(result.flags, contains('rate_limit_exceeded'));
    });

    test('quantum layer remembers a known device across engine instances',
        () async {
      final sharedStorage = MemoryStorage();
      final engineA = buildEngine(quantumStorage: sharedStorage);
      final engineB = buildEngine(quantumStorage: sharedStorage);

      final first = await engineA.process(
        buildRequest(
          {'action': 'transfer', 'amount': 10},
          deviceId: 'device-known',
          ipAddress: '203.0.113.10',
        ),
      );
      expect(first.flags, contains('new_device'));

      // Same device/IP, different engine instance, shared storage: should
      // no longer be flagged as a new device.
      final second = await engineB.process(
        buildRequest(
          {'action': 'transfer', 'amount': 10},
          deviceId: 'device-known',
          ipAddress: '203.0.113.10',
        ),
      );
      expect(second.flags, isNot(contains('new_device')));
      expect(second.flags, isNot(contains('ip_anomaly')));
    });
  });

  group('payload size limit', () {
    test('allows a payload within the configured limit', () async {
      final engine = buildEngine(
        config: const SecurityConfig(maxPayloadSize: 1024 * 1024),
      );
      final request = buildRequest({'action': 'transfer', 'amount': 50});
      final result = await engine.process(request);
      expect(result.allowed, isTrue);
    });

    test('rejects a payload larger than the configured limit', () async {
      final engine =
          buildEngine(config: const SecurityConfig(maxPayloadSize: 100));
      final body = {
        'action': 'transfer',
        'amount': 50,
        'note': 'x' * 500,
      };
      final request = buildRequest(body);
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('payload_too_large'));
      expect(result.layerName, 'PayloadSizeLayer');
    });

    test('rejects an oversized payload before signature verification runs',
        () async {
      // Even with no signature at all, the payload-size rejection should
      // fire first since PayloadSizeLayer runs before SignatureLayer.
      final engine =
          buildEngine(config: const SecurityConfig(maxPayloadSize: 50));
      final request = RequestContext(
        headers: const {},
        body: {'note': 'y' * 1000},
        userId: 'user_1',
        ipAddress: '127.0.0.1',
        deviceId: 'device-1',
      );
      final result = await engine.process(request);
      expect(result.allowed, isFalse);
      expect(result.flags, contains('payload_too_large'));
    });
  });
}
