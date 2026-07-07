import '../models/request_context.dart';
import '../models/security_result.dart';
import 'security_layer.dart';

/// Optional hook invoked by [SecurityEngine] after every layer runs.
/// Useful for wiring up custom logging/metrics without subclassing.
typedef LayerObserver = void Function(
  RequestContext context,
  SecurityResult result,
);

/// The core orchestrator of the SIMOSEC pipeline.
///
/// [SecurityEngine] owns an ordered list of [SecurityLayer]s and pushes a
/// [RequestContext] through them sequentially. Execution stops at the
/// first layer that blocks the request (fail-fast), so expensive layers
/// can be placed after cheap ones for better performance.
///
/// The engine does not know anything about *what* each layer checks —
/// that separation keeps it open for extension (new layers) but closed
/// for modification (the engine itself never needs to change).
class SecurityEngine {
  /// The ordered list of layers this engine runs each request through.
  final List<SecurityLayer> layers;

  /// Optional hook invoked after every layer runs, useful for custom
  /// logging/metrics without subclassing.
  final LayerObserver? onLayerResult;

  /// Creates an engine that runs requests through [layers] in order.
  SecurityEngine({
    required this.layers,
    this.onLayerResult,
  });

  /// Runs [context] through every layer in order.
  ///
  /// Behavior:
  /// - If a layer returns `allowed: false`, the pipeline stops immediately
  ///   and that layer's result (blocked) is returned as the final result.
  /// - If a layer returns `allowed: true` but flags the request
  ///   (verdict == flagged), the pipeline continues, but the highest risk
  ///   score and accumulated flags are carried into the final result.
  /// - If every layer allows the request, an aggregated "allowed" result
  ///   is returned, carrying the maximum risk score seen and all flags
  ///   collected along the way.
  Future<SecurityResult> process(RequestContext context) async {
    final List<String> accumulatedFlags = [];
    double maxRiskScore = 0.0;
    bool sawFlag = false;

    for (final layer in layers) {
      final rawResult = await layer.check(context);
      final result = rawResult.layerName == null
          ? rawResult.withLayerName(layer.name)
          : rawResult;

      onLayerResult?.call(context, result);

      accumulatedFlags.addAll(result.flags);
      if (result.riskScore > maxRiskScore) {
        maxRiskScore = result.riskScore;
      }
      if (result.verdict == SecurityVerdict.flagged) {
        sawFlag = true;
      }

      // Fail-fast: stop the pipeline the instant a layer blocks.
      if (!result.allowed) {
        return SecurityResult(
          allowed: false,
          riskScore: maxRiskScore,
          flags: accumulatedFlags,
          message: 'Blocked at "${layer.name}": ${result.message}',
          verdict: SecurityVerdict.blocked,
          layerName: layer.name,
        );
      }
    }

    // Every layer passed. Decide between "allowed" and "flagged" based on
    // whether any layer raised a flag along the way.
    return SecurityResult(
      allowed: true,
      riskScore: maxRiskScore,
      flags: accumulatedFlags,
      message: sawFlag
          ? 'Request allowed but flagged for review'
          : 'Request allowed',
      verdict: sawFlag ? SecurityVerdict.flagged : SecurityVerdict.allowed,
      layerName: null,
    );
  }
}
