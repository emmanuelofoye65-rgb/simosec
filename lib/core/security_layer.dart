import '../models/request_context.dart';
import '../models/security_result.dart';

/// The contract every security layer in the SIMOSEC pipeline must
/// implement.
///
/// Layers are intentionally simple and single-responsibility (SRP): each
/// layer inspects a [RequestContext] and returns a [SecurityResult]
/// describing whether the request should continue. The [SecurityEngine]
/// is responsible for sequencing, short-circuiting, and aggregation —
/// layers should never know about each other directly.
///
/// To add a new layer: implement this interface and register an instance
/// with [SecurityEngine]. No changes to the engine or other layers are
/// required (Open/Closed Principle).
abstract class SecurityLayer {
  /// A short, stable, human-readable name used in logs and results.
  String get name;

  /// Inspects [context] and returns a [SecurityResult].
  ///
  /// Implementations should be side-effect-light with respect to
  /// [context.body] (avoid destructive mutation) but may freely read/write
  /// [context.metadata] to communicate with later layers.
  Future<SecurityResult> check(RequestContext context);
}
