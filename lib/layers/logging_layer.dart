import '../core/security_layer.dart';
import '../models/request_context.dart';
import '../models/security_result.dart';

/// A single structured log entry produced by [LoggingLayer].
class SecurityLogEntry {
  /// When this log entry was recorded.
  final DateTime timestamp;

  /// The name of the layer that produced this entry (always
  /// `LoggingLayer`, since only it creates entries).
  final String layerName;

  /// The user associated with the logged request, or `'anonymous'`.
  final String userId;

  /// The originating IP address of the logged request.
  final String ipAddress;

  /// A short human-readable description of what happened.
  final String message;

  /// Creates a structured log entry.
  const SecurityLogEntry({
    required this.timestamp,
    required this.layerName,
    required this.userId,
    required this.ipAddress,
    required this.message,
  });

  @override
  String toString() {
    return '[${timestamp.toIso8601String()}] '
        '[$layerName] '
        'user=$userId ip=$ipAddress :: $message';
  }
}

/// LAYER 7 — Logs every request and the decision reached by the pipeline
/// up to this point.
///
/// This layer is designed to run LAST in the pipeline, so it can record
/// the final outcome (allowed/flagged) for requests that made it all the
/// way through. It always allows the request — logging never blocks
/// traffic. For simplicity this uses `print`; swap [sink] for a real
/// logging backend (file, remote log service) in production.
class LoggingLayer implements SecurityLayer {
  @override
  String get name => 'LoggingLayer';

  /// Where log lines are written. Defaults to `print`, but can be
  /// overridden (e.g. to write to a file or forward to a log service).
  final void Function(String line) sink;

  /// In-memory history of everything logged, useful for tests/inspection.
  final List<SecurityLogEntry> history = [];

  /// Creates a logging layer. Defaults to writing to stdout via `print`
  /// unless a custom [sink] is provided.
  LoggingLayer({void Function(String line)? sink}) : sink = sink ?? print;

  @override
  Future<SecurityResult> check(RequestContext context) async {
    final entry = SecurityLogEntry(
      timestamp: DateTime.now().toUtc(),
      layerName: name,
      userId: context.userId ?? 'anonymous',
      ipAddress: context.ipAddress,
      message: 'Request reached final logging stage',
    );

    history.add(entry);
    sink(entry.toString());

    return SecurityResult.allow(message: 'Logged');
  }
}
