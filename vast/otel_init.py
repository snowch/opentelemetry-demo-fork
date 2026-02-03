"""Shared OpenTelemetry bootstrap for observability services."""

import os
import functools
import warnings
from contextlib import contextmanager

_tracer_provider = None
_initialized = False

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False

try:
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    _REQUESTS_INSTRUMENTOR_AVAILABLE = True
except ImportError:
    _REQUESTS_INSTRUMENTOR_AVAILABLE = False


def init_telemetry(service_name: str) -> None:
    """Initialize OpenTelemetry with OTLP gRPC exporter.

    No-ops gracefully if packages are missing or collector is unreachable.
    """
    global _tracer_provider, _initialized

    if _initialized:
        return

    if not _OTEL_AVAILABLE:
        warnings.warn("OpenTelemetry packages not installed; tracing disabled.")
        _initialized = True
        return

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")

    try:
        resource = Resource.create({
            "service.name": service_name,
            "service.namespace": "opentelemetry-demo",
        })
        _tracer_provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        _tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(_tracer_provider)

        # Auto-instrument the requests library so the Trino Python client
        # propagates traceparent headers to the Trino coordinator.
        if _REQUESTS_INSTRUMENTOR_AVAILABLE:
            RequestsInstrumentor().instrument()

        _initialized = True
        print(f"[OTel] Tracing initialized for {service_name} -> {endpoint}")
    except Exception as e:
        warnings.warn(f"OpenTelemetry init failed, tracing disabled: {e}")
        _initialized = True


def get_tracer(name: str = __name__):
    """Return a tracer from the global provider."""
    if _OTEL_AVAILABLE and _tracer_provider:
        return trace.get_tracer(name)
    return None


def traced(func):
    """Decorator that wraps a function in an OTel span.

    Span name: {module}.{function}. Records exceptions automatically.
    Becomes a passthrough if tracing is not available.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tracer = get_tracer(func.__module__)
        if tracer is None:
            return func(*args, **kwargs)
        with tracer.start_as_current_span(f"{func.__module__}.{func.__qualname__}") as span:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                span.set_status(StatusCode.ERROR, str(e))
                span.record_exception(e)
                raise
    return wrapper


@contextmanager
def traced_cursor(cursor, sql: str):
    """Context manager that wraps a cursor.execute() in a db.query span.

    Usage:
        cursor = conn.cursor()
        with traced_cursor(cursor, sql) as cur:
            cur.execute(sql)
            rows = cur.fetchall()

    Attributes: db.system=trino, db.statement (first 4096 chars).
    Adds full SQL as a span event when the query exceeds 4096 chars.
    Records row count on success, exception on failure.
    """
    tracer = get_tracer("db")
    if tracer is None:
        yield cursor
        return

    # Normalise whitespace for readability in trace UIs
    clean_sql = " ".join(sql.split())

    with tracer.start_as_current_span("db.query") as span:
        span.set_attribute("db.system", "trino")
        span.set_attribute("db.statement", clean_sql[:4096])
        if len(clean_sql) > 4096:
            span.add_event("db.statement.full", {"db.statement": clean_sql})
        try:
            yield cursor
            # Record row count if available
            if cursor.description:
                span.set_attribute("db.row_count", cursor.rowcount if cursor.rowcount >= 0 else 0)
        except Exception as e:
            span.set_status(StatusCode.ERROR, str(e))
            span.record_exception(e)
            raise
