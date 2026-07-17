"""Structured logs, request metrics, and optional OpenTelemetry export."""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from prometheus_client import CollectorRegistry, Counter, Histogram, make_asgi_app


class JsonLogFormatter(logging.Formatter):
    def __init__(self, *, service_name: str) -> None:
        super().__init__()
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "service": self._service_name,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field_name in ("request_id", "method", "path", "status_code", "duration_ms"):
            value = getattr(record, field_name, None)
            if value is not None:
                document[field_name] = value
        if record.exc_info:
            document["exception"] = self.formatException(record.exc_info)
        return json.dumps(document, separators=(",", ":"), ensure_ascii=False)


def configure_logging(*, service_name: str, level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter(service_name=service_name))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


def configure_observability(
    app: FastAPI,
    *,
    service_name: str,
    otlp_endpoint: str | None,
) -> None:
    registry = CollectorRegistry(auto_describe=True)
    requests = Counter(
        "aegisledger_http_requests_total",
        "HTTP requests processed by the proposal gateway",
        ("method", "route", "status"),
        registry=registry,
    )
    latency = Histogram(
        "aegisledger_http_request_duration_seconds",
        "Proposal gateway request duration",
        ("method", "route"),
        registry=registry,
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    )
    logger = logging.getLogger("aegisledger.http")

    @app.middleware("http")
    async def request_telemetry(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        started = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - started
        route = request.scope.get("route")
        route_path = getattr(route, "path", request.url.path)
        requests.labels(request.method, route_path, str(response.status_code)).inc()
        latency.labels(request.method, route_path).observe(duration)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": route_path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1_000, 3),
            },
        )
        return response

    app.mount("/metrics", make_asgi_app(registry=registry))
    _configure_tracing(app, service_name=service_name, otlp_endpoint=otlp_endpoint)


def _configure_tracing(
    app: FastAPI,
    *,
    service_name: str,
    otlp_endpoint: str | None,
) -> None:
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logging.getLogger(__name__).warning("OpenTelemetry instrumentation is unavailable")
        return

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True))
        )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
