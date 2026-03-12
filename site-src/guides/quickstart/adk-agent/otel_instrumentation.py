# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OpenTelemetry instrumentation setup for the ADK agent."""

import logging
import os
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger(__name__)


def setup_otel_tracing(service_name: str = "adk-agent"):
    """Set up OpenTelemetry tracing with OTLP exporter and W3C trace context propagation."""
    otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    logger.info(f"Setting up OpenTelemetry tracing: service={service_name}, endpoint={otel_endpoint}")

    resource = Resource.create({
        "service.name": service_name,
        "service.namespace": os.environ.get("NAMESPACE", "default"),
        "service.instance.id": os.environ.get("HOSTNAME", "unknown"),
    })

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otel_endpoint}/v1/traces"))
    )
    trace.set_tracer_provider(tracer_provider)

    # Set W3C Trace Context as the global propagator
    # This ensures trace context is extracted from incoming requests
    # and propagated to outgoing requests automatically
    from opentelemetry import propagate
    propagate.set_global_textmap(TraceContextTextMapPropagator())

    LoggingInstrumentor().instrument(set_logging_format=True)

    logger.info("OpenTelemetry tracing configured with W3C Trace Context propagation")

    return tracer_provider


def instrument_fastapi(app):
    """Instrument a FastAPI application with OpenTelemetry.

    This automatically:
    - Extracts trace context from incoming HTTP headers (traceparent, tracestate)
    - Creates spans for each request
    - Propagates trace context to child operations
    """
    FastAPIInstrumentor.instrument_app(app)
    logger.info("FastAPI instrumented for distributed tracing")
