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
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor

logger = logging.getLogger(__name__)


def setup_otel_tracing(service_name: str = "adk-agent"):
    """
    Set up OpenTelemetry tracing with OTLP exporter.

    Args:
        service_name: Name of the service for tracing
    """
    # Get OTEL collector endpoint from environment
    otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    logger.info(f"Setting up OpenTelemetry tracing for service: {service_name}")
    logger.info(f"OTLP endpoint: {otel_endpoint}")

    # Create a resource with service name
    resource = Resource.create({
        "service.name": service_name,
        "service.namespace": os.environ.get("NAMESPACE", "default"),
        "service.instance.id": os.environ.get("HOSTNAME", "unknown"),
    })

    # Set up the tracer provider
    tracer_provider = TracerProvider(resource=resource)

    # Configure OTLP exporter
    otlp_exporter = OTLPSpanExporter(
        endpoint=otel_endpoint,
        insecure=True,  # Use insecure connection for simplicity
    )

    # Add span processor
    span_processor = BatchSpanProcessor(otlp_exporter)
    tracer_provider.add_span_processor(span_processor)

    # Set the global tracer provider
    trace.set_tracer_provider(tracer_provider)

    # Instrument logging to include trace context
    LoggingInstrumentor().instrument(set_logging_format=True)

    logger.info("OpenTelemetry tracing setup complete")

    return tracer_provider


def instrument_fastapi(app):
    """
    Instrument a FastAPI application with OpenTelemetry.

    Args:
        app: FastAPI application instance
    """
    logger.info("Instrumenting FastAPI application")
    FastAPIInstrumentor.instrument_app(app)
    logger.info("FastAPI instrumentation complete")


def get_tracer(name: str = __name__):
    """
    Get a tracer instance.

    Args:
        name: Name for the tracer

    Returns:
        Tracer instance
    """
    return trace.get_tracer(name)
