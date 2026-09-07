// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpotel

import (
	"context"
	"testing"
	"time"
)

// TestNewOTLPHTTPTracerProvider_ConstructsAndShutsDownWithoutALiveCollector confirms that
// building the real OTLP/HTTP exporter (E3.3) and shutting it down does not require a live
// collector: otlptracehttp.New dials lazily, and shutting down a provider that never
// exported anything must not hang or dial out. This directly tests the real stable
// go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp client, not a fake -- it
// simply never points it at a live server (per the build instruction: no live external
// collector in this suite).
func TestNewOTLPHTTPTracerProvider_ConstructsAndShutsDownWithoutALiveCollector(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tp, shutdown, err := NewOTLPHTTPTracerProvider(ctx, "naalp-otel-test-service", "127.0.0.1:1", true)
	if err != nil {
		t.Fatalf("NewOTLPHTTPTracerProvider: %v", err)
	}
	if tp == nil {
		t.Fatalf("NewOTLPHTTPTracerProvider returned a nil provider with a nil error")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestNewOTLPHTTPTracerProvider_FailsClosedOnEmptyServiceName(t *testing.T) {
	_, _, err := NewOTLPHTTPTracerProvider(context.Background(), "", "127.0.0.1:1", true)
	if err == nil {
		t.Fatalf("NewOTLPHTTPTracerProvider with an empty serviceName returned nil error")
	}
}

func TestNewOTLPHTTPTracerProvider_FailsClosedOnEmptyEndpoint(t *testing.T) {
	_, _, err := NewOTLPHTTPTracerProvider(context.Background(), "svc", "", true)
	if err == nil {
		t.Fatalf("NewOTLPHTTPTracerProvider with an empty endpoint returned nil error")
	}
}

// TestNewInMemoryTracerProvider_RoundTripsASpan confirms the in-memory (E3.3 test/demo
// path) provider is wired correctly end to end: a span started/ended through it is
// observable via the exporter's GetSpans() synchronously, with no batching delay.
func TestNewInMemoryTracerProvider_RoundTripsASpan(t *testing.T) {
	tp, exp := NewInMemoryTracerProvider("naalp-otel-roundtrip")
	defer func() { _ = tp.Shutdown(context.Background()) }()

	_, span := tp.Tracer("test").Start(context.Background(), "manual-span")
	span.End()

	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "manual-span" {
		t.Fatalf("GetSpans() = %+v, want exactly one span named manual-span", spans)
	}
}
