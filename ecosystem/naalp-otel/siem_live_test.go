// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//go:build live

package naalpotel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalperror"
)

// jaegerV3Envelope is the grpc-gateway JSON transcoding wrapper Jaeger's api_v3 QueryService
// HTTP endpoint returns for its (originally server-streaming) GetTrace RPC:
// {"result": {"resourceSpans": [...]}}, confirmed empirically against a live
// jaegertracing/jaeger:2.20.0 container this session (POST a real OTLP span to
// /v1/traces, then GET /api/v3/traces/{traceId} and observe the "result" wrapper) and
// against jaeger-idl's query_service.proto (GetTrace returns
// stream opentelemetry.proto.trace.v1.TracesData).
type jaegerV3Envelope struct {
	Result otlpTracesData `json:"result"`
}

// TestLiveSIEMBackendExport_E33 is the E3.3 D1 acceptance test: it stands up a REAL
// observability/SIEM-shaped backend -- jaegertracing/jaeger:2.20.0, the latest tagged
// Jaeger release confirmed against the GitHub Releases API this session, which natively
// terminates OTLP (no bridging collector needed, confirmed by probing the same image's
// /v1/traces + /api/v3/traces/{id} endpoints live this session) -- exports the N-AALP
// AUDIT channel over the real OTLP/HTTP exporter, and asserts the exported object actually
// LANDED in the backend's own storage with its naalp.* attributes AND error.type intact,
// read back through Jaeger's own stable, documented Query API (api_v3.QueryService,
// JSON/HTTP transcoding, https://www.jaegertracing.io/docs/2.20/apis/). This is a genuinely
// different real backend from the E3.1 Collector test (a full storage+query backend, not a
// receive-and-re-export sink), so the two D1 tests are not the same round trip counted
// twice.
//
// D1 failure requirement: this test fails if Jaeger never stores/serves the trace (the
// query poll window elapses with no matching span -- see RED-EVIDENCE.md
// "naalp-otel / live-siem-backend-export" for the recorded mutation-witness: pointing the
// exporter at the wrong port flips this test red).
func TestLiveSIEMBackendExport_E33(t *testing.T) {
	requireDocker(t)

	otlpPort := freeTCPPort(t)
	queryPort := freeTCPPort(t)
	c := runContainer(t, "siem-e33",
		"jaegertracing/jaeger:2.20.0",
		[]string{
			"-p", fmt.Sprintf("%d:4318/tcp", otlpPort),
			"-p", fmt.Sprintf("%d:16686/tcp", queryPort),
		},
		"", "", // Jaeger's all-in-one image ships OTLP+query enabled by default; no config to inject.
	)

	otlpEndpoint := fmt.Sprintf("127.0.0.1:%d", otlpPort)
	queryBase := fmt.Sprintf("http://127.0.0.1:%d", queryPort)
	waitForTCP(t, otlpEndpoint, 60*time.Second)
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", queryPort), 60*time.Second)
	// See waitForHTTPReady's doc comment: a bare TCP-accept is not proof the container's HTTP
	// servers are ready to complete a request yet on this Docker Desktop setup.
	waitForHTTPReady(t, "http://"+otlpEndpoint+"/", 20*time.Second)
	waitForHTTPReady(t, queryBase+"/", 20*time.Second)

	runSIEMExport(t, otlpEndpoint, queryBase)
	_ = c
}

// runSIEMExport emits one real Outcome on the N-AALP Audit channel (0x000B, kind 0
// "Receipt" -- impl/go/channels.Table) through the real OTLP/HTTP exporter pointed at
// otlpEndpoint, forces a real verify-failure so error.type is populated (naalperror
// "BadSignature", resolved from the real registry, never invented), force-flushes, then
// polls Jaeger's real Query API v3 (queryBase) for the resulting trace and asserts the
// naalp.* + error.type attributes arrived exactly as emitted.
func runSIEMExport(t *testing.T, otlpEndpoint, queryBase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tp, shutdown, err := NewOTLPHTTPTracerProvider(ctx, "naalp-otel-live-e33", otlpEndpoint, true)
	if err != nil {
		t.Fatalf("NewOTLPHTTPTracerProvider: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = shutdown(shutdownCtx)
	}()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	rec, err := NewRecorder(tp.Tracer("naalp-otel-live-e33"), mp.Meter("naalp-otel-live-e33"))
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	badSig, ok := naalperror.CodeForName("BadSignature")
	if !ok {
		t.Fatalf("naalperror.CodeForName(BadSignature): not found in the real registry")
	}

	const auditChannel uint64 = 0x000B // channels.Table: Audit
	const auditKindReceipt uint64 = 0  // Audit's kind 0: "Receipt"

	out := &Outcome{
		Channel:         auditChannel,
		Kind:            auditKindReceipt,
		Effect:          2, // non_idempotent_write -- matches Receipt's niw KindSpec classification
		SignerID:        "did:key:z6MkLiveE33Test",
		ContentID:       []byte{0x51, 0xe1, 0x00, 0x42},
		Verified:        false,
		VerifyErrorCode: badSig,
	}
	sc, err := rec.EmitOperationSpan(ctx, out)
	if err != nil {
		t.Fatalf("EmitOperationSpan: %v", err)
	}
	if !sc.HasTraceID() {
		t.Fatalf("EmitOperationSpan returned a SpanContext with no trace ID")
	}
	traceID := sc.TraceID().String()

	if err := tp.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	wantSpanName := "naalp.Audit.Receipt"

	var span otlpSpan
	var found bool
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	client := &http.Client{Timeout: 5 * time.Second}
	url := queryBase + "/api/v3/traces/" + traceID
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("GET %s: status %d, body %s", url, resp.StatusCode, string(body))
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var env jaegerV3Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("decoding Jaeger v3 GetTrace response: %v\nbody: %s", err, string(body))
		}
		if span, found = findSpanByNamePrefix(env.Result, wantSpanName); found {
			break
		}
		lastErr = fmt.Errorf("trace %s present in Jaeger's response but no span named %q yet (body: %s)", traceID, wantSpanName, string(body))
		time.Sleep(500 * time.Millisecond)
	}
	if !found {
		t.Fatalf("the real Jaeger backend never stored/served the exported audit span (trace %s, %q) within the poll window (last: %v)", traceID, wantSpanName, lastErr)
	}

	attrs := attrFlatten(span.Attributes)
	if attrs[AttrNaalpChannelName] != "Audit" {
		t.Fatalf("%s = %q, want Audit", AttrNaalpChannelName, attrs[AttrNaalpChannelName])
	}
	if attrs[AttrNaalpKindName] != "Receipt" {
		t.Fatalf("%s = %q, want Receipt", AttrNaalpKindName, attrs[AttrNaalpKindName])
	}
	if attrs[AttrNaalpSignerID] != "did:key:z6MkLiveE33Test" {
		t.Fatalf("%s = %q, want did:key:z6MkLiveE33Test", AttrNaalpSignerID, attrs[AttrNaalpSignerID])
	}
	if attrs[AttrNaalpContentID] != "51e10042" {
		t.Fatalf("%s = %q, want 51e10042", AttrNaalpContentID, attrs[AttrNaalpContentID])
	}
	if attrs[AttrNaalpVerified] != "false" {
		t.Fatalf("%s = %q, want false (this is a deliberate verify-failure outcome)", AttrNaalpVerified, attrs[AttrNaalpVerified])
	}
	if attrs[AttrErrorType] != "BadSignature" {
		t.Fatalf("%s = %q, want BadSignature (resolved from the real naalperror registry, survived the real OTLP export + Jaeger storage round trip)", AttrErrorType, attrs[AttrErrorType])
	}
	if attrs[AttrNaalpSchemaStatus] != SchemaStatus {
		t.Fatalf("%s = %q, want %q", AttrNaalpSchemaStatus, attrs[AttrNaalpSchemaStatus], SchemaStatus)
	}
	if span.Status.Code != 2 { // opentelemetry.proto.trace.v1.Status.STATUS_CODE_ERROR == 2
		t.Fatalf("span status code = %d, want 2 (STATUS_CODE_ERROR) for a verify failure", span.Status.Code)
	}
}
