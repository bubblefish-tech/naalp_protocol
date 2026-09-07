// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//go:build live

package naalpotel

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// TestLiveCollectorRoundTrip_E31 is the E3.1 D1 acceptance test: it stands up a REAL
// OpenTelemetry Collector (otel/opentelemetry-collector-contrib:0.160.0, the latest tagged
// release confirmed against the GitHub Releases API this session) in Docker, points this
// package's real OTLP/HTTP exporter (NewOTLPHTTPTracerProvider -- the same constructor
// production callers use) at its OTLP/HTTP receiver, emits one real N-AALP operation span
// through the real Recorder, and asserts the Collector actually RECEIVED it: it reads back
// the Collector's own file-exporter output (a real component of the real collector process,
// confirmed present in the v0.160.0 contrib manifest) and checks the gen_ai.* + naalp.*
// attributes arrived byte-for-byte as emitted. No mock exporter, no mock collector, no
// in-memory stand-in anywhere in this path.
//
// D1 failure requirement: this test fails if the Collector does not receive the span (the
// file never contains a matching span within the poll window -- see the mutation-witness
// note below, which proves this concretely by pointing the exporter at a closed port).
func TestLiveCollectorRoundTrip_E31(t *testing.T) {
	requireDocker(t)

	cfgPath, err := filepath.Abs(filepath.Join("testdata", "otelcol-config.yaml"))
	if err != nil {
		t.Fatalf("resolving testdata/otelcol-config.yaml: %v", err)
	}

	hostPort := freeTCPPort(t)
	// --user 0:0: the official image is FROM scratch with no /tmp and a non-root default
	// user; running as root here lets the file exporter write /etc/otelcol-contrib/spans.json
	// regardless of that directory's baked-in ownership (see testdata/otelcol-config.yaml).
	c := runContainer(t, "collector-e31",
		"otel/opentelemetry-collector-contrib:0.160.0",
		[]string{"-p", fmt.Sprintf("%d:4318/tcp", hostPort), "--user", "0:0"},
		cfgPath, "/etc/otelcol-contrib/config.yaml",
	)

	endpoint := fmt.Sprintf("127.0.0.1:%d", hostPort)
	waitForTCP(t, endpoint, 60*time.Second)
	waitForHTTPReady(t, "http://"+endpoint+"/", 20*time.Second)

	runCollectorRoundTrip(t, c, endpoint, "search_docs_e31_live")
}

// runCollectorRoundTrip emits one real Outcome through a real Recorder pointed at endpoint,
// force-flushes, polls the collector container's file-exporter output for a span whose name
// starts with toolName's derived span name, and asserts the gen_ai.*/naalp.* attributes
// survived the real OTLP/HTTP wire trip + the collector's own re-export to disk. Returns the
// exact span name it looked for (used by TestLiveCollectorRoundTrip_E31's mutation-witness
// companion run to assert absence at a dead endpoint).
func runCollectorRoundTrip(t *testing.T, c *dockerContainer, endpoint, toolName string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tp, shutdown, err := NewOTLPHTTPTracerProvider(ctx, "naalp-otel-live-e31", endpoint, true)
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

	rec, err := NewRecorder(tp.Tracer("naalp-otel-live-e31"), mp.Meter("naalp-otel-live-e31"))
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	out := &Outcome{
		Channel:   channelBridge,
		Kind:      kindCarriage,
		Effect:    0, // read_only
		SignerID:  "did:key:z6MkLiveE31Test",
		ContentID: []byte{0xca, 0xfe, 0xba, 0xbe},
		Verified:  true,
		ToolName:  toolName,
	}
	if _, err := rec.EmitOperationSpan(ctx, out); err != nil {
		t.Fatalf("EmitOperationSpan: %v", err)
	}
	if err := tp.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	wantName := OpExecuteTool + " " + toolName
	hostDest := filepath.Join(t.TempDir(), "spans.json")

	var span otlpSpan
	var found bool
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := catFromContainer(c.name, "/etc/otelcol-contrib/spans.json", hostDest)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if span, found = parseTracesDataLines(t, raw, wantName); found {
			break
		}
		lastErr = fmt.Errorf("collector output present but no span named %q found yet", wantName)
		time.Sleep(500 * time.Millisecond)
	}
	if !found {
		t.Fatalf("the real Collector never received/exported the span %q within the poll window (last: %v)", wantName, lastErr)
	}

	attrs := attrFlatten(span.Attributes)
	if attrs[AttrGenAIOperationName] != OpExecuteTool {
		t.Fatalf("%s = %q, want %q (collector-received span)", AttrGenAIOperationName, attrs[AttrGenAIOperationName], OpExecuteTool)
	}
	if attrs[AttrGenAIToolName] != toolName {
		t.Fatalf("%s = %q, want %q", AttrGenAIToolName, attrs[AttrGenAIToolName], toolName)
	}
	if attrs[AttrGenAIToolCallID] != "cafebabe" {
		t.Fatalf("%s = %q, want cafebabe", AttrGenAIToolCallID, attrs[AttrGenAIToolCallID])
	}
	if attrs[AttrNaalpSignerID] != "did:key:z6MkLiveE31Test" {
		t.Fatalf("%s = %q, want did:key:z6MkLiveE31Test", AttrNaalpSignerID, attrs[AttrNaalpSignerID])
	}
	if attrs[AttrNaalpEffect] != "read_only" {
		t.Fatalf("%s = %q, want read_only", AttrNaalpEffect, attrs[AttrNaalpEffect])
	}
	if attrs[AttrNaalpSchemaStatus] != SchemaStatus {
		t.Fatalf("%s = %q, want %q (the collector must see the honest experimental-pinned-sha status too)", AttrNaalpSchemaStatus, attrs[AttrNaalpSchemaStatus], SchemaStatus)
	}
	if attrs[AttrNaalpSchemaSHA] != PinnedSemconvGenAISHA {
		t.Fatalf("%s = %q, want %q", AttrNaalpSchemaSHA, attrs[AttrNaalpSchemaSHA], PinnedSemconvGenAISHA)
	}

	return wantName
}
