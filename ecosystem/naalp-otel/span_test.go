// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpotel

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalperror"
)

// newTestRecorder wires a real in-memory SDK tracer provider (tracetest.InMemoryExporter,
// synchronous) and a real SDK metric provider (a ManualReader) -- both real
// go.opentelemetry.io/otel/sdk components, no hand-rolled fakes -- and returns the
// Recorder plus the two readback handles a test needs.
func newTestRecorder(t *testing.T) (*Recorder, func() tracetest.SpanStubs, func() metricdata.ResourceMetrics) {
	t.Helper()
	tp, exp := NewInMemoryTracerProvider("naalp-otel-test")
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	rec, err := NewRecorder(tp.Tracer("naalp-otel-test"), mp.Meter("naalp-otel-test"))
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	getSpans := func() tracetest.SpanStubs { return exp.GetSpans() }
	getMetrics := func() metricdata.ResourceMetrics {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("metric reader Collect: %v", err)
		}
		return rm
	}

	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
	})
	return rec, getSpans, getMetrics
}

// attrMap flattens a tracetest.SpanStub's attribute list into a plain map for easy
// assertion lookups.
func attrMap(s tracetest.SpanStub) map[string]string {
	m := make(map[string]string, len(s.Attributes))
	for _, kv := range s.Attributes {
		m[string(kv.Key)] = kv.Value.Emit()
	}
	return m
}

// sumCounter sums every int64 data point recorded under the named instrument across all
// scopes/metrics in a collected ResourceMetrics snapshot.
func sumCounter(rm metricdata.ResourceMetrics, name string) int64 {
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// naalperror codes used across these tests, resolved through the real registry (never
// hand-picked numbers) so a registry reorder cannot silently desync the tests.
func codeFor(t *testing.T, name string) uint64 {
	t.Helper()
	code, ok := naalperror.CodeForName(name)
	if !ok {
		t.Fatalf("naalperror.CodeForName(%q): not found in the registry", name)
	}
	return code
}

func TestMapOperation_BridgeCarriageIsExecuteTool(t *testing.T) {
	op, ok := mapOperation(channelBridge, kindCarriage)
	if !ok || op != OpExecuteTool {
		t.Fatalf("mapOperation(Bridge, Carriage) = (%q, %v), want (%q, true)", op, ok, OpExecuteTool)
	}
	// Cross-check against the real channels.Table (not a hardcoded name here) so a table
	// renumber flips this test, never silently mis-maps a different channel to execute_tool.
	spec, ok := channels.Channel(channelBridge)
	if !ok || spec.Name != "Bridge" {
		t.Fatalf("channels.Channel(0x%04X) = (%v, %v), want Bridge", channelBridge, spec, ok)
	}
}

func TestMapOperation_WorkflowIsInvokeAgent(t *testing.T) {
	spec, ok := channels.Channel(channelWorkflow)
	if !ok || spec.Name != "Workflow" {
		t.Fatalf("channels.Channel(0x%04X) = (%v, %v), want Workflow", channelWorkflow, spec, ok)
	}
	for _, k := range spec.Kinds {
		op, ok := mapOperation(channelWorkflow, k.Code)
		if !ok || op != OpInvokeAgent {
			t.Fatalf("mapOperation(Workflow, %s) = (%q, %v), want (%q, true)", k.Name, op, ok, OpInvokeAgent)
		}
	}
}

func TestMapOperation_UnmappedChannelReturnsFalse(t *testing.T) {
	// Governance (0x0004) has no honest gen_ai.operation.name member -- see the mapping
	// comment in span.go. This is the negative case the mutation test in
	// TestEmitOperationSpan_UnmappedChannelHasNoGenAIOperationName below relies on.
	if _, ok := mapOperation(0x0004, 0); ok {
		t.Fatalf("mapOperation(Governance, 0) returned ok=true, want false (no honest gen_ai mapping)")
	}
}

func TestEmitOperationSpan_HappyPathExecuteTool(t *testing.T) {
	rec, getSpans, getMetrics := newTestRecorder(t)
	out := &Outcome{
		Channel:   channelBridge,
		Kind:      kindCarriage,
		Effect:    uint64(0), // read_only
		SignerID:  "did:key:z6Mktest",
		ContentID: []byte{0xde, 0xad, 0xbe, 0xef},
		Verified:  true,
		ToolName:  "search_docs",
	}
	if _, err := rec.EmitOperationSpan(context.Background(), out); err != nil {
		t.Fatalf("EmitOperationSpan: %v", err)
	}

	spans := getSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name != OpExecuteTool+" search_docs" {
		t.Fatalf("span name = %q, want %q", s.Name, OpExecuteTool+" search_docs")
	}
	if s.Status.Code != codes.Ok {
		t.Fatalf("span status = %v, want Ok", s.Status.Code)
	}
	attrs := attrMap(s)
	if attrs[AttrGenAIOperationName] != OpExecuteTool {
		t.Fatalf("attr %s = %q, want %q", AttrGenAIOperationName, attrs[AttrGenAIOperationName], OpExecuteTool)
	}
	if attrs[AttrGenAIToolName] != "search_docs" {
		t.Fatalf("attr %s = %q, want search_docs", AttrGenAIToolName, attrs[AttrGenAIToolName])
	}
	if attrs[AttrGenAIToolCallID] != "deadbeef" {
		t.Fatalf("attr %s = %q, want deadbeef", AttrGenAIToolCallID, attrs[AttrGenAIToolCallID])
	}
	if attrs[AttrNaalpSchemaStatus] != SchemaStatus {
		t.Fatalf("attr %s = %q, want %q (never present as stable/graded)", AttrNaalpSchemaStatus, attrs[AttrNaalpSchemaStatus], SchemaStatus)
	}
	if _, present := attrs[AttrErrorType]; present {
		t.Fatalf("error.type present on a successful outcome")
	}

	rm := getMetrics()
	if got := sumCounter(rm, "naalp.operations"); got != 1 {
		t.Fatalf("naalp.operations = %d, want 1", got)
	}
	if got := sumCounter(rm, "naalp.approvals.refused"); got != 0 {
		t.Fatalf("naalp.approvals.refused = %d, want 0", got)
	}
}

// TestEmitOperationSpan_VerifyFailureSetsErrorStatus is the mutation-witness anchor for
// this package (see RED-EVIDENCE notes in the build report): it asserts BOTH the span
// status AND the error.type attribute name a real, registry-resolved naalperror name on a
// verify failure. Dropping the span.SetStatus(codes.Error, ...) call in span.go flips this
// test red on the status assertion.
func TestEmitOperationSpan_VerifyFailureSetsErrorStatus(t *testing.T) {
	rec, getSpans, _ := newTestRecorder(t)
	badSig := codeFor(t, "BadSignature")
	out := &Outcome{
		Channel:         channelBridge,
		Kind:            kindCarriage,
		Effect:          0,
		Verified:        false,
		VerifyErrorCode: badSig,
	}
	if _, err := rec.EmitOperationSpan(context.Background(), out); err != nil {
		t.Fatalf("EmitOperationSpan: %v", err)
	}
	spans := getSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Status.Code != codes.Error {
		t.Fatalf("span status = %v, want Error on a verify failure", s.Status.Code)
	}
	attrs := attrMap(s)
	if attrs[AttrErrorType] != "BadSignature" {
		t.Fatalf("attr %s = %q, want BadSignature (from the real naalperror registry, not invented)", AttrErrorType, attrs[AttrErrorType])
	}
}

func TestEmitOperationSpan_ApprovalRefusalIncrementsRefusalCounter(t *testing.T) {
	rec, _, getMetrics := newTestRecorder(t)
	approvalRequired := codeFor(t, "ApprovalRequired")
	spec, ok := channels.Channel(channelWorkflow)
	if !ok || len(spec.Kinds) == 0 {
		t.Fatalf("channels.Channel(Workflow) unavailable")
	}
	out := &Outcome{
		Channel:  channelWorkflow,
		Kind:     spec.Kinds[0].Code,
		Effect:   1,
		Verified: true,
		Approval: &ApprovalOutcome{Required: true, Granted: false, RefusalErrorCode: approvalRequired},
	}
	if _, err := rec.EmitOperationSpan(context.Background(), out); err != nil {
		t.Fatalf("EmitOperationSpan: %v", err)
	}
	rm := getMetrics()
	if got := sumCounter(rm, "naalp.approvals.refused"); got != 1 {
		t.Fatalf("naalp.approvals.refused = %d, want 1", got)
	}
}

func TestEmitOperationSpan_UnmappedChannelHasNoGenAIOperationName(t *testing.T) {
	rec, getSpans, _ := newTestRecorder(t)
	// Governance/PolicyPublish (kind 0): no honest gen_ai mapping (see mapOperation).
	out := &Outcome{Channel: 0x0004, Kind: 0, Effect: 2, Verified: true}
	if _, err := rec.EmitOperationSpan(context.Background(), out); err != nil {
		t.Fatalf("EmitOperationSpan: %v", err)
	}
	spans := getSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	attrs := attrMap(spans[0])
	if _, present := attrs[AttrGenAIOperationName]; present {
		t.Fatalf("gen_ai.operation.name present on a channel with no honest mapping -- would be an invented enum value")
	}
	if spans[0].Name != "naalp.Governance.PolicyPublish" {
		t.Fatalf("span name = %q, want naalp.Governance.PolicyPublish", spans[0].Name)
	}
}

func TestEmitOperationSpan_FailClosedOnUnknownSurface(t *testing.T) {
	rec, getSpans, getMetrics := newTestRecorder(t)
	out := &Outcome{Channel: 0xFFFF, Kind: 99, Verified: true}
	_, err := rec.EmitOperationSpan(context.Background(), out)
	if err == nil {
		t.Fatalf("EmitOperationSpan on an unknown surface returned nil error, want ErrUnknownSurface")
	}
	var naalpErr *Error
	if !errors.As(err, &naalpErr) || naalpErr.Kind != "UnknownSurface" {
		t.Fatalf("error = %v, want Kind=UnknownSurface", err)
	}
	if len(getSpans()) != 0 {
		t.Fatalf("a span was emitted despite a fail-closed error -- fail-closed must emit NOTHING")
	}
	if sumCounter(getMetrics(), "naalp.operations") != 0 {
		t.Fatalf("a metric point was recorded despite a fail-closed error")
	}
}

func TestEmitOperationSpan_FailClosedOnUnknownErrorCode(t *testing.T) {
	rec, getSpans, _ := newTestRecorder(t)
	out := &Outcome{
		Channel:         channelBridge,
		Kind:            kindCarriage,
		Verified:        false,
		VerifyErrorCode: 0xFFFFFFFF, // far outside naalperror.Names' range
	}
	_, err := rec.EmitOperationSpan(context.Background(), out)
	if err == nil {
		t.Fatalf("EmitOperationSpan with an unresolvable error code returned nil error")
	}
	var naalpErr *Error
	if !errors.As(err, &naalpErr) || naalpErr.Kind != "UnknownErrorCode" {
		t.Fatalf("error = %v, want Kind=UnknownErrorCode", err)
	}
	if len(getSpans()) != 0 {
		t.Fatalf("a span was emitted despite an unresolvable error code")
	}
}

func TestEmitOperationSpan_FailClosedOnEffectOutOfRange(t *testing.T) {
	rec, getSpans, _ := newTestRecorder(t)
	out := &Outcome{Channel: channelBridge, Kind: kindCarriage, Effect: 4, Verified: true}
	_, err := rec.EmitOperationSpan(context.Background(), out)
	if err == nil {
		t.Fatalf("EmitOperationSpan with Effect=4 (outside 0..3) returned nil error")
	}
	if len(getSpans()) != 0 {
		t.Fatalf("a span was emitted despite an out-of-range effect")
	}
}

func TestEmitOperationSpan_NilOutcomeFailsClosed(t *testing.T) {
	rec, getSpans, _ := newTestRecorder(t)
	if _, err := rec.EmitOperationSpan(context.Background(), nil); !errors.Is(err, ErrNilOutcome) {
		t.Fatalf("EmitOperationSpan(nil) error = %v, want ErrNilOutcome", err)
	}
	if len(getSpans()) != 0 {
		t.Fatalf("a span was emitted for a nil Outcome")
	}
}

// TestEmitOperationSpan_EffectAttributeReflectsTheRealPolicyLabel is a second
// mutation-witness anchor: it asserts naalp.effect carries the REAL policy.Effect
// SafetyLabelName for each of the four closed values, sourced from impl/go/policy, never a
// locally reinvented string table. Replacing effectFromUint/SafetyLabelName's result with a
// constant flips this test on the destructive case (the one value that does not collide
// with any other case's expectation prefix).
func TestEmitOperationSpan_EffectAttributeReflectsTheRealPolicyLabel(t *testing.T) {
	rec, getSpans, _ := newTestRecorder(t)
	want := []string{"read_only", "idempotent_write", "non_idempotent_write", "destructive"}
	for effect := range want {
		out := &Outcome{Channel: channelBridge, Kind: kindCarriage, Effect: uint64(effect), Verified: true}
		if _, err := rec.EmitOperationSpan(context.Background(), out); err != nil {
			t.Fatalf("EmitOperationSpan(effect=%d): %v", effect, err)
		}
	}
	spans := getSpans()
	if len(spans) != 4 {
		t.Fatalf("got %d spans, want 4", len(spans))
	}
	for i, s := range spans {
		attrs := attrMap(s)
		if attrs[AttrNaalpEffect] != want[i] {
			t.Fatalf("span %d: naalp.effect = %q, want %q", i, attrs[AttrNaalpEffect], want[i])
		}
	}
}
