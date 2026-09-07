// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naalpotel implements ecosystem tasks E3.1 (OTel span/metric emission for N-AALP
// operations, mapped onto the gen_ai.* semantic-convention attributes where honest) and
// E3.3 (OTLP export of those spans/metrics to a collector/SIEM), per requirements R5.1/R5.3.
//
// This is an ECOSYSTEM/adoption-layer package: additive only, no wire/CDDL/vector change.
// It performs no cryptography, no CBOR encoding, and no second content-id computation of
// its own -- every byte-level fact it reports (channel, kind, effect, signer id, content id,
// error names) is read from the real Part-1 reference implementation
// (impl/go/channels, impl/go/policy, impl/go/naalperror), never reinvented, matching the
// "buy-before-make" pattern the sibling ecosystem/naalp-agent-go module already follows.
//
// EXPERIMENTAL SCHEMA -- see attrs.go for the full grounding. The OTel Go SDK this package
// builds on is stable (v1.46.0). The gen_ai.* attribute NAMES this package emits are pinned
// to one upstream commit SHA because the schema that owns them has shipped zero tagged
// releases. Every span and metric this package emits carries naalp.otel.schema_status =
// "experimental-pinned-sha" -- callers MUST surface that status, never present this
// package's output as graded or stable telemetry.
package naalpotel

import (
	"context"
	"encoding/hex"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalperror"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// effectFromUint decodes an already-range-checked (0..3) wire effect value into the real
// impl/go/policy.Effect type -- the caller (EmitOperationSpan) validates the range first
// so this never indexes policy.Effect.SafetyLabelName's fixed 4-element array out of bounds.
func effectFromUint(v uint64) policy.Effect { return policy.Effect(v) }

// The two N-AALP channels this package maps onto the gen_ai.operation.name closed enum
// (see mapOperation). Named here, not left as magic numbers, and cross-checked against the
// real impl/go/channels.Table by name in span_test.go (a drift in channels.Table's
// numbering would flip that test, not silently mis-map).
const (
	channelBridge   uint64 = 0x000D // channels.Table[13].Name == "Bridge"
	channelWorkflow uint64 = 0x0011 // channels.Table[17].Name == "Workflow"
	kindCarriage    uint64 = 0      // Bridge's only kind: "Carriage"
)

// mapOperation honestly maps an N-AALP (channel, kind) pair onto a gen_ai.operation.name
// closed-enum member, or reports ok=false when no member of that enum corresponds. Only
// two N-AALP surfaces get a gen_ai.operation.name: Bridge/Carriage (the channel that
// literally carries an MCP/A2A tool invocation across the wire -> execute_tool) and every
// Workflow kind (a task-orchestration lifecycle -> invoke_agent, the closest closed-enum
// member for "an agent is being invoked to do work"). Every other N-AALP channel (Control,
// Memory, Capability, Identity, Governance, Immune, Federation, Settlement, Compliance,
// Sensory, Telemetry, Audit, Stream, Commerce, Interaction, Discovery, Knowledge, Spatial)
// has no honest gen_ai.operation.name member and gets none -- its span name and attributes
// come from the naalp.* namespace instead (see EmitOperationSpan).
func mapOperation(channelID, kindID uint64) (op string, ok bool) {
	switch {
	case channelID == channelBridge && kindID == kindCarriage:
		return OpExecuteTool, true
	case channelID == channelWorkflow:
		return OpInvokeAgent, true
	default:
		return "", false
	}
}

// ApprovalOutcome describes a governance approval/refusal gate that applied to the object
// this Outcome reports on. A nil ApprovalOutcome on Outcome means no approval gate applied
// to this object at all (never confused with "applied and silently granted").
type ApprovalOutcome struct {
	Required bool
	Granted  bool
	// RefusalErrorCode is the naalperror code explaining a refusal (nonzero iff !Granted).
	// It MUST resolve via naalperror.NameForCode; an unresolvable code fails the whole
	// EmitOperationSpan call closed (ErrUnknownErrorCode) rather than reporting a blank
	// error.type.
	RefusalErrorCode uint64
}

// Outcome describes one N-AALP object's execution/verification/approval outcome -- the
// input to EmitOperationSpan. Fields mirror envelope.Object directly (Channel, Kind,
// Effect, and the signer/content identifiers a caller has already computed for that
// object) so a caller never re-derives anything this package could get from the object
// itself; ProviderName/ToolName/AgentName are the three gen_ai.* fields N-AALP has no
// native carrier for and are OPTIONAL -- "" means omit the attribute, never invented.
type Outcome struct {
	Channel   uint64
	Kind      uint64
	Effect    uint64 // envelope.Object.Effect; must decode to policy.Effect (0..3)
	SignerID  string // identity.SignerID(...) output; "" = unknown/absent
	ContentID []byte // the object's content-id; nil = absent

	Verified        bool
	VerifyErrorCode uint64 // naalperror code explaining a verify failure; 0 = success

	ProviderName string // OPTIONAL caller-supplied gen_ai.provider.name; "" = omit
	ToolName     string // OPTIONAL caller-supplied gen_ai.tool.name; "" = omit
	AgentName    string // OPTIONAL caller-supplied gen_ai.agent.name; "" = omit

	Approval *ApprovalOutcome // nil = no approval gate applied to this object
}

// Recorder holds the OTel instruments EmitOperationSpan uses. Created once per
// tracer/meter pair (NewRecorder), not per call, so instrument creation errors surface at
// setup time rather than being swallowed per-span.
type Recorder struct {
	tracer         trace.Tracer
	opCounter      metric.Int64Counter
	refusalCounter metric.Int64Counter
}

// NewRecorder builds a Recorder against a real tracer and meter (obtained from a real
// trace.TracerProvider / metric.MeterProvider -- an SDK provider in production, an
// in-memory/manual-reader provider in tests; see export.go and span_test.go). Fails
// closed if instrument creation itself fails (a malformed unit/description would be a
// programmer error in this package, not a runtime input).
func NewRecorder(tracer trace.Tracer, meter metric.Meter) (*Recorder, error) {
	if tracer == nil || meter == nil {
		return nil, wrapf(ErrNilOutcome, "tracer and meter must both be non-nil")
	}
	opCounter, err := meter.Int64Counter(
		"naalp.operations",
		metric.WithDescription("count of N-AALP operation outcomes emitted as OTel spans (naalpotel, experimental pinned-SHA gen_ai schema)"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("naalpotel: creating naalp.operations counter: %w", err)
	}
	refusalCounter, err := meter.Int64Counter(
		"naalp.approvals.refused",
		metric.WithDescription("count of N-AALP governance approval refusals observed by naalpotel"),
		metric.WithUnit("{refusal}"),
	)
	if err != nil {
		return nil, fmt.Errorf("naalpotel: creating naalp.approvals.refused counter: %w", err)
	}
	return &Recorder{tracer: tracer, opCounter: opCounter, refusalCounter: refusalCounter}, nil
}

// EmitOperationSpan emits one completed span (and the associated naalp.operations /
// naalp.approvals.refused metric points) for a single N-AALP object outcome. It reports
// on an ALREADY-COMPLETED outcome (verification and any approval gate have already run),
// so the span is started and ended within this call -- there is no separate "start" call.
//
// Fail-closed: a malformed Outcome (an unresolvable channel/kind pair, or an error code
// absent from the naalperror registry) returns a named *Error and emits NEITHER a span
// NOR a metric point. A caller MUST NOT treat a returned error as "emit an empty span
// anyway" -- there is no code path in this function that does that.
func (r *Recorder) EmitOperationSpan(ctx context.Context, out *Outcome) (trace.SpanContext, error) {
	if out == nil {
		return trace.SpanContext{}, ErrNilOutcome
	}

	// Resolve the (channel, kind) pair against the real registry -- fail closed on an
	// unknown surface rather than guessing at names.
	chSpec, chOK := channels.Channel(out.Channel)
	kSpec, kOK := channels.Lookup(out.Channel, out.Kind)
	if !chOK || !kOK {
		return trace.SpanContext{}, wrapf(ErrUnknownSurface, "channel=0x%04X kind=%d", out.Channel, out.Kind)
	}

	// Effect must decode to the closed 0..3 policy.Effect range -- policy.Effect.SafetyLabelName
	// indexes a fixed 4-element array and would panic on an out-of-range value, so this
	// package validates rather than trusting the caller.
	if out.Effect > 3 {
		return trace.SpanContext{}, wrapf(ErrUnknownSurface, "effect=%d is outside the closed 0..3 policy.Effect range", out.Effect)
	}
	effect := effectFromUint(out.Effect)

	// Resolve the verify-error name (if any) against the real naalperror registry -- never
	// fabricate error.type.
	var verifyErrName string
	if out.VerifyErrorCode != 0 {
		name, ok := naalperror.NameForCode(out.VerifyErrorCode)
		if !ok {
			return trace.SpanContext{}, wrapf(ErrUnknownErrorCode, "VerifyErrorCode=%d", out.VerifyErrorCode)
		}
		verifyErrName = name
	}

	// Resolve the approval-refusal name (if any), same discipline.
	var refusalErrName string
	if out.Approval != nil && !out.Approval.Granted && out.Approval.RefusalErrorCode != 0 {
		name, ok := naalperror.NameForCode(out.Approval.RefusalErrorCode)
		if !ok {
			return trace.SpanContext{}, wrapf(ErrUnknownErrorCode, "Approval.RefusalErrorCode=%d", out.Approval.RefusalErrorCode)
		}
		refusalErrName = name
	}

	opName, opOK := mapOperation(out.Channel, out.Kind)
	spanName := "naalp." + chSpec.Name + "." + kSpec.Name
	if opOK {
		// A gen_ai closed-enum operation applies: OTel convention names the span after the
		// operation, e.g. "execute_tool <tool>" / "invoke_agent <name>" -- but since a tool
		// or agent NAME is optional/caller-supplied here (never invented), keep the span
		// name to the operation alone when no name was supplied.
		if opName == OpExecuteTool && out.ToolName != "" {
			spanName = opName + " " + out.ToolName
		} else if opName == OpInvokeAgent && out.AgentName != "" {
			spanName = opName + " " + out.AgentName
		} else {
			spanName = opName
		}
	}

	attrs := make([]attribute.KeyValue, 0, 16)
	attrs = append(attrs,
		attribute.String(AttrNaalpChannelName, chSpec.Name),
		attribute.Int64(AttrNaalpChannelID, int64(out.Channel)),
		attribute.String(AttrNaalpKindName, kSpec.Name),
		attribute.Int64(AttrNaalpKindID, int64(out.Kind)),
		attribute.String(AttrNaalpEffect, effect.SafetyLabelName()),
		attribute.Bool(AttrNaalpVerified, out.Verified),
		attribute.String(AttrNaalpSchemaStatus, SchemaStatus),
		attribute.String(AttrNaalpSchemaSHA, PinnedSemconvGenAISHA),
	)
	if out.SignerID != "" {
		attrs = append(attrs, attribute.String(AttrNaalpSignerID, out.SignerID))
		// gen_ai.agent.id and naalp.signer_id (above) are deliberately set to the SAME value
		// (out.SignerID): one identity under two names, so a standard OTel/GenAI consumer reads
		// gen_ai.agent.id while a naalp-native consumer reads naalp.signer_id. They are NOT two
		// independent facts — a reader MUST NOT treat their equality as cross-corroboration.
		attrs = append(attrs, attribute.String(AttrGenAIAgentID, out.SignerID))
	}
	if len(out.ContentID) > 0 {
		attrs = append(attrs, attribute.String(AttrNaalpContentID, hex.EncodeToString(out.ContentID)))
	}
	if opOK {
		attrs = append(attrs, attribute.String(AttrGenAIOperationName, opName))
	}
	if out.ProviderName != "" {
		attrs = append(attrs, attribute.String(AttrGenAIProviderName, out.ProviderName))
	}
	if out.AgentName != "" {
		attrs = append(attrs, attribute.String(AttrGenAIAgentName, out.AgentName))
	}
	if out.ToolName != "" {
		attrs = append(attrs, attribute.String(AttrGenAIToolName, out.ToolName))
	}
	if opName == OpExecuteTool && len(out.ContentID) > 0 {
		attrs = append(attrs, attribute.String(AttrGenAIToolCallID, hex.EncodeToString(out.ContentID)))
	}
	if out.Approval != nil {
		attrs = append(attrs,
			attribute.Bool(AttrNaalpApprovalReq, out.Approval.Required),
			attribute.Bool(AttrNaalpApprovalGrant, out.Approval.Granted),
		)
	}

	failed := !out.Verified || (out.Approval != nil && !out.Approval.Granted)
	errType := verifyErrName
	if errType == "" {
		errType = refusalErrName
	}
	if failed && errType != "" {
		attrs = append(attrs, attribute.String(AttrErrorType, errType))
	}

	_, span := r.tracer.Start(ctx, spanName, trace.WithAttributes(attrs...))
	if failed {
		msg := errType
		if msg == "" {
			msg = "naalp operation outcome failed with no named error code"
		}
		span.SetStatus(codes.Error, msg)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	sc := span.SpanContext()
	span.End()

	metricAttrs := []attribute.KeyValue{
		attribute.String(AttrNaalpChannelName, chSpec.Name),
		attribute.String(AttrNaalpEffect, effect.SafetyLabelName()),
	}
	if opOK {
		metricAttrs = append(metricAttrs, attribute.String(AttrGenAIOperationName, opName))
	}
	if failed && errType != "" {
		metricAttrs = append(metricAttrs, attribute.String(AttrErrorType, errType))
	}
	r.opCounter.Add(ctx, 1, metric.WithAttributes(metricAttrs...))

	if out.Approval != nil && !out.Approval.Granted {
		r.refusalCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String(AttrNaalpChannelName, chSpec.Name),
			attribute.String(AttrErrorType, refusalErrName),
		))
	}

	return sc, nil
}
