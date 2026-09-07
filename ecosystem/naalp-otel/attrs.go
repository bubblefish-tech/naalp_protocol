// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpotel

// EXPERIMENTAL / PRE-RELEASE SCHEMA.
//
// The OpenTelemetry Go SDK this package builds on (go.opentelemetry.io/otel, .../sdk,
// .../sdk/metric, .../exporters/otlp/otlptrace/otlptracehttp -- all v1.46.0, released
// 2026-08-25, confirmed via the Go module proxy https://proxy.golang.org this session)
// IS STABLE: it is the OTel project's own v1.x line, the stable API/SDK surface. Building
// against it is real, production-grade dependency use, not an experimental gamble.
//
// What is EXPERIMENTAL is only the gen_ai.* ATTRIBUTE-NAME SCHEMA below. As of the
// upstream-primary-source re-check (re-verified this session, 2026-08-31): the repo that owns these conventions,
// https://github.com/open-telemetry/semantic-conventions-genai, has shipped ZERO tagged
// releases and ZERO tags in its entire history (GitHub Releases API and Tags API both
// return an empty array), its CHANGELOG.md reads only "## Unreleased", and every gen_ai.*
// item is marked upstream stability "development" (below "experimental", let alone
// "stable"). There is no versioned schema to depend on -- only a moving commit SHA.
//
// So every gen_ai.* constant below is pinned to one specific upstream commit SHA (F3: an
// independent, non-circular authority -- the upstream YAML model, never this codebase),
// NOT a release tag, because no release tag exists:
//
//	Pinned SHA: 67dff024110be5bd9f318006e733f4078e0f4c97
//	(open-telemetry/semantic-conventions-genai, branch main, HEAD as of 2026-08-27T06:10:11Z,
//	re-confirmed still HEAD-equivalent and still zero-release/zero-tag on 2026-08-31)
//	Source file:
//	https://raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/67dff024110be5bd9f318006e733f4078e0f4c97/model/gen-ai/registry.yaml
//
// This package MUST NOT be presented as "graded" or "stable telemetry." It is
// flagged-experimental (SchemaStatus below) precisely because the upstream names it emits
// can rename or vanish without a deprecation window (no release process governs them yet).
// Every gen_ai.* NAME here traces to a grep-able key in that pinned YAML -- never invented,
// never guessed from memory (E8). When gen_ai has no attribute for something N-AALP needs to
// record, this package uses a clearly namespaced naalp.* attribute instead of stretching the
// gen_ai.* namespace (also below).
const (
	// PinnedSemconvGenAISHA is the exact open-telemetry/semantic-conventions-genai commit
	// every gen_ai.* constant in this file was read from. Re-diff this file against
	// model/gen-ai/registry.yaml at a new SHA before bumping it (F6).
	PinnedSemconvGenAISHA = "67dff024110be5bd9f318006e733f4078e0f4c97"

	// SchemaStatus is the honest maturity label this package reports on every span/metric
	// it emits (as the naalp.otel.schema_status attribute) and is what any consumer of this
	// package MUST surface in status reporting -- never "stable", never "graded".
	SchemaStatus = "experimental-pinned-sha"
)

// gen_ai.* attribute keys, pinned to PinnedSemconvGenAISHA, model/gen-ai/registry.yaml.
// Every key's upstream `stability:` field at the pinned SHA is "development" (source lines
// noted per key). None are "experimental" or "stable" upstream; the OTel Go SDK carrying
// them is what is stable, not these names.
const (
	// AttrGenAIOperationName: registry.yaml key "gen_ai.operation.name" (source line 587),
	// a CLOSED enum. See OpExecuteTool / OpInvokeAgent below for the two enum members this
	// package emits; N-AALP surfaces with no honest member in the enum do not set this key.
	AttrGenAIOperationName = "gen_ai.operation.name"

	// AttrGenAIProviderName: registry.yaml key "gen_ai.provider.name" (source line 3), a
	// CLOSED enum of named GenAI backends (openai, anthropic, ...). N-AALP itself names no
	// provider -- this key is set ONLY when a caller explicitly supplies Outcome.ProviderName
	// (e.g. it is bridging to a named external GenAI backend); never invented.
	AttrGenAIProviderName = "gen_ai.provider.name"

	// AttrGenAIAgentID: registry.yaml key "gen_ai.agent.id" (source line 433). Mapped to the
	// N-AALP object's cryptographic signer id (identity.SignerID output) -- the real acting
	// identity, not a synthesized value.
	AttrGenAIAgentID = "gen_ai.agent.id"

	// AttrGenAIAgentName: registry.yaml key "gen_ai.agent.name" (source line 445). Set only
	// when a caller supplies a human-readable agent name; N-AALP carries no such field
	// natively.
	AttrGenAIAgentName = "gen_ai.agent.name"

	// AttrGenAIToolName: registry.yaml key "gen_ai.tool.name" (source line 460). Set only
	// when a caller supplies the carried tool's name (e.g. from the bridged MCP/A2A payload);
	// N-AALP's Bridge/Carriage kind does not itself name the tool.
	AttrGenAIToolName = "gen_ai.tool.name"

	// AttrGenAIToolCallID: registry.yaml key "gen_ai.tool.call.id" (source line 465). Set to
	// the N-AALP object's own content-id (hex) when the operation maps to execute_tool -- the
	// object's content-id already is a unique, verifiable identifier for that call.
	AttrGenAIToolCallID = "gen_ai.tool.call.id"
)

// OpExecuteTool / OpInvokeAgent are the two gen_ai.operation.name closed-enum members this
// package emits. Both are members of the enum at registry.yaml lines 587-670 (pinned SHA):
// "execute_tool" (id: execute_tool, line ~622) and "invoke_agent" (id: invoke_agent, line
// ~617). The enum has other members (chat, embeddings, retrieval, plan, ...) this package
// does not use, because no N-AALP channel honestly corresponds to them (see mapOperation in
// span.go) -- emitting one of those for an unrelated N-AALP surface would be the invented-
// name failure this file exists to prevent.
const (
	OpExecuteTool = "execute_tool"
	OpInvokeAgent = "invoke_agent"
)

// error.type is a STABLE (not gen_ai, not experimental) attribute from the main, tagged
// open-telemetry/semantic-conventions repository: model/error/registry.yaml, id
// "registry.error", attribute "error.type", stability: stable, confirmed present and
// stable at tag v1.44.0 (published 2026-08-04) this session. It is General-Attributes,
// not part of the pre-release gen_ai schema, so it carries no experimental caveat.
const AttrErrorType = "error.type"

// naalp.* attributes: N-AALP-specific fields gen_ai has no member for. Namespaced under
// naalp.* rather than stretched into gen_ai.* (the discipline this whole file exists to
// enforce: an attribute absent from the pinned upstream registry never gets a gen_ai.* name).
const (
	AttrNaalpChannelID     = "naalp.channel.id"
	AttrNaalpChannelName   = "naalp.channel.name"
	AttrNaalpKindID        = "naalp.kind.id"
	AttrNaalpKindName      = "naalp.kind.name"
	AttrNaalpEffect        = "naalp.effect"
	AttrNaalpSignerID      = "naalp.signer_id"
	AttrNaalpContentID     = "naalp.content_id"
	AttrNaalpVerified      = "naalp.verified"
	AttrNaalpApprovalReq   = "naalp.approval.required"
	AttrNaalpApprovalGrant = "naalp.approval.granted"
	AttrNaalpSchemaStatus  = "naalp.otel.schema_status"
	AttrNaalpSchemaSHA     = "naalp.otel.genai_schema_sha"
)
