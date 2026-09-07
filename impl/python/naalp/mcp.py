# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""NAALP-MCP binding profile for the Python SDK (design.md §19; Companion-Spec Requirement 6.1) --
a draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
(envelope §2) on the Bridge channel, and it REUSES the closed effect lattice (policy), the approval +
single-use consume ledger (approval), and the T1 content-id framing (§2.3) unchanged.

What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that a
tool's annotations are unenforced hints a malicious server can lie about -- "clients MUST consider
tool annotations to be untrusted unless they come from trusted servers". This profile turns that
anonymous, untrusted hint into a SIGNED effect claim by a named key:

  - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are carried
    OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization identity --
    the wrapping signer is the authority (R-14.6).
  - PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice
    (read_only < idempotent_write < non_idempotent_write < destructive). Because the spine carries no
    CBOR boolean (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT hint takes
    its MCP default. destructiveHint's default of TRUE is why an un-annotated write maps to destructive
    -- the fail-closed rule.
  - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
    DECLARED effect, under its ML-DSA signature. A verifier independently recomputes the
    annotation-derived effect and enforces the MORE SEVERE of the two (resolve_enforced_effect -- the
    good-regulator attenuator: a disagreeing input collapses UP, never down). A signer that DECLARES
    BELOW its own carried annotations is rejected fail-closed (EffectUnderDeclared); an annotation set
    mapping outside the lattice is rejected (MalformedAnnotation), never defaulted to benign.
  - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
    (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
    invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.

Every check is fail-closed (§15). Ported from impl/go/mcp; the byte surface (annotation encoding, the
mapping table, tool-call bodies/content-ids, call bindings, the resolution verdicts) is graded against
the shared vectors/mcp/cases.json; the signed governance path (verify_tool_call / authorize_call) uses
real deterministic ML-DSA-65 and is demonstrated in isolation only (the corpus carries no signed
vector).
"""
from . import approval, cbor, channels, cose, envelope, policy
from .cbor import U, B, M

# Channel binding, the tier-1 kind code, and the tier for the MCP wrapper (design §6.1). McpToolCall
# is kind 1 on the Bridge channel -- a named escalation over the frozen baseline Carriage kind (0),
# which stays untouched (R-15A.2).
CHANNEL_BRIDGE = 0x000D      # Bridge channel (foreign carriage lives here)
KIND_MCP_TOOL_CALL = 1       # tier-1 kind code (baseline Carriage is kind 0)
TIER = 1                     # a named escalation adding the governed MCP wrapper (R-15A.2)

# Annotation CBOR keys inside a naalp-mcp-annotations map. Each value is the uint 1 (true) / 0 (false)
# -- the spine carries no CBOR boolean (design §3.1).
KEY_READ_ONLY = 1            # MCP readOnlyHint
KEY_DESTRUCTIVE = 2          # MCP destructiveHint
KEY_IDEMPOTENT = 3          # MCP idempotentHint
KEY_OPEN_WORLD = 4          # MCP openWorldHint (ADVISORY -- not an effect determinant)

# MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
# write maps to destructive -- the fail-closed default.
DEFAULT_READ_ONLY = False
DEFAULT_DESTRUCTIVE = True
DEFAULT_IDEMPOTENT = False


class McpError(ValueError):
    """A named, fail-closed MCP-profile error; .kind is the stable error kind (mirroring the Go/Rust
    kinds MalformedAnnotation, EffectUnderDeclared, EffectOutsideLattice, ToolCallMalformed, and the
    reused §7 ApprovalRequired)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def content_id(b):
    """T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets),
    identical to the spine framing over raw bytes."""
    return cbor.content_id(bytes(b))


# ---- the transcribed MCP annotation set (naalp-mcp-annotations) -------------------------------

class Annotations:
    """The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL:
    None means the hint was absent (the MCP default applies in the mapping), so an absent hint and a
    present false are distinct on the wire though they may resolve to the same effect. open_world is
    carried for accountability but never enters the effect mapping (design §5)."""

    __slots__ = ("read_only", "destructive", "idempotent", "open_world")

    def __init__(self, read_only=None, destructive=None, idempotent=None, open_world=None):
        self.read_only = read_only     # MCP readOnlyHint
        self.destructive = destructive  # MCP destructiveHint
        self.idempotent = idempotent   # MCP idempotentHint
        self.open_world = open_world   # MCP openWorldHint (advisory only)

    def to_value(self):
        """Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1."""
        pairs = []
        if self.read_only is not None:
            pairs.append((U(KEY_READ_ONLY), U(1 if self.read_only else 0)))
        if self.destructive is not None:
            pairs.append((U(KEY_DESTRUCTIVE), U(1 if self.destructive else 0)))
        if self.idempotent is not None:
            pairs.append((U(KEY_IDEMPOTENT), U(1 if self.idempotent else 0)))
        if self.open_world is not None:
            pairs.append((U(KEY_OPEN_WORLD), U(1 if self.open_world else 0)))
        return M(pairs)

    def encode(self):
        """The deterministic-CBOR bytes of the annotation map (keys sorted by encode)."""
        return cbor.encode(self.to_value())


def annotations_from_value(v):
    """Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a
    non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a
    duplicate key, or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map
    outside the closed lattice, so it is rejected, never defaulted to benign (AC-6.1.2)."""
    if not isinstance(v, M):
        raise McpError("MalformedAnnotation", "annotation set is not a map")
    a = Annotations()
    seen = set()
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise McpError("MalformedAnnotation", "non-uint annotation key")
        if not isinstance(val, U) or val.v > 1:      # a hint value outside {0,1} maps outside the lattice
            raise McpError("MalformedAnnotation", "annotation hint value is outside {0,1}")
        if k.v in seen:
            raise McpError("MalformedAnnotation", "duplicate annotation key")
        seen.add(k.v)
        flag = val.v == 1
        if k.v == KEY_READ_ONLY:
            a.read_only = flag
        elif k.v == KEY_DESTRUCTIVE:
            a.destructive = flag
        elif k.v == KEY_IDEMPOTENT:
            a.idempotent = flag
        elif k.v == KEY_OPEN_WORLD:
            a.open_world = flag
        else:
            raise McpError("MalformedAnnotation", "annotation key outside the closed mapping")
    return a


# ---- the published annotation -> effect mapping table (design §6.1) ---------------------------

def map_annotations_to_effect(a):
    """Map a tool's transcribed annotations to the closed four-effect lattice by the published table,
    applying the MCP default for each absent hint:

        readOnlyHint true                                  -> read_only
        readOnlyHint false, destructiveHint true           -> destructive
        readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
        readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write

    An absent readOnlyHint defaults false (a write); an absent destructiveHint defaults TRUE
    (destructive) -- so a tool with no annotations maps to destructive, the fail-closed collapse to
    the most-severe. openWorldHint is never consulted (design §5)."""
    ro = DEFAULT_READ_ONLY if a.read_only is None else a.read_only
    de = DEFAULT_DESTRUCTIVE if a.destructive is None else a.destructive
    idem = DEFAULT_IDEMPOTENT if a.idempotent is None else a.idempotent
    if ro:
        return policy.READ_ONLY
    if de:
        return policy.DESTRUCTIVE
    if idem:
        return policy.IDEMPOTENT_WRITE
    return policy.NON_IDEMPOTENT_WRITE


def resolve_enforced_effect(annotation_mapped, declared):
    """The more-severe resolution (the good-regulator attenuator). Given the annotation-derived
    effect and the wrapping signer's declared effect, return (enforced, mismatch) -- the enforced
    effect being the MORE SEVERE (equal to `declared` on success), and mismatch whether the two
    disagreed (attributable to the wrapping signer). A declared value outside the closed lattice is
    EffectOutsideLattice; a declared value BELOW the annotation-derived effect is EffectUnderDeclared
    (a wrapper's declared effect can never sit under its own carried annotations' mapping)."""
    if declared > policy.DESTRUCTIVE:
        raise McpError("EffectOutsideLattice", "declared effect outside the closed four-effect lattice")
    if declared < annotation_mapped:
        raise McpError("EffectUnderDeclared", "declared effect is below the annotation-mapped effect")
    return declared, declared != annotation_mapped


# ---- the wrapper body (naalp-mcp-tool-call) ---------------------------------------------------

class ToolCall:
    """The wrapper body (envelope field 10). `tool` and `args` are the foreign MCP bytes, carried
    octet-for-octet (carriage, not adoption); `annotations` is the wrapping signer's transcription of
    the tool's hints, on which the mapping operates. The wrapper's OWN effect is envelope field 7, not
    a body field."""

    __slots__ = ("tool", "args", "annotations")

    def __init__(self, tool, args, annotations):
        self.tool = bytes(tool)
        self.args = bytes(args)
        self.annotations = annotations

    def to_map(self):
        return M([
            (U(1), B(self.tool)),
            (U(2), B(self.args)),
            (U(3), self.annotations.to_value()),
        ])

    def bytes(self):
        """Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}."""
        return cbor.encode(self.to_map())

    def content_id(self):
        """The tool-call body's content id (T1 framing)."""
        return content_id(self.bytes())

    def call_binding(self):
        """The (tool_id, args_id) binding whose content id an approval binds for this call."""
        return new_call_binding(self.tool, self.args)

    def envelope_object(self, signer, created, profile, declared, causes):
        """Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel,
        kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as field
        10, and `causes`. The caller signs it; the signer BECOMES accountable for the declared effect
        and the annotation transcription. A declared effect outside the closed lattice is rejected
        fail-closed. Under-declaration is NOT rejected here -- it is a signed, attributable claim whose
        inconsistency verify_tool_call surfaces as EffectUnderDeclared at the enforcement point."""
        if declared > policy.DESTRUCTIVE:
            raise McpError("EffectOutsideLattice", "declared effect outside the closed lattice")
        return envelope.Object(
            kind=KIND_MCP_TOOL_CALL, channel=CHANNEL_BRIDGE, tier=TIER,
            signer=bytes(signer), created=created, effect=declared,
            causes=list(causes), profile=profile, body=self.to_map())


def sign_tool_call(obj, alg, seed):
    """Sign an McpToolCall envelope object with a real deterministic ML-DSA key; the signer becomes
    accountable for the declared effect and the carried annotations."""
    return envelope.sign(obj, alg, seed)


def tool_call_from_body(v):
    """Parse an envelope object body (a decoded cbor Value) into a ToolCall. A body that is not
    exactly {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed;
    a malformed annotation set is MalformedAnnotation. Fail-closed."""
    if not isinstance(v, M):
        raise McpError("ToolCallMalformed", "tool-call body is not a map")
    tool = args = None
    ann = None
    have_ann = False
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise McpError("ToolCallMalformed", "non-uint tool-call body key")
        if k.v == 1:
            if not isinstance(val, B):
                raise McpError("ToolCallMalformed", "tool is not a bstr")
            tool = val.v
        elif k.v == 2:
            if not isinstance(val, B):
                raise McpError("ToolCallMalformed", "args is not a bstr")
            args = val.v
        elif k.v == 3:
            ann = annotations_from_value(val)   # raises MalformedAnnotation
            have_ann = True
        else:
            raise McpError("ToolCallMalformed", "unknown tool-call body field %d" % k.v)
    if tool is None or args is None or not have_ann:
        raise McpError("ToolCallMalformed", "tool-call body missing a mandatory field")
    return ToolCall(tool, args, ann)


# ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

class CallBinding:
    """Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content
    id. An approval binds the content id of THIS binding, so a changed tool description (new tool_id)
    OR changed arguments (new args_id) yields a new call content id and invalidates a prior approval
    bound to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3)."""

    __slots__ = ("tool_id", "args_id")

    def __init__(self, tool_id, args_id):
        self.tool_id = bytes(tool_id)
        self.args_id = bytes(args_id)

    def to_map(self):
        return M([(U(1), B(self.tool_id)), (U(2), B(self.args_id))])

    def bytes(self):
        """Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}."""
        return cbor.encode(self.to_map())

    def content_id(self):
        """The call content id an approval binds."""
        return content_id(self.bytes())


def new_call_binding(tool, args):
    """Compute the binding from the raw tool and args bytes."""
    return CallBinding(content_id(tool), content_id(args))


# ---- kind validation (composes with the frozen baseline) --------------------------------------

def kind_validator(channel, kind):
    """Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall)."""
    return channel == CHANNEL_BRIDGE and kind == KIND_MCP_TOOL_CALL


def _baseline_kind_validator(channel, kind):
    try:
        channels.lookup(channel, kind)
        return True
    except channels.UnknownKind:
        return False


def composed_kind_validator(channel, kind):
    """Accepts the frozen baseline kinds OR the tier-1 McpToolCall -- the validator an MCP-aware
    endpoint passes to envelope.verify. A baseline-only endpoint using the baseline validator alone
    correctly rejects an McpToolCall as UnknownKind (fail-closed)."""
    return _baseline_kind_validator(channel, kind) or kind_validator(channel, kind)


# ---- verified tool call -----------------------------------------------------------------------

class Resolved:
    """An MCP tool call that has passed envelope verification and effect resolution. It carries the
    enforced effect (the more-severe value C5 authorizes on), whether the annotation and declared
    effect disagreed (mismatch -- attributable to signer), and the parsed tool call."""

    __slots__ = ("content_id", "signer", "tool_call", "annotation_mapped", "declared", "enforced",
                 "mismatch")

    def __init__(self, content_id, signer, tool_call, annotation_mapped, declared, enforced, mismatch):
        self.content_id = bytes(content_id)
        self.signer = signer
        self.tool_call = tool_call
        self.annotation_mapped = annotation_mapped
        self.declared = declared
        self.enforced = enforced
        self.mismatch = mismatch


def verify_tool_call(profile, alg, pubkey, signed_obj):
    """Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the
    signed object with real crypto (envelope.verify against the composed validator -- content id,
    ranges, header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge McpToolCall;
    (3) parses the tool-call body (rejecting a malformed annotation set); (4) recomputes the
    annotation-derived effect from the CARRIED annotations, independent of the declared effect;
    (5) resolves the enforced effect to the MORE SEVERE, rejecting under-declaration. The enforced
    effect equals the declared envelope effect on success, so the object's field 7 is the correct C5
    authorization input. Any failure returns its named error and authorizes nothing (fail-closed)."""
    o = envelope.verify(profile, alg, pubkey, composed_kind_validator, signed_obj)
    if o.channel != CHANNEL_BRIDGE or o.kind != KIND_MCP_TOOL_CALL or o.tier != TIER:
        raise McpError("ToolCallMalformed", "not a tier-1 Bridge McpToolCall")
    tc = tool_call_from_body(o.body)
    mapped = map_annotations_to_effect(tc.annotations)
    declared = o.effect                          # envelope.verify already range-checked field 7 to 0..3
    enforced, mismatch = resolve_enforced_effect(mapped, declared)
    return Resolved(o.id, o.signer, tc, mapped, declared, enforced, mismatch)


# ---- the per-call approval gate (reuses §7 approval + consume ledger) --------------------------

def authorize_call(r, appr, approver_alg, approver_pubkey, appr_sig, by, now, ledger):
    """Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind
    the EXACT call binding content id (tool_id + args_id) -- so it satisfies neither a call with
    different arguments nor a call whose tool description changed (Requirement 6.1) -- its granted
    effect must cover the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it
    is consumed single-use by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror
    the spine: a non-matching or under-granting approval denies ApprovalRequired with no ledger append;
    an already-spent approval denies AlreadyConsumed; the consume (the single state change) happens
    only when every check holds. Returns None on authorization."""
    call_cid = r.tool_call.call_binding().content_id()
    try:
        approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, call_cid, now)
    except approval.ApprovalError as e:
        # A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
        if e.kind == "ApprovalMismatch":
            raise McpError("ApprovalRequired", "approval does not bind this exact call")
        raise
    if not policy.authorizes(appr.grant, r.enforced):
        raise McpError("ApprovalRequired", "the approval's granted effect does not cover the call")
    ledger.consume(appr.id(), by)                # AlreadyConsumed on replay (fail-closed, no double-spend)
    return None
