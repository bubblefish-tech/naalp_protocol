# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
K5 -- the N-AALP Governance Kit's offline, framework-agnostic chain verifier and replay tool
(the N-AALP Governance Kit design).

Given a recorded chain of MIXED-KIND signed N-AALP objects -- tool calls, results, events, or any
other (channel, kind) surface, as emitted by ANY adapter (K1 ADK, K2 A2A, K3 MCP, or one not yet
written) into a length-prefixed session log (the same append-only framing K1's and K3's
`ChainRecorder` already write, see `read_log` below) -- this module:

  1. VERIFIES the whole chain OFFLINE (no network, no live framework dependency): every object's
     signature through the real `naalp.ez.verify` (never re-implemented here), every `causes`
     link resolving to the correct, EARLIER-in-the-log prior content id, fail-closed on any bad
     signature / broken causal link / missing referent -- each failure a distinct, named
     exception `.kind` (K5-1, K5-2). A chain with ANY defect is rejected WHOLE: `verify_chain`
     either returns a complete, checked `VerifiedChain` or raises; there is no partial-accept
     path.
  2. REPLAYS the chain -- re-derives the CAUSAL order of the governed actions (a topological sort
     over the `causes[]` DAG the objects themselves carry, not merely the log's append order) so
     an offline auditor can re-inspect what happened, in the order it causally happened, after
     the fact (K5-2).
  3. Runs identically regardless of which adapter produced the log (K5-3): this module reads only
     object KINDS + chain links via the real Part-1 core (`naalp.envelope`/`naalp.ez`) and never
     imports or references any framework SDK (no ADK, no A2A, no MCP) -- a chain produced by K1's
     `ChainRecorder`, K3's `ChainRecorder`, or hand-assembled bytes verifies identically.

This module adds NO cryptography and NO CBOR encoding of its own beyond what `sign_verification_
receipt` (below) needs to emit its OWN signed output through the real core -- every byte-checking
step is a direct call into `naalp.ez.verify` / `naalp.cose.parse_sign1_raw`
/ `naalp.envelope._parse_protected` (the SAME internal protected-header parse `naalp.ez.verify`
itself performs first, reused here -- never a second header parser -- purely to select which
verifying key to try in a multi-signer chain; the claimed signer id this peek reads is UNTRUSTED
and decides only which key to attempt, never whether the object is accepted -- `ez.verify`
afterward re-derives and cryptographically checks everything from the raw bytes, so a forged
claim fails as an ordinary bad signature, not as a bypassed check).

MIXED-KIND, KIND-AGNOSTIC BY DESIGN: unlike K0 (`naalp_kit.binding.verify_action`), which assumes
every body follows K0's own single-opaque-bstr-field shape (K1/K3's Bridge/Carriage capture),
`VerifiedLink.body` here is kept as the raw decoded `naalp.cbor` Value for WHATEVER (channel,
kind) the object actually declares -- Governance/Approval, Audit/Receipt, Bridge/Carriage, or any
other of the twenty registered channels can all appear in the SAME session log. A caller who
knows a given link came from a K0-shaped adapter can still recover its opaque payload via
`k0_payload(link)` (a thin, optional convenience over `naalp_kit.binding._extract_payload`); K5
itself never assumes that shape.
"""
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp_kit/naalp imports)

from naalp_kit import binding
from naalp import cbor, cose, envelope, ez
from naalp.cbor import U, B, A, M


# --- named, fail-closed error taxonomy (design.md sec.5's kit-wide taxonomy, K5's subset) ------

class ChainVerifyError(ValueError):
    """Base for every K5 error; `.kind` is the stable, distinct reason name (design.md sec.5).
    `.index` is the zero-based position of the offending record in the log (None when the defect
    is about the log's framing as a whole, before any record boundary is known)."""

    kind = "E_CHAIN_VERIFY"

    def __init__(self, msg, index=None, cause=None):
        super().__init__(msg)
        self.index = index
        self.cause = cause


class LogMalformed(ChainVerifyError):
    """The outer length-prefixed log framing itself is corrupt -- truncated mid length-prefix or
    mid-record. Distinct from any single record's content being invalid (SignatureInvalid,
    below): this is a defect in how the records were FRAMED, not in what any one of them says."""

    kind = "E_LOG_MALFORMED"


class SignatureInvalid(ChainVerifyError):
    """A record fails real cryptographic/structural verification through `naalp.ez.verify` --
    bad signature, tampered body, content-id mismatch, unregistered (channel, kind), or the bytes
    do not even parse as a tagged COSE_Sign1 N-AALP object at all. `.cause` carries the original
    core exception (an `envelope.EnvelopeError` with its own `.kind`, or a `naalp.cbor` decode
    error) UNWRAPPED in spirit -- never re-derived, always the real core's own verdict."""

    kind = "E_VERIFY"


class UnresolvedSigner(ChainVerifyError):
    """A record's claimed signer id has no verifying public key registered with the caller's
    resolver (see `verify_chain`'s `resolve_pubkey` parameter). Distinct from SignatureInvalid:
    this chain was never EVEN ATTEMPTED cryptographically -- the offline verifier simply has no
    key to check it against, and per this module's fail-closed discipline that is refused, never
    silently skipped or accepted on faith."""

    kind = "E_UNRESOLVED_SIGNER"


class BrokenReferent(ChainVerifyError):
    """A record's `causes[]` names a content id that is not present ANYWHERE in this chain -- a
    missing by-reference payload (design.md sec.7's "removed by-reference payload -> unverifiable,
    never valid"). K5 never treats an unresolvable causal reference as merely informational."""

    kind = "E_REFERENT"


class ChainOrderBroken(ChainVerifyError):
    """A causal link is present and its referent exists, but the chain's own claimed causal order
    disagrees with the log: the named cause appears AT OR AFTER its dependent in the log (an
    out-of-order / reordered / dropped link), two records claim the SAME content id (a forged or
    replayed duplicate), or the causes[] graph contains a cycle. All three are "the causal
    structure of this chain cannot be trusted," so they share one reason name; `.index` and the
    message distinguish which."""

    kind = "E_CHAIN"


# --- read_log: the append-only, length-prefixed framing K1's/K3's ChainRecorder already write --

def read_log(source: Union[bytes, bytearray, "object"]) -> List[bytes]:
    """Split a recorded session log back into its individual signed-object records. Accepts
    either raw bytes/bytearray (the whole log already read into memory) or any object exposing
    `.read(n)` (a real file/stream) -- SAME 4-byte-big-endian-length-prefix framing as
    `naalp_adk_plugin.adk_plugin.ChainRecorder` / `naalp_mcp_hook.mcp_hook.ChainRecorder` write
    (kept as an independent read-only implementation here, matching every other ecosystem
    package's convention of not cross-importing between packages).

    Fail-closed on truncation (LogMalformed, E_LOG_MALFORMED) -- a partially-written or corrupted
    log is refused whole rather than silently returning the records that DID parse."""
    if isinstance(source, (bytes, bytearray)):
        import io
        stream = io.BytesIO(bytes(source))
    else:
        stream = source
    records: List[bytes] = []
    index = 0
    while True:
        header = stream.read(4)
        if not header:
            break
        if len(header) != 4:
            raise LogMalformed(
                "log truncated mid length-prefix at record %d (%d header bytes, need 4)"
                % (index, len(header)), index=index)
        (n,) = struct.unpack(">I", header)
        payload = stream.read(n)
        if len(payload) != n:
            raise LogMalformed(
                "log truncated mid-record at record %d (%d payload bytes, need %d)"
                % (index, len(payload), n), index=index)
        records.append(bytes(payload))
        index += 1
    return records


# --- per-record verification -------------------------------------------------------------------

# The pubkey resolver: a single raw pubkey (bytes -- one signer for the whole chain, the common
# K1/K3 single-adapter-session case), a signer-id -> pubkey mapping, or a signer-id -> Optional
# [pubkey] callable (multi-signer chains, e.g. a K2 A2A boundary crossing where each side signs
# with its own key). NEVER resolved from anything the chain itself carries about its own signer
# (F3, matching ecosystem/naalp-bundle's TrustAnchor discipline) -- always the CALLER's own,
# out-of-band key material.
PubkeyResolver = Union[bytes, bytearray, Mapping[bytes, bytes], Callable[[bytes], Optional[bytes]]]


def _resolve_pubkey(resolver: PubkeyResolver, claimed_signer: bytes) -> Optional[bytes]:
    if hasattr(resolver, "get") and not isinstance(resolver, (bytes, bytearray)):
        return resolver.get(claimed_signer)
    if callable(resolver):
        return resolver(claimed_signer)
    raise TypeError(
        "resolve_pubkey must be bytes, a signer-id->pubkey mapping, or a "
        "signer-id->Optional[pubkey] callable, got %r" % (type(resolver),))


@dataclass(frozen=True)
class VerifiedLink:
    """One record's checked, trusted fields, recovered from a verified N-AALP object -- the SAME
    fields `naalp_kit.binding.VerifiedAction` exposes, plus `index` (this record's position in
    the raw log) and `raw` (the exact signed bytes, so a caller can re-derive anything K5 itself
    did not bother to surface). `body` is the raw decoded `naalp.cbor` Value for whatever (channel,
    kind) this object declares -- see the module docstring's "mixed-kind, kind-agnostic" note."""

    index: int
    content_id: bytes
    channel: int
    kind: int
    effect: int
    signer: bytes
    created: int
    body: object
    causes: Tuple[bytes, ...]
    raw: bytes


def _verify_one(index: int, raw: bytes, resolve_pubkey: PubkeyResolver, profile: int) -> VerifiedLink:
    if isinstance(resolve_pubkey, (bytes, bytearray)):
        pubkey = bytes(resolve_pubkey)
    else:
        try:
            prot, _payload, _sig = cose.parse_sign1_raw(bytes(raw))
            _alg, claimed_signer, _profile, _version = envelope._parse_protected(prot)
        except Exception as e:  # noqa: BLE001 -- ANY parse failure here means "does not verify"
            raise SignatureInvalid(
                "record %d does not parse as a signed N-AALP object: %r" % (index, e),
                index=index, cause=e) from e
        pubkey = _resolve_pubkey(resolve_pubkey, claimed_signer)
        if pubkey is None:
            raise UnresolvedSigner(
                "record %d: no verifying key registered for signer id %r"
                % (index, claimed_signer), index=index)
    try:
        obj = ez.verify(pubkey, bytes(raw), profile=profile)
    except Exception as e:  # noqa: BLE001 -- the real core's own verdict, wrapped, never re-derived
        raise SignatureInvalid(
            "record %d failed verification: %r" % (index, e), index=index, cause=e) from e
    return VerifiedLink(
        index=index, content_id=obj.id, channel=obj.channel, kind=obj.kind, effect=obj.effect,
        signer=obj.signer, created=obj.created, body=obj.body, causes=tuple(obj.causes),
        raw=bytes(raw),
    )


# --- whole-chain verify: causal-link + duplicate-content-id checks (K5-1, K5-2) -----------------

@dataclass(frozen=True)
class VerifiedChain:
    """The result of a successful `verify_chain`: every record checked, in ORIGINAL log/append
    order (`links`), plus the causally-reconstructed REPLAY order as indices into `links`
    (`replay_order`) -- K5-2's "reconstructs causal order"."""

    links: Tuple[VerifiedLink, ...]
    replay_order: Tuple[int, ...]


def verify_chain(
    records: Sequence[bytes], resolve_pubkey: PubkeyResolver, profile: int = cose.PROFILE_PUBLIC,
) -> VerifiedChain:
    """The whole K5 job: verify every record, then check every causal link, then reconstruct
    replay order. FAIL-CLOSED WHOLE -- the first defect found (in record order, then in causal-
    link-check order) raises immediately with its distinct named reason; there is no partial
    `VerifiedChain` returned on any failure path."""
    links: List[VerifiedLink] = []
    seen_at: Dict[bytes, int] = {}
    for index, raw in enumerate(records):
        link = _verify_one(index, raw, resolve_pubkey, profile)
        if link.content_id in seen_at:
            raise ChainOrderBroken(
                "record %d duplicates the content id of record %d (%s) -- a forged or replayed "
                "chain entry" % (index, seen_at[link.content_id], link.content_id.hex()),
                index=index)
        seen_at[link.content_id] = index
        links.append(link)

    # Every causal reference must name an EARLIER record already present in this same chain
    # (design.md sec.7: "removed by-reference payload -> unverifiable, never valid"; "reordered/
    # dropped chain links flagged").
    for link in links:
        for cause in link.causes:
            referent_index = seen_at.get(cause)
            if referent_index is None:
                raise BrokenReferent(
                    "record %d (content id %s) causes[] names %s, which is not present anywhere "
                    "in this chain" % (link.index, link.content_id.hex(), cause.hex()),
                    index=link.index)
            if referent_index >= link.index:
                raise ChainOrderBroken(
                    "record %d (content id %s) causes[] names record %d, which appears at or "
                    "after it in the log -- an out-of-order / reordered / dropped causal link"
                    % (link.index, link.content_id.hex(), referent_index), index=link.index)

    replay_order = _topological_order(links, seen_at)
    return VerifiedChain(links=tuple(links), replay_order=replay_order)


def _topological_order(links: List[VerifiedLink], cid_to_index: Dict[bytes, int]) -> Tuple[int, ...]:
    """Kahn's algorithm over the `causes[]` DAG, deterministic tie-break by (created, content_id)
    so replay order is reproducible even with multiple roots or parallel/merge branches -- a
    mixed-kind session need not be one linear chain. A cycle here is unreachable given
    `verify_chain`'s own out-of-order check above (which already forbids a cause pointing at or
    after its own index -- exactly what a cycle among index-ordered records would require); kept
    as a defensive, honestly-reported failure rather than an infinite loop or a silent partial
    order if that invariant is ever relaxed."""
    n = len(links)
    children: Dict[int, List[int]] = {i: [] for i in range(n)}
    indegree = [0] * n
    for link in links:
        for cause in link.causes:
            parent = cid_to_index[cause]
            children[parent].append(link.index)
            indegree[link.index] += 1
    ready = [i for i in range(n) if indegree[i] == 0]
    order: List[int] = []
    while ready:
        ready.sort(key=lambda i: (links[i].created, links[i].content_id))
        i = ready.pop(0)
        order.append(i)
        for child in children[i]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(order) != n:
        raise ChainOrderBroken("the causal graph contains a cycle -- chain rejected whole")
    return tuple(order)


def replay(chain: VerifiedChain) -> Tuple[VerifiedLink, ...]:
    """K5-2's replay: the checked links, reordered into the causal sequence the objects
    themselves claim (never the raw log's append order, though for a single strictly-chained
    session the two coincide)."""
    return tuple(chain.links[i] for i in chain.replay_order)


def verify_and_replay(
    records: Sequence[bytes], resolve_pubkey: PubkeyResolver, profile: int = cose.PROFILE_PUBLIC,
) -> Tuple[VerifiedLink, ...]:
    """Convenience: verify the whole chain, then return it already in replay (causal) order."""
    return replay(verify_chain(records, resolve_pubkey, profile=profile))


def k0_payload(link: VerifiedLink) -> bytes:
    """Optional convenience for a link the caller KNOWS came from a K0-shaped adapter (K1/K3's
    Bridge/Carriage capture, or any other kind that happens to use K0's single-opaque-bstr-field
    body shape): recovers the opaque payload octets via K0's OWN extractor
    (`naalp_kit.binding._extract_payload`) rather than a second decoder. Raises K0's
    `binding.MalformedBody` for a link whose body does NOT follow that shape -- K5 never guesses."""
    return binding._extract_payload(link.body)


# --- K5's own signed output: a verification receipt (design.md's "can itself emit a signed ------
# --- verification result") -----------------------------------------------------------------------

VERIFICATION_CHANNEL = 0x000B  # Audit (naalp.channels.TABLE[0x000B])
VERIFICATION_KIND = 0          # Receipt -- fixed effect NonIdempotentWrite, per the real registry


def sign_verification_receipt(
    signer: "ez.Signer", chain: VerifiedChain, causes: Sequence[bytes] = (),
) -> bytes:
    """Emit K5's own signed verification result: an Audit/Receipt object (the real registry entry
    naalp.channels.TABLE[0x000B][0]) recording that THIS run verified and replayed `chain`.
    Non-circularly bound to what was actually checked -- never a caller-suppliable summary: the
    digest is `naalp.cbor.content_id` (S-3, the SAME 50-byte multihash primitive every content id
    in this module already comes from, never a second hash function) over the REPLAY-ORDERED
    sequence of the chain's own content ids, recomputed from `chain` every call, so the receipt
    cannot be made to describe a chain other than the one this function actually walked."""
    ordered_ids = [link.content_id for link in replay(chain)]
    digest = cbor.content_id(A([B(cid) for cid in ordered_ids]))
    fields = [
        (U(1), U(len(chain.links))),  # number of links verified
        (U(2), B(digest)),            # content id over the replay-ordered content-id sequence
    ]
    if ordered_ids:
        fields.append((U(3), B(ordered_ids[0])))   # first replayed content id
        fields.append((U(4), B(ordered_ids[-1])))  # last replayed content id
    body = M(fields)
    return signer.sign(VERIFICATION_CHANNEL, VERIFICATION_KIND, body, causes=list(causes))


__all__ = [
    "ChainVerifyError", "LogMalformed", "SignatureInvalid", "UnresolvedSigner",
    "BrokenReferent", "ChainOrderBroken",
    "read_log", "PubkeyResolver", "VerifiedLink", "VerifiedChain",
    "verify_chain", "replay", "verify_and_replay", "k0_payload",
    "VERIFICATION_CHANNEL", "VERIFICATION_KIND", "sign_verification_receipt",
]
