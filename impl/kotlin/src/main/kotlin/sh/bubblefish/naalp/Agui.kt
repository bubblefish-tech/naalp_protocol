// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

//
// C21 NAALP-AGUI UI-consent binding for the Kotlin SDK (design.md §24; R-AGUI-1..6).
//
// NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
// tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
// RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
// envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary signed
// N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction (§8.1)
// unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head carried
// in `prev` so editing or omitting an event breaks the next event's linkage — and the §7 Approval binding
// (object Approval) UNCHANGED.
//
//   - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event. `kind`
//     is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id of the
//     action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.
//
// The load-bearing properties, graded across implementations:
//
//   - A UI approval verifies ONLY against the EXACT action shown. verifyConsent walks the shown chain,
//     takes the action content id from the shown-and-approved event, and requires the action actually being
//     executed to hash to THAT content id (ActionSubstituted otherwise) AND the human approval to bind it
//     (the §7 approval, ApprovalMismatch otherwise). A substituted action has a different content id and is
//     rejected.
//   - A removed/omitted shown-event is detected with its POSITION. walkShown enforces contiguity and
//     returns UIChainBroken on a gap; detectHole reports the first-broken position.
//
// Every check is fail-closed (§15). Ported from impl/go/agui (cross-read against impl/python/naalp/agui.py);
// the byte surface (kind vocabulary, event bodies/heads/ids, action content ids, the shown-chain walk,
// hole position, rejections) is graded against vectors/agui/cases.json; the signed shown-chain and the
// consent binding use real deterministic ML-DSA-65 and are demonstrated in isolation (the corpus carries no
// signed vector).
//
object Agui {
    // The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis is
    // zero.
    const val HEAD_SIZE = 48

    // UI event kinds — the closed AG-UI tool-lifecycle set. A kind outside the set is rejected
    // (UnknownUIEventKind).
    const val KIND_SHOWN = 0L      // the action / tool call was shown (rendered) to the user
    const val KIND_ARGS_SHOWN = 1L // the arguments were shown to the user
    const val KIND_APPROVED = 2L   // the user approved the shown action
    const val KIND_REJECTED = 3L   // the user rejected the shown action

    private val KIND_NAMES: Map<Long, String> = mapOf(
        KIND_SHOWN to "shown", KIND_ARGS_SHOWN to "args-shown",
        KIND_APPROVED to "approved", KIND_REJECTED to "rejected",
    )

    // Whether code is one of the closed UI-event kinds.
    fun isKnownKind(code: Long): Boolean = KIND_NAMES.containsKey(code)

    // The kind name, or "unknown".
    fun kindName(code: Long): String = KIND_NAMES[code] ?: "unknown"

    // A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).
    fun genesis(): ByteArray = ByteArray(HEAD_SIZE)

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    // The exported T1 content id of arbitrary bytes — the content id of an ACTION, which a UI event names
    // in field 3 and a human approval binds. A relying party computes it over the exact action bytes it is
    // about to execute.
    fun contentId(b: ByteArray): ByteArray = Cbor.contentId(b)

    // ---- UIEvent: one receipt-chained shown tool-lifecycle event (design §24) ---------------------

    // One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event: prev is
    // the prior event's head (genesis for seq 0). action is the content id of the exact action bytes shown
    // to the user at this step.
    class UIEvent(session: ByteArray, val kind: Long, action: ByteArray, val seq: Long, prev: ByteArray) {
        val session: ByteArray = session.copyOf()
        val action: ByteArray = action.copyOf()
        val prev: ByteArray = prev.copyOf()

        // Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(session)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(kind)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(action)),
                    Cbor.Pair(Cbor.U(4), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(5), Cbor.B(prev)),
                )
            )
        )

        // The chain head after this event: SHA-384 of the event body (48 octets). Because the body carries
        // prev, editing any event breaks the next event's linkage.
        fun head(): ByteArray = sha384(bytes())

        // The event's T1 content id (50 octets).
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    // Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint key, a
    // mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed.
    fun parseUIEvent(b: ByteArray): UIEvent {
        val v = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("UIMalformed", "ui-event body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) throw NaalpException("UIMalformed", "ui-event body is not a map")
        var sess: ByteArray? = null
        var kind: Long? = null
        var action: ByteArray? = null
        var seq: Long? = null
        var prev: ByteArray? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("UIMalformed", "non-uint ui-event key")
            when (k.v) {
                1L -> { val x = p.v; if (x is Cbor.B) sess = x.v else throw NaalpException("UIMalformed", "session not a bstr") }
                2L -> { val x = p.v; if (x is Cbor.U) kind = x.v else throw NaalpException("UIMalformed", "kind not a uint") }
                3L -> { val x = p.v; if (x is Cbor.B) action = x.v else throw NaalpException("UIMalformed", "action not a bstr") }
                4L -> { val x = p.v; if (x is Cbor.U) seq = x.v else throw NaalpException("UIMalformed", "seq not a uint") }
                5L -> { val x = p.v; if (x is Cbor.B) prev = x.v else throw NaalpException("UIMalformed", "prev not a bstr") }
                else -> throw NaalpException("UIMalformed", "unknown ui-event field ${k.v}")
            }
        }
        if (sess == null || kind == null || action == null || seq == null || prev == null) {
            throw NaalpException("UIMalformed", "ui-event body missing a mandatory field")
        }
        return UIEvent(sess, kind, action, seq, prev)
    }

    // Produce the tagged COSE_Sign1 object over the event body (real deterministic ML-DSA).
    fun signUIEvent(e: UIEvent, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, aguiProtectedHeader(alg), e.bytes())

    // Verify the event's full signature under the profile, reconstruct it from the signed body bytes, and
    // validate the kind against the closed set (UnknownUIEventKind). A bad signature propagates BadSignature.
    // Fail-closed.
    fun verifyUIEvent(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): UIEvent {
        val payload = verifySign1(obj, profile, alg, pubkey)
        val e = parseUIEvent(payload)
        if (!isKnownKind(e.kind)) throw NaalpException("UnknownUIEventKind", "ui-event kind is outside the closed set")
        return e
    }

    // ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) -----------------

    // One step of a walked shown chain: the chain position, the event kind, the action content id shown, and
    // the chain head after it.
    class ShownEvent(val seq: Long, val kind: Long, action: ByteArray, head: ByteArray) {
        val action: ByteArray = action.copyOf()
        val head: ByteArray = head.copyOf()
    }

    // Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered shown
    // events. It requires every event to name the SAME session, seq i to equal its index, each kind to be in
    // the closed set, and prev to link to the previous event's head (genesis for seq 0). A gap, reorder,
    // omitted event, or a session change is UIChainBroken (fail-closed); an unknown kind is
    // UnknownUIEventKind.
    fun walkShown(events: List<UIEvent>): List<ShownEvent> {
        val out = ArrayList<ShownEvent>(events.size)
        var h = genesis()
        var session: ByteArray? = null
        for ((i, e) in events.withIndex()) {
            if (i == 0) {
                session = e.session
            } else if (!e.session.contentEquals(session)) {
                throw NaalpException("UIChainBroken", "a chain is for exactly one session")
            }
            if (!isKnownKind(e.kind)) throw NaalpException("UnknownUIEventKind", "ui-event kind is outside the closed set")
            if (e.seq != i.toLong() || !e.prev.contentEquals(h)) {
                throw NaalpException("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
            }
            h = e.head()
            out.add(ShownEvent(e.seq, e.kind, e.action, h))
        }
        return out
    }

    // Check a UI event chain offline against the UI authority's key. Each element is the tagged COSE_Sign1
    // object for one event; verify every signature under the profile (verifyUIEvent), then enforce the same
    // structural continuity as walkShown. A bad signature propagates BadSignature; a broken link, seq gap, or
    // session change is UIChainBroken. Detects any reorder, omission, or substitution of a shown event
    // (§8.1). Fail-closed.
    fun verifyShownChain(objs: List<ByteArray>, profile: Long, alg: Int, pubkey: ByteArray): List<UIEvent> {
        var h = genesis()
        var session: ByteArray? = null
        val out = ArrayList<UIEvent>(objs.size)
        for ((i, obj) in objs.withIndex()) {
            val e = verifyUIEvent(obj, profile, alg, pubkey)
            if (i == 0) {
                session = e.session
            } else if (!e.session.contentEquals(session)) {
                throw NaalpException("UIChainBroken", "a chain is for exactly one session")
            }
            if (e.seq != i.toLong() || !e.prev.contentEquals(h)) {
                throw NaalpException("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
            }
            h = e.head()
            out.add(e)
        }
        return out
    }

    // Report whether a presented (possibly gappy) event list breaks contiguity — a deleted/omitted
    // shown-event — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's seq
    // is not i or its prev does not link to the previous event's head. A contiguous list returns (0, false).
    fun detectHole(events: List<UIEvent>): kotlin.Pair<Int, Boolean> {
        var h = genesis()
        for ((i, e) in events.withIndex()) {
            if (e.seq != i.toLong() || !e.prev.contentEquals(h)) {
                return kotlin.Pair(i, true)
            }
            h = e.head()
        }
        return kotlin.Pair(0, false)
    }

    // ---- the UI consent binding (reuses the §7 Approval) ------------------------------------------

    // The content id of the action shown-and-approved in a walked chain, or null if no approved event is
    // present. It is the content id a valid consent binds; a chain with no approved event has no consent to
    // bind.
    fun approvedActionCid(shown: List<ShownEvent>): ByteArray? {
        for (ev in shown) {
            if (ev.kind == KIND_APPROVED) return ev.action.copyOf()
        }
        return null
    }

    // Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks the
    // shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content id from
    // the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7 approval binds
    // THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired / BadSignature); and (4)
    // requires the action actually being executed (actionBytes) to hash to the shown-and-approved content id
    // — a SUBSTITUTED action has a different content id and is rejected (ActionSubstituted). Every failure
    // throws its named error and authorizes nothing (fail-closed). On success the caller may execute exactly
    // actionBytes.
    fun verifyConsent(
        chain: List<UIEvent>,
        actionBytes: ByteArray,
        appr: Approval.ApprovalRecord,
        approverAlg: Int,
        approverPubkey: ByteArray,
        apprSig: ByteArray,
        now: Long,
    ) {
        val shown = walkShown(chain) // UIChainBroken / UnknownUIEventKind on a hole
        val shownCid = approvedActionCid(shown)
            ?: throw NaalpException("UINoConsent", "the shown chain carries no approved event")
        // The human approval must be a valid signature binding the shown-and-approved action content id.
        Approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, shownCid, now)
        // The action actually being executed MUST be the exact one shown and approved: a substitution has a
        // different content id and is rejected. This is the seam a lax UI profile would drop.
        if (!contentId(actionBytes).contentEquals(shownCid)) {
            throw NaalpException("ActionSubstituted", "the executed action is not the exact action shown+approved")
        }
    }

    // ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

    // The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits.
    private fun aguiProtectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    // Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
    // Mirrors the shared verify: alg registry, profile floor, key-alg match, signature. Fail-closed with a
    // named error.
    private fun verifySign1(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ByteArray {
        val parts = Cose.parseSign1Raw(obj) // [protected, payload, signature]
        val halg = algFromProtected(parts[0])
        val (level, known) = Cose.algLevel(halg)
        if (!known) throw NaalpException("UnknownAlg", "unregistered alg $halg")
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (halg != alg) throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        return parts[1]
    }

    private fun algFromProtected(prot: ByteArray): Int {
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) throw NaalpException("UIMalformed", "protected header is not a map")
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L) {
                val value = p.v
                if (value is Cbor.N) return value.v.toInt()
                if (value is Cbor.U) return value.v.toInt()
            }
        }
        throw NaalpException("UIMalformed", "protected header has no alg")
    }
}
