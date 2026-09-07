// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C21 NAALP-AGUI UI-consent binding for the C# SDK (design.md §24; R-AGUI-1..6), ported from
    /// impl/go/agui and cross-checked against impl/python/naalp/agui.py.
    ///
    /// <para>NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream
    /// (the AG-UI tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id,
    /// and RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO
    /// new envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an
    /// ordinary signed N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain
    /// construction (§8.1) unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic
    /// seq, the prior head carried in prev so editing or omitting an event breaks the next event's
    /// linkage — and the §7 approval binding (<see cref="Approval"/>) UNCHANGED.</para>
    ///
    /// <list type="bullet">
    /// <item>A UI approval verifies ONLY against the EXACT action shown. <see cref="VerifyConsent"/>
    /// walks the shown chain, takes the action content id from the shown-and-approved event, and
    /// requires the action actually being executed to hash to THAT content id (ActionSubstituted
    /// otherwise) AND the human approval to bind it (ApprovalMismatch otherwise).</item>
    /// <item>A removed/omitted shown-event is detected with its POSITION. <see cref="WalkShown"/>
    /// enforces contiguity and returns UIChainBroken on a gap; <see cref="DetectHole"/> reports the
    /// first-broken position.</item>
    /// </list>
    ///
    /// <para>Every check is fail-closed (§15). The byte surface (kind vocabulary, event bodies/heads/ids,
    /// action content ids, the shown-chain walk, hole position, rejections) is graded against
    /// vectors/agui/cases.json; the signed shown-chain and the consent binding use real deterministic
    /// ML-DSA-65 and are demonstrated in isolation (the corpus carries no signed vector).</para>
    /// </summary>
    public static class Agui
    {
        /// <summary>The width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.</summary>
        public const int HeadSize = 48;

        // UI event kinds — the closed AG-UI tool-lifecycle set. A kind outside the set is rejected.
        public const long KindShown = 0;     // the action / tool call was shown (rendered) to the user
        public const long KindArgsShown = 1; // the arguments were shown to the user
        public const long KindApproved = 2;  // the user approved the shown action
        public const long KindRejected = 3;  // the user rejected the shown action

        private static readonly Dictionary<long, string> KindNames = new Dictionary<long, string>
        {
            { KindShown, "shown" }, { KindArgsShown, "args-shown" },
            { KindApproved, "approved" }, { KindRejected, "rejected" },
        };

        /// <summary>Whether code is one of the closed UI-event kinds.</summary>
        public static bool IsKnownKind(long code) => KindNames.ContainsKey(code);

        /// <summary>The kind name, or "unknown".</summary>
        public static string KindName(long code) => KindNames.TryGetValue(code, out string? n) ? n : "unknown";

        /// <summary>A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).</summary>
        public static byte[] Genesis() => new byte[HeadSize];

        private static byte[] HeadOf(byte[] b) => SHA384.HashData(b);

        /// <summary>T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
        /// The content id of an ACTION, which a UI event names in field 3 and a human approval binds. A
        /// relying party computes it over the exact action bytes it is about to execute.</summary>
        public static byte[] ContentId(byte[] b) => Cbor.ContentId(b);

        // ---- UIEvent: one receipt-chained shown tool-lifecycle event (design §24) ------------------

        /// <summary>One shown tool-lifecycle event in a UI session's event stream. It chains onto the
        /// prior event: Prev is the prior event's Head (Genesis for seq 0). Action is the content id of
        /// the exact action bytes shown to the user at this step.</summary>
        public sealed class UIEvent
        {
            public readonly byte[] Session;
            public readonly long Kind;
            public readonly byte[] Action;
            public readonly long Seq;
            public readonly byte[] Prev;

            public UIEvent(byte[] session, long kind, byte[] action, long seq, byte[] prev)
            {
                Session = (byte[])session.Clone();
                Kind = kind;
                Action = (byte[])action.Clone();
                Seq = seq;
                Prev = (byte[])prev.Clone();
            }

            /// <summary>Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Session)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Kind)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(Action)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(Seq)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.B(Prev)),
                }));
            }

            /// <summary>The chain head after this event: SHA-384 of the event body (48 octets). Because
            /// the body carries Prev, editing any event breaks the next event's linkage.</summary>
            public byte[] Head() => HeadOf(Bytes());

            /// <summary>The event's T1 content-id (50 octets).</summary>
            public byte[] Id() => ContentId(Bytes());
        }

        /// <summary>Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a
        /// non-uint key, a mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed.</summary>
        public static UIEvent ParseUIEvent(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("UIMalformed", "ui-event body is not well-formed deterministic CBOR");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("UIMalformed", "ui-event body is not a map");
            }
            byte[]? sess = null, action = null, prev = null;
            long? kind = null, seq = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("UIMalformed", "non-uint ui-event key");
                }
                if (ku.V == 1 && p.Val is Cbor.B s) sess = s.V;
                else if (ku.V == 2 && p.Val is Cbor.U k) kind = k.V;
                else if (ku.V == 3 && p.Val is Cbor.B a) action = a.V;
                else if (ku.V == 4 && p.Val is Cbor.U sq) seq = sq.V;
                else if (ku.V == 5 && p.Val is Cbor.B pv) prev = pv.V;
                else throw new NaalpException("UIMalformed", "unknown or mistyped ui-event field");
            }
            if (sess == null || kind == null || action == null || seq == null || prev == null)
            {
                throw new NaalpException("UIMalformed", "ui-event body missing a mandatory field");
            }
            return new UIEvent(sess, kind.Value, action, seq.Value, prev);
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the event body (real deterministic ML-DSA).</summary>
        public static byte[] SignUIEvent(UIEvent e, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), e.Bytes());

        /// <summary>Verify the event's full signature under the profile, reconstruct it from the signed
        /// body bytes, and validate the kind against the closed set (UnknownUIEventKind). A bad signature
        /// propagates BadSignature. Fail-closed.</summary>
        public static UIEvent VerifyUIEvent(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifySign1(obj, profile, alg, pubkey);
            UIEvent e = ParseUIEvent(payload);
            if (!IsKnownKind(e.Kind))
            {
                throw new NaalpException("UnknownUIEventKind", "ui-event kind is outside the closed set");
            }
            return e;
        }

        // ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) --------------

        /// <summary>One step of a walked shown chain: the chain position, the event kind, the action
        /// content id shown, and the chain head after it.</summary>
        public sealed class ShownEvent
        {
            public readonly long Seq;
            public readonly long Kind;
            public readonly byte[] Action;
            public readonly byte[] Head;

            public ShownEvent(long seq, long kind, byte[] action, byte[] head)
            {
                Seq = seq;
                Kind = kind;
                Action = action;
                Head = head;
            }
        }

        /// <summary>Verify a UI event chain's structural continuity OFFLINE (no signatures) and return
        /// the ordered shown events. It requires every event to name the SAME session, seq i to equal its
        /// index, each kind to be in the closed set, and prev to link to the previous event's Head
        /// (genesis for seq 0). A gap, reorder, omitted event, or a session change is UIChainBroken
        /// (fail-closed); an unknown kind is UnknownUIEventKind.</summary>
        public static List<ShownEvent> WalkShown(List<UIEvent> events)
        {
            var outp = new List<ShownEvent>(events.Count);
            byte[] h = Genesis();
            byte[]? session = null;
            for (int i = 0; i < events.Count; i++)
            {
                UIEvent e = events[i];
                if (i == 0)
                {
                    session = e.Session;
                }
                else if (!BytesEqual(e.Session, session!))
                {
                    throw new NaalpException("UIChainBroken", "a chain is for exactly one session");
                }
                if (!IsKnownKind(e.Kind))
                {
                    throw new NaalpException("UnknownUIEventKind", "ui-event kind is outside the closed set");
                }
                if (e.Seq != i || !BytesEqual(e.Prev, h))
                {
                    throw new NaalpException("UIChainBroken", "ui-event prev/seq does not chain to the previous event");
                }
                h = e.Head();
                outp.Add(new ShownEvent(e.Seq, e.Kind, (byte[])e.Action.Clone(), (byte[])h.Clone()));
            }
            return outp;
        }

        /// <summary>Check a UI event chain offline against the UI authority's key. Each element is the
        /// tagged COSE_Sign1 object for one event; verify every signature under the profile
        /// (VerifyUIEvent), then enforce the same structural continuity as <see cref="WalkShown"/>. A bad
        /// signature propagates BadSignature; a broken link, seq gap, or session change is UIChainBroken.
        /// Detects any reorder, omission, or substitution of a shown event (§8.1). Fail-closed.</summary>
        public static List<UIEvent> VerifyShownChain(List<byte[]> objs, int profile, int alg, byte[] pubkey)
        {
            byte[] h = Genesis();
            byte[]? session = null;
            var outp = new List<UIEvent>(objs.Count);
            for (int i = 0; i < objs.Count; i++)
            {
                UIEvent e = VerifyUIEvent(objs[i], profile, alg, pubkey);
                if (i == 0)
                {
                    session = e.Session;
                }
                else if (!BytesEqual(e.Session, session!))
                {
                    throw new NaalpException("UIChainBroken", "a chain is for exactly one session");
                }
                if (e.Seq != i || !BytesEqual(e.Prev, h))
                {
                    throw new NaalpException("UIChainBroken", "ui-event prev/seq does not chain to the previous event");
                }
                h = e.Head();
                outp.Add(e);
            }
            return outp;
        }

        /// <summary>Report whether a presented (possibly gappy) event list breaks contiguity — a
        /// deleted/omitted shown-event — and, if so, the FIRST-BROKEN POSITION: the index i where the
        /// i-th presented event's Seq is not i or its Prev does not link to the previous event's Head. A
        /// contiguous list returns (0, false).</summary>
        public static (int Position, bool Hole) DetectHole(List<UIEvent> events)
        {
            byte[] h = Genesis();
            for (int i = 0; i < events.Count; i++)
            {
                UIEvent e = events[i];
                if (e.Seq != i || !BytesEqual(e.Prev, h))
                {
                    return (i, true);
                }
                h = e.Head();
            }
            return (0, false);
        }

        // ---- the UI consent binding (reuses the §7 approval) --------------------------------------

        /// <summary>The content id of the action shown-and-approved in a walked chain, and whether an
        /// approved event is present. It is the content id a valid consent binds; a chain with no
        /// approved event has no consent to bind.</summary>
        public static (byte[] Cid, bool Ok) ApprovedActionCid(List<ShownEvent> shown)
        {
            foreach (ShownEvent ev in shown)
            {
                if (ev.Kind == KindApproved)
                {
                    return ((byte[])ev.Action.Clone(), true);
                }
            }
            return (Array.Empty<byte>(), false);
        }

        /// <summary>Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It
        /// (1) walks the shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the
        /// action content id from the shown-and-approved event (UINoConsent if there is none); (3)
        /// verifies the human §7 approval binds THAT shown content id and has not expired
        /// (ApprovalMismatch / ApprovalExpired / BadSignature); and (4) requires the action actually
        /// being executed (<paramref name="actionBytes"/>) to hash to the shown-and-approved content id —
        /// a SUBSTITUTED action has a different content id and is rejected (ActionSubstituted). Every
        /// failure throws its named error and authorizes nothing (fail-closed). On success the caller may
        /// execute exactly <paramref name="actionBytes"/>.</summary>
        public static void VerifyConsent(List<UIEvent> chain, byte[] actionBytes, Approval.ApprovalRecord appr,
            int approverAlg, byte[] approverPubkey, byte[] apprSig, long now)
        {
            List<ShownEvent> shown = WalkShown(chain); // UIChainBroken / UnknownUIEventKind on a hole
            (byte[] shownCid, bool ok) = ApprovedActionCid(shown);
            if (!ok)
            {
                throw new NaalpException("UINoConsent", "the shown chain carries no approved event");
            }
            // The human approval must be a valid signature binding the shown-and-approved action content id.
            Approval.VerifyApproval(appr, approverAlg, approverPubkey, apprSig, shownCid, now);
            // The action actually being executed MUST be the exact one shown and approved: a substitution
            // has a different content id and is rejected. This is the seam a lax UI profile would drop.
            if (!BytesEqual(ContentId(actionBytes), shownCid))
            {
                throw new NaalpException("ActionSubstituted", "the executed action is not the exact action shown+approved");
            }
        }

        // ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) -------------

        private static byte[] BareProtected(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        private static int AlgFromProtected(byte[] prot)
        {
            Cbor.Value pv;
            try
            {
                pv = Cbor.Decode(prot);
            }
            catch (NaalpException)
            {
                throw new NaalpException("UIMalformed", "protected header is malformed");
            }
            if (pv is Cbor.M m)
            {
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (p.K is Cbor.U ku && ku.V == 1)
                    {
                        if (p.Val is Cbor.N n) return (int)n.V;
                        if (p.Val is Cbor.U u) return (int)u.V;
                    }
                }
            }
            throw new NaalpException("UIMalformed", "protected header has no alg");
        }

        // VerifySign1 verifies a tagged COSE_Sign1 object under the profile floor with real crypto and
        // returns the payload: alg registry -> profile floor -> key-alg match -> signature. Fail-closed.
        private static byte[] VerifySign1(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[][] parts;
            try
            {
                parts = Cose.ParseSign1Raw(obj);
            }
            catch (NaalpException)
            {
                throw new NaalpException("UIMalformed", "malformed COSE object");
            }
            byte[] prot = parts[0];
            byte[] payload = parts[1];
            byte[] sig = parts[2];

            int halg = AlgFromProtected(prot);
            (int level, bool known) = Cose.AlgLevel(halg);
            if (!known)
            {
                throw new NaalpException("UnknownAlg", "unregistered alg " + halg);
            }
            if (level < Cose.ProfileMinLevel(profile))
            {
                throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
            }
            if (halg != alg)
            {
                throw new NaalpException("KeyAlgMismatch", "alg " + halg + " does not match the verifier key alg " + alg);
            }
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            if (!Cose.CoseVerify1Raw(halg, pubkey, tbs, sig))
            {
                throw new NaalpException("BadSignature", "signature does not verify");
            }
            return payload;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
