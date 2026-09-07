// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

namespace Naalp
{
    public static partial class Envelope
    {
        /// <summary>
        /// The ext/cext extension key under which an object NAMES the re-check procedure for the claim
        /// in its body (design.md §2.5, NAALP-REQ-111(c) -- the "checkable minimum"). The value is a
        /// procedure id into the closed registry below. In the non-critical ext map (field 11) it is
        /// may-ignore; in the critical cext map (field 12) it is must-understand and an unknown
        /// procedure id is rejected fail-closed (UnknownCriticalExt), the same C3 critical-extension
        /// rule reaching the procedure it names. 13 does not collide with the safety-label ext key 1
        /// (§6.4), the signer-counter ext key 14 (§2.5.2), or the producing-boundary ext key 15 (§2.5.4).
        /// Byte-identical to impl/go and impl/rust.
        /// </summary>
        public const int RECHECK_KEY = 13;

        // The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
        // recheck-procedure production and vectors/registry/recheck.csv.

        /// <summary>Recompute the content id from the body and compare (§2.3).</summary>
        public const long RECHECK_RECOMPUTE_CONTENT_ID = 1;

        /// <summary>Verify the COSE_Sign1 signature under the signer key (§4).</summary>
        public const long RECHECK_VERIFY_COSE_SIGN1 = 2;

        /// <summary>Walk the signed causal partial order offline (§8.2).</summary>
        public const long RECHECK_WALK_CAUSES = 3;

        /// <summary>Replay the single-use consume ledger for the approval (§7.2).</summary>
        public const long RECHECK_REPLAY_CONSUME_CHECK = 4;

        /// <summary>
        /// Reports whether <paramref name="id"/> is a recognized re-check procedure. The registry is
        /// CLOSED: an id outside {1..4} is unknown, and an unknown id under the critical map is
        /// rejected (§2.5).
        /// </summary>
        public static bool IsKnownRecheckProcedure(long id)
        {
            return id >= RECHECK_RECOMPUTE_CONTENT_ID && id <= RECHECK_REPLAY_CONSUME_CHECK;
        }
    }

    /// <summary>
    /// Accessor/setter for the T1.3 recheck procedure (<see cref="Envelope.RECHECK_KEY"/>, §2.5). Kept
    /// as EXTENSION methods on <see cref="Envelope.Object"/> -- purely additive, with no edit to the
    /// existing Envelope.cs -- the same idiom as
    /// <see cref="EnvelopeProducingBoundaryExtensions"/> and
    /// <see cref="EnvelopeSignerCounterExtensions"/>, so the call site reads
    /// <c>o.Recheck()</c> / <c>o.SetRecheck(id, critical)</c>, mirroring impl/go's
    /// <c>(o *Object) Recheck()</c> / <c>SetRecheck()</c> methods.
    /// </summary>
    public static class EnvelopeRecheckExtensions
    {
        // ExtGetUint mirrors impl/go's cextGetUint: returns the uint value under key in a CBOR map (ext
        // or cext), reporting present only when the key exists AND its value is a uint. A present key
        // whose value is the WRONG type returns not-present (never falls through to keep scanning).
        private static bool ExtGetUint(Cbor.M? m, int key, out long value)
        {
            value = 0;
            if (m == null)
            {
                return false;
            }
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == key)
                {
                    if (p.Val is Cbor.U vu)
                    {
                        value = vu.V;
                        return true;
                    }
                    return false;
                }
            }
            return false;
        }

        /// <summary>
        /// Return the re-check procedure <paramref name="o"/> names (<see cref="Envelope.RECHECK_KEY"/>,
        /// §2.5): Present is true when a procedure is named, and Critical is true iff it is named in the
        /// cext map (field 12, must-understand) rather than the ext map (field 11, may-ignore). cext
        /// takes precedence when both carry the key. When no procedure is named the claim is
        /// attributable-only (NAALP-REQ-111).
        /// </summary>
        public static (long Id, bool Present, bool Critical) Recheck(this Envelope.Object o)
        {
            if (ExtGetUint(o.Cext, Envelope.RECHECK_KEY, out long cv))
            {
                return (cv, true, true);
            }
            if (ExtGetUint(o.Ext, Envelope.RECHECK_KEY, out long ev))
            {
                return (ev, true, false);
            }
            return (0, false, false);
        }

        /// <summary>
        /// Name <paramref name="procId"/> as the body claim's re-check procedure. <paramref
        /// name="critical"/> places it in the cext map (field 12, must-understand); otherwise the ext
        /// map (field 11, may-ignore). Creates the carrier if absent and leaves any other extension
        /// entries -- including one already in the OTHER carrier -- intact.
        /// </summary>
        public static void SetRecheck(this Envelope.Object o, long procId, bool critical)
        {
            var entry = new Cbor.Pair(new Cbor.U(Envelope.RECHECK_KEY), new Cbor.U(procId));
            if (critical)
            {
                o.Cext = UpsertEntry(o.Cext, entry);
            }
            else
            {
                o.Ext = UpsertEntry(o.Ext, entry);
            }
        }

        private static Cbor.M UpsertEntry(Cbor.M? target, Cbor.Pair entry)
        {
            if (target == null)
            {
                return new Cbor.M(new List<Cbor.Pair> { entry });
            }
            var newPairs = new List<Cbor.Pair>(target.Pairs.Count + 1);
            bool replaced = false;
            foreach (Cbor.Pair p in target.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == Envelope.RECHECK_KEY)
                {
                    newPairs.Add(entry);
                    replaced = true;
                }
                else
                {
                    newPairs.Add(p);
                }
            }
            if (!replaced)
            {
                newPairs.Add(entry);
            }
            return new Cbor.M(newPairs);
        }
    }
}
