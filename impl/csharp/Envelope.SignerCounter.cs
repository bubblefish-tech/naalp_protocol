// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    public static partial class Envelope
    {
        /// <summary>
        /// The ext extension key under which an object OPTIONALLY carries a forward-only per-signer
        /// counter (design.md §2.5.2, NAALP-REQ-120 -- the per-signer counter). The value is a
        /// forward-only position (a uint) the signer increments on each object. It lives in the
        /// NON-CRITICAL ext map (field 11): a verifier that does not perform duplication-detection
        /// ignores it and the object still verifies (may-ignore). Because ext (field 11) is part of the
        /// signed body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature -- the
        /// deliberate contrast with the T1.5 consume-receipt position, which is signed by the LEDGER
        /// key. 14 is the next free ext/cext key: it does not collide with the safety-label ext key 1
        /// (§6.4) or the recheck ext/cext key 13 (<see cref="RECHECK_KEY"/>). Byte-identical to impl/go
        /// and impl/rust.
        ///
        /// <para>The counter is DETECTION, not prevention (NAALP-REQ-120; Security Considerations): a
        /// single self-authored sequence proves nothing. It is a NON-CRITICAL field only -- placing it
        /// in the critical cext map (field 12) is an unrecognized critical extension and is rejected
        /// fail-closed (UnknownCriticalExt, the existing §2.5 rule), because a detection aid is never a
        /// must-understand verification gate.</para>
        /// </summary>
        public const int SIGNER_COUNTER_KEY = 14;

        /// <summary>
        /// One detected per-signer counter conflict: two or more DISTINCT objects (distinct content
        /// ids) from the SAME signer id that carry the SAME forward-only counter value. A forward-only
        /// counter binds each value to at most one object, so a value bound to &gt;= 2 distinct objects
        /// is the observable fingerprint of the key incrementing in two places (key duplication). The
        /// finding surfaces BOTH sides of the contradiction: the reused <see cref="Counter"/> value and
        /// every conflicting content id (<see cref="Ids"/>, ascending by bytes) -- never a single flag
        /// with the evidence hidden.
        /// </summary>
        public sealed class DuplicationFinding
        {
            /// <summary>The signer id whose forward-only counter was reused.</summary>
            public readonly byte[] Signer;

            /// <summary>The reused forward-only counter value.</summary>
            public readonly long Counter;

            /// <summary>The content ids of the &gt;= 2 conflicting objects, ascending by bytes.</summary>
            public readonly List<byte[]> Ids;

            public DuplicationFinding(byte[] signer, long counter, List<byte[]> ids)
            {
                Signer = signer;
                Counter = counter;
                Ids = ids;
            }
        }
    }

    /// <summary>
    /// Accessor/setter for the T1.6 forward-only per-signer counter
    /// (<see cref="Envelope.SIGNER_COUNTER_KEY"/>, §2.5.2), plus the set-wide duplication detector. Kept
    /// as EXTENSION methods on <see cref="Envelope.Object"/> -- purely additive, with no edit to the
    /// existing Envelope.cs -- the same idiom as <see cref="EnvelopeProducingBoundaryExtensions"/> and
    /// <see cref="EnvelopeRecheckExtensions"/>, so the call site reads <c>o.SignerCounter()</c> /
    /// <c>o.SetSignerCounter(seq)</c>, mirroring impl/go's <c>(o *Object) SignerCounter()</c> /
    /// <c>SetSignerCounter()</c> methods.
    /// </summary>
    public static class EnvelopeSignerCounterExtensions
    {
        // ExtGetUint mirrors impl/go's cextGetUint: returns the uint value under key in a CBOR map,
        // reporting present only when the key exists AND its value is a uint.
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
        /// Return the forward-only per-signer position <paramref name="o"/> names
        /// (<see cref="Envelope.SIGNER_COUNTER_KEY"/>, §2.5.2): Present is true iff a counter is named
        /// in the non-critical ext map (field 11) as a uint. The field is OPTIONAL -- absent
        /// (Present == false) is valid. Present is keyed on the KEY being present, not on the value: a
        /// present counter of value 0 returns (0, true).
        /// </summary>
        public static (long Seq, bool Present) SignerCounter(this Envelope.Object o)
        {
            bool present = ExtGetUint(o.Ext, Envelope.SIGNER_COUNTER_KEY, out long v);
            return (v, present);
        }

        /// <summary>
        /// Name <paramref name="seq"/> as this object's forward-only per-signer position in the
        /// NON-CRITICAL ext map (field 11), covered by the signer's COSE_Sign1 signature. Creates the
        /// ext carrier if absent and leaves any other extension entries intact. The counter is
        /// deliberately never placed in the critical cext map (it is detection, not a verification
        /// gate) -- a caller who does so builds ext/cext directly, bypassing this setter.
        /// </summary>
        public static void SetSignerCounter(this Envelope.Object o, long seq)
        {
            var entry = new Cbor.Pair(new Cbor.U(Envelope.SIGNER_COUNTER_KEY), new Cbor.U(seq));
            if (o.Ext == null)
            {
                o.Ext = new Cbor.M(new List<Cbor.Pair> { entry });
                return;
            }
            var newPairs = new List<Cbor.Pair>(o.Ext.Pairs.Count + 1);
            bool replaced = false;
            foreach (Cbor.Pair p in o.Ext.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == Envelope.SIGNER_COUNTER_KEY)
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
            o.Ext = new Cbor.M(newPairs);
        }

        // BytesKey renders a byte string as a fixed-width (2 hex chars/byte) hex string so ordinal
        // string ordering of the key is IDENTICAL to unsigned bytewise ordering of the underlying bytes
        // (including differing-length prefixes) -- matching Go's raw-byte string comparison
        // (sort.Strings over a Go string built from the raw signer bytes).
        private static string BytesKey(byte[] b) => Convert.ToHexString(b);

        /// <summary>
        /// Scan a SET of PRESENTED objects for per-signer counter reuse. This is the whole point of the
        /// field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a signer id ONLY when
        /// two conflicting sequences from that signer physically MEET in the presented set -- a counter
        /// value bound to &gt;= 2 distinct content ids by one signer. Given only ONE object per value
        /// (one sequence) it returns no findings; the second conflicting object must be present,
        /// unsuppressed, for the duplication to become provable. Objects with no counter do not
        /// participate. Output is deterministic (findings ordered by signer id then counter; ids within
        /// a finding ascending).
        ///
        /// <para>It operates over the SET, never per object: a per-object boolean could never express
        /// "these two distinct objects reuse one position," and a single self-authored counter proves
        /// nothing on its own.</para>
        /// </summary>
        public static List<Envelope.DuplicationFinding> DetectSignerDuplication(IEnumerable<Envelope.Object> objs)
        {
            // signerKey -> counter -> (content-id-key -> content-id-bytes), a set that de-dups a
            // byte-identical re-presentation (one content id twice) so it is NOT a conflict.
            var groups = new SortedDictionary<string, Dictionary<long, Dictionary<string, byte[]>>>(StringComparer.Ordinal);
            var signerBytes = new Dictionary<string, byte[]>();

            foreach (Envelope.Object o in objs)
            {
                (long seq, bool present) = o.SignerCounter();
                if (!present)
                {
                    continue; // a counter-less object does not participate in detection
                }
                byte[] id = o.ContentId();
                string sk = BytesKey(o.Signer);
                signerBytes[sk] = o.Signer;
                if (!groups.TryGetValue(sk, out Dictionary<long, Dictionary<string, byte[]>>? byCounter))
                {
                    byCounter = new Dictionary<long, Dictionary<string, byte[]>>();
                    groups[sk] = byCounter;
                }
                if (!byCounter.TryGetValue(seq, out Dictionary<string, byte[]>? idset))
                {
                    idset = new Dictionary<string, byte[]>();
                    byCounter[seq] = idset;
                }
                idset[BytesKey(id)] = id;
            }

            var findings = new List<Envelope.DuplicationFinding>();
            foreach (KeyValuePair<string, Dictionary<long, Dictionary<string, byte[]>>> skEntry in groups)
            {
                Dictionary<long, Dictionary<string, byte[]>> byCounter = skEntry.Value;
                var counters = new List<long>(byCounter.Keys);
                // ascending UNSIGNED order (the counter is a uint64 bit pattern carried in a signed
                // long, §wire convention) -- matches impl/go's sort.Slice over uint64.
                counters.Sort((a, b) => ((ulong)a).CompareTo((ulong)b));
                foreach (long c in counters)
                {
                    Dictionary<string, byte[]> idset = byCounter[c];
                    // A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
                    // duplication. The >= 2 requirement is the detection-requires-both invariant: relax
                    // it to >= 1 and a single sequence would flag (prevention theatre) -- the mutation
                    // the "one sequence alone -> not flagged" test is built to catch.
                    if (idset.Count < 2)
                    {
                        continue;
                    }
                    var ids = new List<byte[]>(idset.Values);
                    ids.Sort((a, b) => Cbor.CompareBytes(a, b));
                    findings.Add(new Envelope.DuplicationFinding(signerBytes[skEntry.Key], c, ids));
                }
            }
            return findings;
        }
    }
}
