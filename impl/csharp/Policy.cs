// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// N-AALP C5 effect vocabulary and authorization for the C# SDK (§6).
    ///
    /// <para>The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
    /// unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
    /// (action &lt;= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.</para>
    /// </summary>
    public static class Policy
    {
        public const long READ_ONLY = 0;
        public const long IDEMPOTENT_WRITE = 1;
        public const long NON_IDEMPOTENT_WRITE = 2;
        public const long DESTRUCTIVE = 3;

        private static readonly string[] Names =
        {
            "read_only", "idempotent_write", "non_idempotent_write", "destructive",
        };

        /// <summary>Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2).</summary>
        public static long NormalizeEffect(long v)
        {
            return (v >= 0 && v <= 3) ? v : DESTRUCTIVE;
        }

        public static string SafetyLabelName(long e)
        {
            return Names[NormalizeEffect(e)];
        }

        /// <summary>The §6.1 lattice: an action of class `action` is permitted under ceiling iff action &lt;= ceiling.</summary>
        public static bool Authorizes(long ceiling, long action)
        {
            return action <= ceiling;
        }

        /// <summary>The signed safety-label body {1: risk, 2: scope} (R-6.4).</summary>
        public static byte[] SafetyLabelBytes(string risk, string scope)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.T(risk)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(scope)),
            }));
        }
    }
}
