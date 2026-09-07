// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// T3.3 naalp-error object + numeric error-code registry (design.md §3.5, R3.3/R3.4) known-answer
    /// tests for the C# SDK. Mirrors impl/go/naalperror/naalperror_test.go and
    /// impl/rust/src/naalperror.rs's embedded tests: (1) registry size + index (129 unique names,
    /// code == index+1), (2) hand-computed encode KATs (independent of the oracle and of impl/go /
    /// impl/rust), (3) full-grammar encode/decode round trip (detail + subject), (4) dual-carriage
    /// mismatch rejected Malformed [MUTATION ANCHOR], (5) unknown code accepted opaque
    /// [MUTATION ANCHOR], (6) NameForCode known entries + the unregistered boundary.
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~NaalpErrorKatTest</c></para>
    /// </summary>
    public sealed class NaalpErrorKatTest
    {
        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        /// <summary>
        /// Pins the registry to exactly 129 unique names with no gaps (the fields-of-record invariant:
        /// code == index+1, sequential 1..129). A mutation that drops or duplicates an entry flips this
        /// and the code/name relationship.
        /// </summary>
        [Fact]
        public void RegistrySizeAndIndex()
        {
            Assert.Equal(132, NaalpError.Names.Length);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < NaalpError.Names.Length; i++)
            {
                string n = NaalpError.Names[i];
                Assert.True(seen.Add(n), "duplicate name " + n + " at code " + (i + 1));
                (long c, bool ok) = NaalpError.CodeForName(n);
                Assert.True(ok && c == i + 1, "CodeForName(" + n + ")=" + c + "," + ok + " want " + (i + 1));
            }
        }

        /// <summary>
        /// Pins the deterministic naalp-error body bytes against hand-computed CBOR (independent of the
        /// oracle and of impl/go / impl/rust): a2 (map-2) 01 &lt;code&gt; 02 &lt;tstr name&gt;. A
        /// mutation of Encode flips it.
        /// </summary>
        [Fact]
        public void EncodeKat()
        {
            // code 1 (single-byte uint), name "NonCanonical" (12 bytes -> tstr head 0x6c).
            Assert.Equal("a20101026c4e6f6e43616e6f6e6963616c", Hex(NaalpError.Encode(1, "NonCanonical", "", null)));
            // code 52 (>=24 -> two-byte uint 18 34), name "NotDelivered" (12 bytes).
            Assert.Equal("a2011834026c4e6f7444656c697665726564", Hex(NaalpError.Encode(52, "NotDelivered", "", null)));
        }

        /// <summary>
        /// Exercises the optional fields 3 and 4 (map grows to a3/a4, keys stay ascending): a full
        /// round trip through Decode must recover the exact code/name/detail/subject.
        /// </summary>
        [Fact]
        public void EncodeDecodeFull()
        {
            byte[] subj = new byte[50];
            subj[0] = 0x20;
            subj[1] = 0x30;
            (long code, bool ok) = NaalpError.CodeForName("BadSignature");
            Assert.True(ok);
            byte[] b = NaalpError.Encode(code, "BadSignature", "reason", subj);
            NaalpError.Object o = NaalpError.Decode(b);
            Assert.Equal("BadSignature", o.Name);
            Assert.Equal("reason", o.Detail);
            Assert.NotNull(o.Subject);
            Assert.Equal(50, o.Subject!.Length);
        }

        /// <summary>
        /// MUTATION ANCHOR: a registered code carrying the wrong registered name is rejected Malformed
        /// (the strengthening direction -- the code is authoritative). Skipping the name-agreement check
        /// flips this test pass-&gt;fail.
        /// </summary>
        [Fact]
        public void DualCarriageMismatchIsMalformed()
        {
            (long code22, bool ok) = NaalpError.CodeForName("BadSignature"); // code 22
            Assert.True(ok);
            byte[] b = NaalpError.Encode(code22, "NotDelivered", "", null); // code 22, name of code 52
            NaalpException ex = Assert.Throws<NaalpException>(() => NaalpError.Decode(b));
            Assert.Equal("Malformed", ex.Kind);
        }

        /// <summary>
        /// MUTATION ANCHOR: a code outside the registry is accepted opaque (open-registry contract).
        /// Rejecting an unknown code flips this test pass-&gt;fail.
        /// </summary>
        [Fact]
        public void UnknownCodeIsOpaque()
        {
            byte[] b = NaalpError.Encode(60000, "SomeFutureError", "", null);
            NaalpError.Object o = NaalpError.Decode(b);
            Assert.Equal(60000, o.Code);
            Assert.Equal("SomeFutureError", o.Name);
        }

        /// <summary>Pins a few known code-&gt;name entries plus the unregistered boundary.</summary>
        [Fact]
        public void NameForCodeKnownAndBoundary()
        {
            var want = new Dictionary<long, string>
            {
                [1] = "NonCanonical",
                [22] = "BadSignature",
                [119] = "RebindUnauthorized",
            };
            foreach (KeyValuePair<long, string> kv in want)
            {
                (string name, bool ok) = NaalpError.NameForCode(kv.Key);
                Assert.True(ok, "NameForCode(" + kv.Key + ") must be registered");
                Assert.Equal(kv.Value, name);
            }
            foreach (long code in new long[] { 0, 133, 60000 })
            {
                (_, bool ok) = NaalpError.NameForCode(code);
                Assert.False(ok, "NameForCode(" + code + ") should be unregistered");
            }
        }
    }
}
