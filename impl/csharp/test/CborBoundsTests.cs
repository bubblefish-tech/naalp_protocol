// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// The CBOR decoder nesting-depth bound (design.md §3.4, R7), ported from
    /// impl/go/cbor/bounds_test.go. The outermost item is depth 1, and DecodeBounded rejects the
    /// first item at depth maxDepth+1 with a DepthExceeded error, before it is materialized. The
    /// unbounded Decode path still accepts the same structure, so the bound is what does the work.
    /// </summary>
    public sealed class CborBoundsTests
    {
        // nestedArraysCbor returns canonical CBOR for k single-element arrays wrapping a zero
        // scalar: 0x81 (array of one) repeated k times, then 0x00. Decoding it, the outermost
        // array is at depth 1 and the innermost scalar is at depth k+1.
        private static byte[] NestedArraysCbor(int k)
        {
            var outp = new byte[k + 1];
            for (int i = 0; i < k; i++)
            {
                outp[i] = 0x81;
            }
            outp[k] = 0x00;
            return outp;
        }

        [Fact]
        public void DecodeBoundedDepth()
        {
            const int d = 3;

            // deepest scalar at depth d (k = d-1): accepted at maxDepth=d.
            byte[] atLimit = NestedArraysCbor(d - 1);
            Cbor.DecodeBounded(atLimit, d); // must not throw

            // deepest scalar at depth d+1 (k = d): rejected DepthExceeded at maxDepth=d.
            byte[] over = NestedArraysCbor(d);
            var ex = Assert.Throws<NaalpException>(() => Cbor.DecodeBounded(over, d));
            Assert.Equal("DepthExceeded", ex.Kind);

            // The unbounded path accepts the same over-depth structure: the bound, not another
            // check, is what rejected it above.
            Cbor.Decode(over); // must not throw
        }
    }
}
