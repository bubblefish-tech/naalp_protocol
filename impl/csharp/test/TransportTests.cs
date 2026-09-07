// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C11 transport bindings graded against the non-circular oracle
    /// <c>vectors/transport/cases.json</c>: one signed object = one message unit across
    /// N-PAMP/QUIC/WebSocket/HTTP; the binding adds only framing; a sensitive object over a
    /// non-confidential transport is refused (ConfidentialTransportRequired); a required-but-absent
    /// peer authentication is refused (PeerUnauthenticated); the media type is
    /// <c>application/vnd.bubblefish.naalp+cbor</c>. The expected values come from the committed corpus, not from
    /// the module under test.
    /// </summary>
    public sealed class TransportTests
    {
        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "transport", "cases.json");
                if (File.Exists(p))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(p));
                    return doc.RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/transport/cases.json not found from " + AppContext.BaseDirectory);
        }

        [Fact]
        public void TransportTableMatchesOracle()
        {
            JsonElement v = Vector();
            Assert.Equal(v.GetProperty("media_type").GetString(), Transport.MediaType);
            foreach (JsonElement tr in v.GetProperty("transports").EnumerateArray())
            {
                string name = tr.GetProperty("name").GetString()!;
                Transport.Binding? b = Transport.ByName(name);
                Assert.True(b != null, "unknown transport " + name);
                Assert.Equal(tr.GetProperty("confidential").GetBoolean(), b!.Confidential);
                Assert.Equal(tr.GetProperty("peer_authenticated").GetBoolean(), b!.PeerAuthenticated);
            }
        }

        [Fact]
        public void EmitMatrixMatchesOracle()
        {
            JsonElement v = Vector();
            byte[] obj = { 0xDE, 0xAD, 0xBE, 0xEF };
            int confidentialRefusals = 0, authRefusals = 0;
            foreach (JsonElement r in v.GetProperty("emit_matrix").EnumerateArray())
            {
                string name = r.GetProperty("transport").GetString()!;
                bool sensitive = r.GetProperty("sensitive").GetBoolean();
                bool requirePeerAuth = r.GetProperty("require_peer_auth").GetBoolean();
                string want = r.GetProperty("result").GetString()!;
                Transport.Binding b = Transport.ByName(name)!;

                if (want == "ok")
                {
                    Transport.MessageUnit mu = Transport.Emit(b, obj, sensitive, requirePeerAuth);
                    Assert.Equal(obj, mu.Payload);
                    Assert.Equal(Transport.MediaType, mu.MediaType);
                }
                else
                {
                    var ex = Assert.Throws<NaalpException>(
                        () => Transport.Emit(b, obj, sensitive, requirePeerAuth));
                    Assert.Equal(want, ex.Kind);
                    if (want == "ConfidentialTransportRequired") confidentialRefusals++;
                    if (want == "PeerUnauthenticated") authRefusals++;
                }
            }
            Assert.True(confidentialRefusals > 0, "matrix must exercise a confidentiality refusal");
            Assert.True(authRefusals > 0, "matrix must exercise a peer-auth refusal");
        }

        [Fact]
        public void CrossBindingIdentityPreservesObjectBytes()
        {
            byte[] obj = { 1, 2, 3, 4, 5, 6, 7, 8 };
            foreach (Transport.Binding b in new[]
                { Transport.NPAMP, Transport.QUIC, Transport.WebSocketWSS, Transport.HTTPS })
            {
                Transport.MessageUnit mu = Transport.Emit(b, obj, false, false);
                byte[] recovered = mu.Object();
                Assert.Equal(obj, recovered);
            }
        }

        [Fact]
        public void MediaTypeRejected()
        {
            var mu = new Transport.MessageUnit("http", "application/json", new byte[] { 1, 2, 3 });
            var ex = Assert.Throws<NaalpException>(() => mu.Object());
            Assert.Equal("Malformed", ex.Kind);
        }
    }
}
