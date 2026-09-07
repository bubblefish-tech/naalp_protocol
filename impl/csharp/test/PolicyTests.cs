// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C5 §6 authorization for the C# SDK: the granted×effect authorize/deny matrix (R-6.3), the
    /// signature-only authorization-principal rule (R-6.5), and the strict optional safety-label
    /// extraction (R-6.4). Graded against the shared independent corpus
    /// <c>vectors/effect/cases.json</c> (NOT produced by this code): the authorization_matrix,
    /// principal_sources, and safety_label sections.
    /// </summary>
    public sealed class PolicyTests
    {
        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "effect", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new FileNotFoundException("vectors/effect/cases.json not found");
        }

        // R-6.3: the endpoint policy check denies exactly the effects that exceed the grant's ceiling
        // (a matched signature principal), and the raw lattice agrees. THE MUTATION TARGET: making
        // Grant.AuthorizeObject accept everything flips the denied rows here on their EffectNotAuthorized.
        [Fact]
        public void AuthorizationMatrixMatchesOracle()
        {
            JsonElement v = Vector();
            int allows = 0, denies = 0;
            foreach (JsonElement r in v.GetProperty("authorization_matrix").EnumerateArray())
            {
                long granted = r.GetProperty("granted").GetInt64();
                long effect = r.GetProperty("effect").GetInt64();
                bool allow = r.GetProperty("allow").GetBoolean();
                var g = new Policy.Grant("pA", granted);
                if (allow)
                {
                    allows++;
                    g.AuthorizeObject(Policy.PrincipalSource.Signature, "pA", effect); // must not throw
                }
                else
                {
                    denies++;
                    var ex = Assert.Throws<NaalpException>(
                        () => g.AuthorizeObject(Policy.PrincipalSource.Signature, "pA", effect));
                    Assert.Equal("EffectNotAuthorized", ex.Kind);
                }
                Assert.Equal(allow, Policy.Authorizes(granted, Policy.NormalizeEffect(effect)));
            }
            Assert.True(allows > 0 && denies > 0, "matrix must exercise both allow and deny");
        }

        // R-6.5: only a signature-derived identity is an authorization principal; a transport/foreign/
        // client source is refused UnauthenticatedPrincipal, and even a read_only object is denied from it.
        [Fact]
        public void OnlySignatureIsAnAuthorizationPrincipal()
        {
            JsonElement v = Vector();
            var map = new Dictionary<string, Policy.PrincipalSource>
            {
                { "signature", Policy.PrincipalSource.Signature },
                { "transport_metadata", Policy.PrincipalSource.TransportMetadata },
                { "foreign_header", Policy.PrincipalSource.ForeignHeader },
                { "client_name", Policy.PrincipalSource.ClientName },
            };
            var g = new Policy.Grant("pA", Policy.DESTRUCTIVE); // maximally permissive ceiling
            foreach (JsonElement ps in v.GetProperty("principal_sources").EnumerateArray())
            {
                var src = map[ps.GetProperty("source").GetString()!];
                bool accepted = ps.GetProperty("accepted").GetBoolean();
                if (accepted)
                {
                    Assert.Equal("pA", Policy.ResolveAuthPrincipal(src, "pA"));
                    g.AuthorizeObject(src, "pA", Policy.READ_ONLY); // must not throw
                }
                else
                {
                    Assert.Equal("UnauthenticatedPrincipal",
                        Assert.Throws<NaalpException>(() => Policy.ResolveAuthPrincipal(src, "pA")).Kind);
                    Assert.Equal("UnauthenticatedPrincipal",
                        Assert.Throws<NaalpException>(() => g.AuthorizeObject(src, "pA", Policy.READ_ONLY)).Kind);
                }
            }
        }

        // R-6.4: SafetyLabelFromExt extracts a well-formed {1:tstr,2:tstr} label, reports absence, and
        // rejects a malformed/incomplete label MalformedSafetyLabel — never silently accepting it.
        [Fact]
        public void SafetyLabelFromExtStrict()
        {
            JsonElement v = Vector();
            JsonElement sl = v.GetProperty("safety_label");
            string risk = sl.GetProperty("risk").GetString()!;
            string scope = sl.GetProperty("scope").GetString()!;
            long extKey = sl.GetProperty("ext_key").GetInt64();

            var ext = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(extKey), new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(risk)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(scope)),
                })),
            });
            var (label, present) = Policy.SafetyLabelFromExt(ext);
            Assert.True(present);
            Assert.Equal(risk, label!.Risk);
            Assert.Equal(scope, label.Scope);

            // absent
            Assert.False(Policy.SafetyLabelFromExt(new Cbor.M(new List<Cbor.Pair>())).Present);

            // malformed: ext[1] present but not a map
            Assert.Equal("MalformedSafetyLabel", Assert.Throws<NaalpException>(() =>
                Policy.SafetyLabelFromExt(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(extKey), new Cbor.U(9)),
                }))).Kind);

            // incomplete: missing scope
            Assert.Equal("MalformedSafetyLabel", Assert.Throws<NaalpException>(() =>
                Policy.SafetyLabelFromExt(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(extKey), new Cbor.M(new List<Cbor.Pair>
                    {
                        new Cbor.Pair(new Cbor.U(1), new Cbor.T("x")),
                    })),
                }))).Kind);
        }
    }
}
