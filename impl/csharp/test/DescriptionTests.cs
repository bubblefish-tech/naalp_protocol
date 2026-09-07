// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C18 signed description / directory / import conformance for the C# SDK (design.md §21;
    /// R-DESC-1..8), graded against the shared independent corpus <c>vectors/description/cases.json</c>
    /// (NOT produced by this code): the Description body/head/id and each operation body; the Directory
    /// bodies (version A, the fork B, the length-fork, the different-version succession); the fork
    /// FIRST-DIFFERING position; the Import body/head/id and the bound foreign-id; and the closed
    /// naalp-description-format rejection of an unknown format.
    ///
    /// <para>The offline-verification, directory fork-proof, and confused-deputy import paths use REAL
    /// deterministic ML-DSA-65 (BouncyCastle, rnd=0) and are demonstrated in isolation — the corpus
    /// carries no signed vector (F2/F4, honest). Ported from impl/go/description; mirrors
    /// impl/python/naalp/description.py.</para>
    ///
    /// <para>Deviation from the Go reference (honest F4 note): Go's VerifyImport carries an
    /// ErrVerifierKeyMismatch guard because it takes BOTH an (alg, pubkey) pair AND a separate
    /// cose.Verifier, and must bind them before deriving the authority id. This C# port — like the
    /// Python/Kotlin ports and the sibling <see cref="Gateway.VerifyDecision"/> — verifies with a SINGLE
    /// (alg, pubkey) pair, so the authority id is ALWAYS derived from exactly the key that verified the
    /// signature; the mismatch that guard prevents is structurally impossible here. There is no
    /// VerifierKeyMismatch surface to port: it is absent because the vulnerability it guards cannot
    /// arise in this signature, NOT silently dropped.</para>
    /// </summary>
    public sealed class DescriptionTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "description", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/description/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static List<Description.Operation> OpsOf(JsonElement arr)
        {
            var ops = new List<Description.Operation>();
            foreach (JsonElement o in arr.EnumerateArray())
            {
                ops.Add(new Description.Operation(
                    o.GetProperty("name").GetString()!,
                    o.GetProperty("effect").GetInt64(),
                    o.GetProperty("requires_approval").GetInt64()));
            }
            return ops;
        }

        private static Description.Doc DocOf(JsonElement dv)
        {
            return new Description.Doc(Hb(dv.GetProperty("service_hex").GetString()!), OpsOf(dv.GetProperty("operations")));
        }

        private static Description.Directory DirOf(byte[] id, long version, JsonElement membersHex)
        {
            var members = new List<byte[]>();
            foreach (JsonElement m in membersHex.EnumerateArray())
            {
                members.Add(Hb(m.GetString()!));
            }
            return new Description.Directory(id, version, members);
        }

        // ---- Description: the signed operation table body + each operation body --------------------

        [Fact]
        public void DescriptionBodyMatchesOracle()
        {
            JsonElement v = Vector();
            JsonElement dv = v.GetProperty("description");
            Description.Doc doc = DocOf(dv);
            Assert.Equal(dv.GetProperty("body_hex").GetString(), Hex(doc.Bytes()));
            Assert.Equal(dv.GetProperty("head_hex").GetString(), Hex(doc.Head()));
            Assert.Equal(dv.GetProperty("id_hex").GetString(), Hex(doc.Id()));

            foreach (JsonElement o in dv.GetProperty("operations").EnumerateArray())
            {
                var op = new Description.Operation(
                    o.GetProperty("name").GetString()!, o.GetProperty("effect").GetInt64(), o.GetProperty("requires_approval").GetInt64());
                Assert.Equal(o.GetProperty("body_hex").GetString(), Hex(op.Bytes()));
            }

            // ParseDescription reconstructs the table from the bytes ALONE (offline-verifiable).
            Description.Doc parsed = Description.ParseDescription(Hb(dv.GetProperty("body_hex").GetString()!));
            Assert.Equal(dv.GetProperty("body_hex").GetString(), Hex(parsed.Bytes()));
            Assert.True(parsed.Operation("purge", out Description.Operation purge));
            Assert.Equal(Policy.DESTRUCTIVE, purge.EffectClass());
            Assert.True(purge.RequiresApprovalFlag());
        }

        // ---- Directory: the version A body, the fork B, the length-fork, the succession ------------

        [Fact]
        public void DirectoryBodiesMatchOracle()
        {
            JsonElement v = Vector();
            JsonElement dir = v.GetProperty("directory");
            byte[] id = Hb(dir.GetProperty("directory_hex").GetString()!);
            long ver = dir.GetProperty("version").GetInt64();

            Description.Directory a = DirOf(id, ver, dir.GetProperty("members_a_hex"));
            JsonElement av = dir.GetProperty("a");
            Assert.Equal(av.GetProperty("body_hex").GetString(), Hex(a.Bytes()));
            Assert.Equal(av.GetProperty("head_hex").GetString(), Hex(a.Head()));
            Assert.Equal(av.GetProperty("id_hex").GetString(), Hex(a.Id()));

            JsonElement forkV = dir.GetProperty("fork");
            Description.Directory b = DirOf(id, ver, forkV.GetProperty("members_b_hex"));
            JsonElement bv = forkV.GetProperty("b");
            Assert.Equal(bv.GetProperty("body_hex").GetString(), Hex(b.Bytes()));
            Assert.Equal(bv.GetProperty("head_hex").GetString(), Hex(b.Head()));
            Assert.Equal(bv.GetProperty("id_hex").GetString(), Hex(b.Id()));

            JsonElement lf = dir.GetProperty("length_fork");
            Description.Directory shortDir = DirOf(id, ver, lf.GetProperty("members_short_hex"));
            Assert.Equal(lf.GetProperty("body_hex").GetString(), Hex(shortDir.Bytes()));

            JsonElement dvv = dir.GetProperty("different_version");
            Description.Directory v8 = DirOf(id, dvv.GetProperty("version").GetInt64(), forkV.GetProperty("members_b_hex"));
            Assert.Equal(dvv.GetProperty("body_hex").GetString(), Hex(v8.Bytes()));
        }

        // ---- fork detection at the FIRST-DIFFERING member position ---------------------------------
        // MUTATION ANCHOR: dropping the element-comparison loop in FirstMemberDifference makes the
        // same-length fork (A vs B, member[1] differs) return fork=false, failing Assert.True(fork).

        [Fact]
        public void DirectoryForkAtPosition()
        {
            JsonElement v = Vector();
            JsonElement dir = v.GetProperty("directory");
            byte[] id = Hb(dir.GetProperty("directory_hex").GetString()!);
            long ver = dir.GetProperty("version").GetInt64();

            Description.Directory a = DirOf(id, ver, dir.GetProperty("members_a_hex"));
            Description.Directory b = DirOf(id, ver, dir.GetProperty("fork").GetProperty("members_b_hex"));
            Description.Directory shortDir = DirOf(id, ver, dir.GetProperty("length_fork").GetProperty("members_short_hex"));
            Description.Directory v8 = DirOf(id, dir.GetProperty("different_version").GetProperty("version").GetInt64(),
                dir.GetProperty("fork").GetProperty("members_b_hex"));

            (int pos, bool fork) = Description.DetectFork(a, b);
            Assert.True(fork);
            Assert.Equal(dir.GetProperty("fork").GetProperty("first_differing_position").GetInt32(), pos);

            (int lpos, bool lfork) = Description.DetectFork(a, shortDir);
            Assert.True(lfork);
            Assert.Equal(dir.GetProperty("length_fork").GetProperty("first_differing_position").GetInt32(), lpos);

            // identical members => benign duplicate, not a fork (the corpus -1 sentinel).
            (_, bool dupFork) = Description.DetectFork(a, a);
            Assert.False(dupFork);
            Assert.Equal(-1, dir.GetProperty("duplicate_first_differing_position").GetInt32()); // corpus sentinel

            // a different version is a legitimate succession, not a fork.
            (_, bool verFork) = Description.DetectFork(a, v8);
            Assert.False(verFork);

            // a different directory id is not a conflicting pair.
            Description.Directory other = DirOf(Hb("00"), ver, dir.GetProperty("members_a_hex"));
            (_, bool otherFork) = Description.DetectFork(a, other);
            Assert.False(otherFork);
        }

        // ---- Import: the attestation body + the bound foreign-id, and unknown-format rejection -----

        [Fact]
        public void ImportBodyMatchesOracle()
        {
            JsonElement v = Vector();
            JsonElement im = v.GetProperty("import");
            var imp = new Description.Import(
                Hb(im.GetProperty("importer_hex").GetString()!),
                im.GetProperty("format").GetInt64(),
                Hb(im.GetProperty("foreign_hex").GetString()!),
                OpsOf(im.GetProperty("operations")));

            Assert.Equal(im.GetProperty("body_hex").GetString(), Hex(imp.Bytes()));
            Assert.Equal(im.GetProperty("head_hex").GetString(), Hex(imp.Head()));
            Assert.Equal(im.GetProperty("id_hex").GetString(), Hex(imp.Id()));
            Assert.Equal(im.GetProperty("foreign_id_hex").GetString(), Hex(imp.ForeignId()));

            // ParseImport round-trips the body bytes.
            Description.Import parsed = Description.ParseImport(Hb(im.GetProperty("body_hex").GetString()!));
            Assert.Equal(im.GetProperty("body_hex").GetString(), Hex(parsed.Bytes()));

            // a format outside the closed naalp-description-format set {1,2,3} is rejected on decode.
            JsonElement uf = im.GetProperty("unknown_format");
            var ex = Assert.Throws<NaalpException>(() => Description.ParseImport(Hb(uf.GetProperty("body_hex").GetString()!)));
            Assert.Equal(uf.GetProperty("reject").GetString(), ex.Kind); // UnknownDescriptionFormat
        }

        // ---- offline verification + the non-repudiable directory fork-proof (REAL ML-DSA) ----------

        [Fact]
        public void OfflineVerifyAndForkProofInIsolation()
        {
            JsonElement v = Vector();
            JsonElement dir = v.GetProperty("directory");
            byte[] id = Hb(dir.GetProperty("directory_hex").GetString()!);
            long ver = dir.GetProperty("version").GetInt64();
            int wantPos = dir.GetProperty("fork").GetProperty("first_differing_position").GetInt32();

            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = 21;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            string signerId = Identity.SignerId(Alg, pk);

            Description.Directory a = DirOf(id, ver, dir.GetProperty("members_a_hex"));
            Description.Directory b = DirOf(id, ver, dir.GetProperty("fork").GetProperty("members_b_hex"));
            Description.Directory v8 = DirOf(id, dir.GetProperty("different_version").GetProperty("version").GetInt64(),
                dir.GetProperty("fork").GetProperty("members_b_hex"));
            byte[] signedA = Description.SignDirectory(a, Alg, seed);
            byte[] signedB = Description.SignDirectory(b, Alg, seed);
            byte[] signedV8 = Description.SignDirectory(v8, Alg, seed);

            // offline verification: the SAME signed bytes reconstruct the directory regardless of host.
            Description.Directory ra = Description.VerifyDirectory(signedA, Cose.PROFILE_PUBLIC, Alg, pk);
            Assert.Equal(Hex(a.Bytes()), Hex(ra.Bytes()));

            // the honest fork proof: two signed directories at (dir, ver) with differing members.
            var fp = new Description.DirectoryForkProof(Encoding.UTF8.GetBytes(signerId), signedA, signedB);
            int pos = fp.Verify(Cose.PROFILE_PUBLIC, Alg, pk);
            Assert.Equal(wantPos, pos);

            // an unnamed accused is not evidence.
            var unnamed = new Description.DirectoryForkProof(Array.Empty<byte>(), signedA, signedB);
            var uEx = Assert.Throws<NaalpException>(() => unnamed.Verify(Cose.PROFILE_PUBLIC, Alg, pk));
            Assert.Equal("DirForkProofInvalid", uEx.Kind);

            // identical members are a benign duplicate, not a fork.
            var dup = new Description.DirectoryForkProof(Encoding.UTF8.GetBytes(signerId), signedA, signedA);
            var dEx = Assert.Throws<NaalpException>(() => dup.Verify(Cose.PROFILE_PUBLIC, Alg, pk));
            Assert.Equal("DirForkProofInvalid", dEx.Kind);

            // a different version is a succession, not a fork.
            var succ = new Description.DirectoryForkProof(Encoding.UTF8.GetBytes(signerId), signedA, signedV8);
            var sEx = Assert.Throws<NaalpException>(() => succ.Verify(Cose.PROFILE_PUBLIC, Alg, pk));
            Assert.Equal("DirForkProofInvalid", sEx.Kind);

            // a signature that does not verify under the key is rejected BadSignature.
            byte[] foreignSeed = new byte[32];
            for (int i = 0; i < 32; i++) foreignSeed[i] = 99;
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", foreignSeed);
            var fEx = Assert.Throws<NaalpException>(() => fp.Verify(Cose.PROFILE_PUBLIC, Alg, foreignPk));
            Assert.Equal("BadSignature", fEx.Kind);
        }

        // ---- the confused-deputy rule: the importer is the sole authority (REAL ML-DSA) ------------

        [Fact]
        public void ImportConfusedDeputyInIsolation()
        {
            JsonElement v = Vector();
            JsonElement im = v.GetProperty("import");
            byte[] foreign = Hb(im.GetProperty("foreign_hex").GetString()!);
            List<Description.Operation> ops = OpsOf(im.GetProperty("operations"));

            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = 33;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            string signerId = Identity.SignerId(Alg, pk);

            // the importer field MUST be the wrapping signer's own self-certifying id.
            var honest = new Description.Import(Encoding.UTF8.GetBytes(signerId), Description.FormatANPDescription, foreign, ops);
            byte[] signed = Description.SignImport(honest, Alg, seed);
            Description.ResolvedImport res = Description.VerifyImport(signed, Cose.PROFILE_PUBLIC, Alg, pk);
            Assert.Equal(signerId, res.AuthorityId);                         // the authority is the wrapping key, never the foreign identity
            Assert.Equal(Hex(honest.ForeignId()), Hex(res.ForeignId));       // it binds the exact foreign bytes
            // the foreign bytes DO embed a foreign identity (did:wba:...), which never becomes the authority.
            Assert.Contains("did:wba:foreign.example:agent", Encoding.UTF8.GetString(foreign));
            Assert.NotEqual("did:wba:foreign.example:agent", res.AuthorityId);

            // a signer that names a DIFFERENT importer than its own key id can only import AS ITSELF.
            var lying = new Description.Import(Encoding.UTF8.GetBytes("did:wba:foreign.example:agent"), Description.FormatANPDescription, foreign, ops);
            byte[] signedLie = Description.SignImport(lying, Alg, seed);
            var ex = Assert.Throws<NaalpException>(() => Description.VerifyImport(signedLie, Cose.PROFILE_PUBLIC, Alg, pk));
            Assert.Equal("ImporterMismatch", ex.Kind);
        }
    }
}
