// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Naalp
{
    /// <summary>
    /// C18 — the signed description / directory primitive for the C# SDK (design.md §21; R-DESC-1..8),
    /// ported from impl/go/description and cross-checked against impl/python/naalp/description.py.
    ///
    /// <para>C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own
    /// signed object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the
    /// connection or the host that served them: the same signed description re-verifies byte-identically
    /// when an unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority.
    /// It introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each
    /// object is an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice
    /// (<see cref="Policy"/>) and the T1 content-id framing (§2.3) unchanged.</para>
    ///
    /// <para>Three wire objects: <see cref="Doc"/> {1: service, 2: operations[]} (a service's operation
    /// table); <see cref="Directory"/> {1: directory, 2: version, 3: members[]} (a signed collection of
    /// content ids, whose two conflicting versions from ONE signer are a FORK detected at the
    /// FIRST-DIFFERING member position); and <see cref="Import"/> {1: importer, 2: format, 3: foreign,
    /// 4: operations[]} (a foreign description carried octet-for-octet as a signed attestation, whose
    /// IMPORTER — recomputed self-certifyingly from the verifying key — is the SOLE authorization
    /// identity; a foreign identity embedded in the foreign bytes never authorizes, R-14.6).</para>
    ///
    /// <para>Every check is fail-closed (§15). The byte surface (bodies, heads, content ids, foreign-id
    /// binding, fork position, closed foreign-format rejection) is graded against
    /// vectors/description/cases.json; the offline-verification, fork-proof, and confused-deputy paths
    /// use real deterministic ML-DSA-65 and are demonstrated in isolation (the corpus carries no signed
    /// vector).</para>
    ///
    /// <para>Deviation from the Go reference, honest F4 note: Go's VerifyImport carries a
    /// VerifierKeyMismatch guard because it takes BOTH an (alg, pubkey) pair AND a separate cose.Verifier
    /// and must bind them before deriving the authority id. This C# port — like the Python/Kotlin ports
    /// and the sibling <see cref="Gateway.VerifyDecision"/> — verifies with a SINGLE (alg, pubkey) pair,
    /// so the authority id is ALWAYS derived from exactly the key that verified the signature; the
    /// mismatch that guard prevents is structurally impossible here. There is no VerifierKeyMismatch
    /// surface to port: it is absent because the vulnerability it guards cannot arise in this signature,
    /// NOT silently dropped.</para>
    /// </summary>
    public static class Description
    {
        /// <summary>The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 chain.</summary>
        public const int HeadSize = 48;

        // Foreign description format codes (design §21; the closed naalp-description-format registry).
        public const long FormatA2ACard = 1;        // A2A Agent Card
        public const long FormatANPDescription = 2; // ANP Agent Description
        public const long FormatAGNTCYBadge = 3;    // AGNTCY Agent Badge

        private static bool IsKnownFormat(long f)
            => f == FormatA2ACard || f == FormatANPDescription || f == FormatAGNTCYBadge;

        private static byte[] Head(byte[] b) => SHA384.HashData(b);

        private static byte[] ContentIdOf(byte[] b) => Cbor.ContentId(b);

        // ---- Operation: one listed operation with its effect + approval declaration (§21.2) --------

        /// <summary>One entry of a <see cref="Doc"/> or an <see cref="Import"/> mapping: a named
        /// operation, its C5 effect class, and whether it requires an approval. RequiresApproval is the
        /// uint 1 (yes) / 0 (no) — the spine carries no CBOR boolean (design §3.1).</summary>
        public sealed class Operation
        {
            public readonly string Name;
            public readonly long Effect;
            public readonly long RequiresApproval;

            public Operation(string name, long effect, long requiresApproval)
            {
                Name = name;
                Effect = effect;
                RequiresApproval = requiresApproval;
            }

            internal Cbor.M ToMap()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Name)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Effect)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(RequiresApproval)),
                });
            }

            /// <summary>Deterministic-CBOR encoding of the operation body {1:name,2:effect,3:requires_approval}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToMap());

            /// <summary>The per-operation effect, normalized fail-closed: an unrecognized value is destructive.</summary>
            public long EffectClass() => Policy.NormalizeEffect(Effect);

            /// <summary>True iff the operation declares that it requires an approval.</summary>
            public bool RequiresApprovalFlag() => RequiresApproval == 1;
        }

        private static Operation OperationFromValue(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("DescMalformed", "operation is not a map");
            }
            string? name = null;
            long? effect = null, req = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("DescMalformed", "non-uint operation key");
                }
                if (ku.V == 1 && p.Val is Cbor.T t) name = t.V;
                else if (ku.V == 2 && p.Val is Cbor.U e) effect = e.V;
                else if (ku.V == 3 && p.Val is Cbor.U r) req = r.V;
            }
            if (name == null || effect == null || req == null)
            {
                throw new NaalpException("DescMalformed", "operation missing a mandatory field");
            }
            if (req.Value > 1)
            {
                throw new NaalpException("MalformedApprovalFlag", "requires_approval is outside {0,1}");
            }
            return new Operation(name, effect.Value, req.Value);
        }

        private static List<Operation> OperationsFromValue(Cbor.Value v)
        {
            if (!(v is Cbor.A arr))
            {
                throw new NaalpException("DescMalformed", "operations is not an array");
            }
            var ops = new List<Operation>(arr.Items.Count);
            foreach (Cbor.Value e in arr.Items)
            {
                ops.Add(OperationFromValue(e));
            }
            return ops;
        }

        private static Cbor.A OperationsValue(List<Operation> ops)
        {
            var items = new List<Cbor.Value>(ops.Count);
            foreach (Operation op in ops)
            {
                items.Add(op.ToMap());
            }
            return new Cbor.A(items);
        }

        private static bool FindOperation(List<Operation> ops, string name, out Operation found)
        {
            foreach (Operation op in ops)
            {
                if (op.Name == name)
                {
                    found = op;
                    return true;
                }
            }
            found = null!;
            return false;
        }

        // ---- Doc: a service's signed operation table (§21.2) --------------------------------------

        /// <summary>The naalp-description wire object: a signed N-AALP object listing a service's
        /// operations. Its authority is in the signed bytes: <see cref="ParseDescription"/> reconstructs
        /// the whole operation table from the bytes alone, so an unrelated host serving the same bytes
        /// yields a byte-identical verification (offline-verifiable, not fetch-authenticated).</summary>
        public sealed class Doc
        {
            public readonly byte[] Service;
            public readonly List<Operation> Operations;

            public Doc(byte[] service, List<Operation> operations)
            {
                Service = (byte[])service.Clone();
                Operations = operations;
            }

            /// <summary>Deterministic-CBOR encoding {1: service, 2: operations[]}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Service)),
                    new Cbor.Pair(new Cbor.U(2), OperationsValue(Operations)),
                }));
            }

            /// <summary>The Doc's SHA-384 head (48 octets).</summary>
            public byte[] Head() => Description.Head(Bytes());

            /// <summary>The Doc's T1 content-id (50 octets).</summary>
            public byte[] Id() => ContentIdOf(Bytes());

            /// <summary>The named operation and whether it is listed.</summary>
            public bool Operation(string name, out Operation op) => FindOperation(Operations, name, out op);
        }

        /// <summary>Reconstruct a Doc from its body bytes ALONE — the offline-verifiable property.</summary>
        public static Doc ParseDescription(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            if (!BstrField(m, 1, out byte[] svc) || !Field(m, 2, out Cbor.Value opsV))
            {
                throw new NaalpException("DescMalformed", "description missing service or operations");
            }
            return new Doc(svc, OperationsFromValue(opsV));
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the Doc body.</summary>
        public static byte[] SignDescription(Doc d, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), d.Bytes());

        /// <summary>Verify the Doc's full signature under the profile, then reconstruct the operation
        /// table from the signed body bytes. Because the authority is the signature over the bytes, this
        /// returns the identical Doc regardless of which host served <paramref name="obj"/> (R-DESC-1).</summary>
        public static Doc VerifyDescription(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifySign1(obj, profile, alg, pubkey);
            return ParseDescription(payload);
        }

        // ---- Directory: a signed collection of content ids, with fork detection (§21.3) -----------

        /// <summary>A signed collection object whose members are content ids. It carries a monotonic
        /// per-signer version so two versions can be compared for equivocation.</summary>
        public sealed class Directory
        {
            public readonly byte[] DirectoryId; // the opaque directory identifier (body field 1)
            public readonly long Version;
            public readonly List<byte[]> Members;

            public Directory(byte[] directory, long version, List<byte[]> members)
            {
                DirectoryId = (byte[])directory.Clone();
                Version = version;
                Members = members;
            }

            /// <summary>Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}.</summary>
            public byte[] Bytes()
            {
                var items = new List<Cbor.Value>(Members.Count);
                foreach (byte[] m in Members)
                {
                    items.Add(new Cbor.B(m));
                }
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(DirectoryId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Version)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.A(items)),
                }));
            }

            /// <summary>The Directory's SHA-384 head (48 octets).</summary>
            public byte[] Head() => Description.Head(Bytes());

            /// <summary>The Directory's T1 content-id (50 octets).</summary>
            public byte[] Id() => ContentIdOf(Bytes());
        }

        /// <summary>Reconstruct a Directory from its body bytes alone.</summary>
        public static Directory ParseDirectory(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            if (!BstrField(m, 1, out byte[] did) || !UintField(m, 2, out long ver) || !Field(m, 3, out Cbor.Value memV))
            {
                throw new NaalpException("DescMalformed", "directory missing or malformed field");
            }
            if (!(memV is Cbor.A arr))
            {
                throw new NaalpException("DescMalformed", "members is not an array");
            }
            var members = new List<byte[]>(arr.Items.Count);
            foreach (Cbor.Value e in arr.Items)
            {
                if (!(e is Cbor.B bs))
                {
                    throw new NaalpException("DescMalformed", "member is not a bstr");
                }
                members.Add(bs.V);
            }
            return new Directory(did, ver, members);
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the Directory body.</summary>
        public static byte[] SignDirectory(Directory d, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), d.Bytes());

        /// <summary>Verify the Directory's full signature under the profile, then reconstruct it from
        /// the signed body bytes.</summary>
        public static Directory VerifyDirectory(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifySign1(obj, profile, alg, pubkey);
            return ParseDirectory(payload);
        }

        /// <summary>The first index at which two member lists differ, and whether they differ at all. If
        /// the lists share a common prefix and one is longer, the difference is reported at the length of
        /// the shorter list. Identical lists return (0, false).</summary>
        public static (int Position, bool Differ) FirstMemberDifference(List<byte[]> a, List<byte[]> b)
        {
            int n = Math.Min(a.Count, b.Count);
            for (int i = 0; i < n; i++)
            {
                if (!BytesEqual(a[i], b[i]))
                {
                    return (i, true);
                }
            }
            if (a.Count != b.Count)
            {
                return (n, true);
            }
            return (0, false);
        }

        /// <summary>Compare two directory versions from ONE signer and report whether they equivocate —
        /// the SAME directory id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING
        /// member POSITION (as the §8.5 audit fork-proof reports the position of an equivocation). A
        /// different directory id or version is a legitimate distinct object/succession, not a fork;
        /// identical members are a benign duplicate. In both non-fork cases returns (0, false). The
        /// caller establishes the "one signer" precondition by verifying both objects under the same
        /// key.</summary>
        public static (int Position, bool Fork) DetectFork(Directory a, Directory b)
        {
            if (!BytesEqual(a.DirectoryId, b.DirectoryId) || a.Version != b.Version)
            {
                return (0, false); // different directory or version — not a conflicting pair
            }
            return FirstMemberDifference(a.Members, b.Members);
        }

        /// <summary>Non-repudiable evidence of a directory fork: two validly-signed Directory objects by
        /// ONE signer at the SAME (directory, version) listing DIFFERENT members, carried as the accused
        /// signer's OWN two signed objects. Because a single verifier checks BOTH signed objects, the
        /// proof is self-contained.</summary>
        public sealed class DirectoryForkProof
        {
            public readonly byte[] Signer;
            public readonly byte[] SignedA;
            public readonly byte[] SignedB;

            public DirectoryForkProof(byte[] signer, byte[] signedA, byte[] signedB)
            {
                Signer = (byte[])signer.Clone();
                SignedA = (byte[])signedA.Clone();
                SignedB = (byte[])signedB.Clone();
            }

            /// <summary>Check that this is a genuine directory fork by the signer whose key is (alg,
            /// pubkey), and return the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the
            /// signer id is present; (2) BOTH signed objects verify under the key (which, because a
            /// single verifier checks both, proves one signer); (3) the two directories share one
            /// directory id and version; and (4) their member lists differ. Any failure rejects the
            /// whole proof (fail-closed): an unnamed signer, a different directory/version, or identical
            /// members is DirForkProofInvalid; a signature that does not verify propagates
            /// BadSignature.</summary>
            public int Verify(int profile, int alg, byte[] pubkey)
            {
                if (Signer.Length == 0)
                {
                    throw new NaalpException("DirForkProofInvalid", "an unnamed accused is not evidence");
                }
                Directory a = VerifyDirectory(SignedA, profile, alg, pubkey);
                Directory b = VerifyDirectory(SignedB, profile, alg, pubkey);
                (int pos, bool fork) = DetectFork(a, b);
                if (!fork)
                {
                    throw new NaalpException("DirForkProofInvalid",
                        "same directory+version identical members, or not the same versioned directory");
                }
                return pos;
            }
        }

        // ---- Import: foreign description carried as a signed attestation (§21.4) -------------------

        /// <summary>Carries a foreign description format octet-for-octet (carriage, not adoption) as a
        /// signed N-AALP attestation. Importer is the wrapping signer id (the sole authorization
        /// identity); Foreign is the foreign bytes verbatim; Operations is the N-AALP effect mapping the
        /// importer attests. The foreign bytes' content id is bound by <see cref="ForeignId"/>.</summary>
        public sealed class Import
        {
            public readonly byte[] Importer;
            public readonly long Format;
            public readonly byte[] Foreign;
            public readonly List<Operation> Operations;

            public Import(byte[] importer, long format, byte[] foreign, List<Operation> operations)
            {
                Importer = (byte[])importer.Clone();
                Format = format;
                Foreign = (byte[])foreign.Clone();
                Operations = operations;
            }

            /// <summary>Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Importer)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Format)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(Foreign)),
                    new Cbor.Pair(new Cbor.U(4), OperationsValue(Operations)),
                }));
            }

            /// <summary>The Import attestation's own SHA-384 head (48 octets).</summary>
            public byte[] Head() => Description.Head(Bytes());

            /// <summary>The Import attestation's own T1 content-id (50 octets).</summary>
            public byte[] Id() => ContentIdOf(Bytes());

            /// <summary>The T1 content-id of the carried foreign bytes — the hash the attestation binds.
            /// A changed foreign document yields a different ForeignId, so an attestation binds the exact
            /// bytes it attested.</summary>
            public byte[] ForeignId() => ContentIdOf(Foreign);

            /// <summary>The named operation from the attested mapping and whether it is listed.</summary>
            public bool Operation(string name, out Operation op) => FindOperation(Operations, name, out op);
        }

        /// <summary>Reconstruct an Import from its body bytes alone. A format code outside the closed
        /// naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never
        /// carried as an unknown format. Fail-closed.</summary>
        public static Import ParseImport(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            if (!BstrField(m, 1, out byte[] imp) || !UintField(m, 2, out long fmt)
                || !BstrField(m, 3, out byte[] foreign) || !Field(m, 4, out Cbor.Value opsV))
            {
                throw new NaalpException("DescMalformed", "import missing a mandatory field");
            }
            if (!IsKnownFormat(fmt))
            {
                throw new NaalpException("UnknownDescriptionFormat",
                    "import format " + fmt + " is outside the closed set {1,2,3}");
            }
            return new Import(imp, fmt, foreign, OperationsFromValue(opsV));
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the Import body.</summary>
        public static byte[] SignImport(Import im, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), im.Bytes());

        /// <summary>An Import that has passed signature verification and the confused-deputy check.
        /// AuthorityId is the self-certifying signer id RECOMPUTED from the verifying key — the wrapping
        /// signer, and the only authorization identity. It is never any identity parsed from the foreign
        /// bytes.</summary>
        public sealed class ResolvedImport
        {
            public readonly string AuthorityId;
            public readonly long Format;
            public readonly byte[] ForeignId;
            public readonly List<Operation> Operations;

            public ResolvedImport(string authorityId, long format, byte[] foreignId, List<Operation> operations)
            {
                AuthorityId = authorityId;
                Format = format;
                ForeignId = foreignId;
                Operations = operations;
            }
        }

        /// <summary>Verify a foreign-description import end-to-end and enforce the confused-deputy rule
        /// normatively. It (1) verifies the signed object under the profile with real crypto; (2)
        /// recomputes the wrapping signer's SELF-CERTIFYING id from the verifying key
        /// (<see cref="Identity.SignerId"/>); and (3) requires the attestation's importer field to equal
        /// that recomputed id (ImporterMismatch otherwise). The returned AuthorityId is that recomputed
        /// key id — the wrapping signer — so no field inside the carried foreign bytes, including any
        /// foreign identity claim, can ever become the N-AALP authorization identity (R-14.6). Any
        /// failure throws its named error and authorizes nothing (fail-closed).</summary>
        public static ResolvedImport VerifyImport(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifySign1(obj, profile, alg, pubkey);
            Import im = ParseImport(payload);
            string keyId = Identity.SignerId(alg, pubkey);
            // The authorization identity is the wrapping key's own id. The attestation's declared
            // importer MUST match it: a signer can only ever import AS ITSELF, never as a foreign
            // identity it names.
            if (Identity.Utf8(im.Importer) != keyId)
            {
                throw new NaalpException("ImporterMismatch", "the attested importer is not the verifying key's signer id");
            }
            return new ResolvedImport(keyId, im.Format, im.ForeignId(), im.Operations);
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
                throw new NaalpException("DescMalformed", "protected header is malformed");
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
            throw new NaalpException("DescMalformed", "protected header has no alg");
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
                throw new NaalpException("DescMalformed", "malformed COSE object");
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

        // ---- small deterministic-CBOR field accessors ---------------------------------------------

        private static Cbor.M DecodeMap(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("DescMalformed", "body is not well-formed deterministic CBOR");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("DescMalformed", "body is not a map");
            }
            return m;
        }

        private static bool Field(Cbor.M m, long k, out Cbor.Value v)
        {
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == k)
                {
                    v = p.Val;
                    return true;
                }
            }
            v = null!;
            return false;
        }

        private static bool BstrField(Cbor.M m, long k, out byte[] v)
        {
            if (Field(m, k, out Cbor.Value fv) && fv is Cbor.B b)
            {
                v = b.V;
                return true;
            }
            v = null!;
            return false;
        }

        private static bool UintField(Cbor.M m, long k, out long v)
        {
            if (Field(m, k, out Cbor.Value fv) && fv is Cbor.U u)
            {
                v = u.V;
                return true;
            }
            v = 0;
            return false;
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
