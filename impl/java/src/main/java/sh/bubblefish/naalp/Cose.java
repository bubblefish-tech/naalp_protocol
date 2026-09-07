// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.MLDSASigner;

/**
 * N-AALP C2 signing layer for the Java SDK: the COSE_Sign1 (RFC 9052) signing-input and object
 * assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).
 *
 * <p>The deterministic ML-DSA path uses Bouncy Castle's {@link MLDSASigner} initialised WITHOUT a
 * {@code ParametersWithRandom}, so the FIPS 204 {@code rnd} stays 32 zero bytes — byte-identical to
 * the Go (CIRCL), Rust (fips204) and Python (dilithium-py) reference implementations. Key material
 * is derived from the 32-byte NIST seed (xi) via the seed-only private-key constructor, so the
 * public key equals the NIST ACVP keyGen vector.
 */
public final class Cose {
    public static final int ALG_MLDSA65 = -49;
    public static final int ALG_MLDSA87 = -50;
    public static final int ALG_ED25519 = -19;

    /** N-AALP protection profiles (§2.5): Public, Enterprise, Sovereign. */
    public static final int PROFILE_PUBLIC = 1;
    public static final int PROFILE_ENTERPRISE = 2;
    public static final int PROFILE_SOVEREIGN = 3;

    public static final long TAG_SIGN1 = 18;

    private Cose() {}

    /** The NIST security level of a registered alg, plus whether it is registered at all. */
    public static final class AlgLevel {
        public final int level;
        public final boolean known;
        AlgLevel(int level, boolean known) {
            this.level = level;
            this.known = known;
        }
    }

    /**
     * NIST security level of a registered alg (ML-DSA-87 = 5, ML-DSA-65 = 3, Ed25519 = 0, a
     * classical hybrid leg), and whether the alg is registered at all (§2.5 / C2 registry).
     */
    public static AlgLevel algLevel(int alg) {
        if (alg == ALG_MLDSA87) {
            return new AlgLevel(5, true);
        }
        if (alg == ALG_MLDSA65) {
            return new AlgLevel(3, true);
        }
        if (alg == ALG_ED25519) {
            return new AlgLevel(0, true);
        }
        return new AlgLevel(0, false);
    }

    /** Minimum signature level a profile accepts (Sovereign floors at level 5; else 3). */
    public static int profileMinLevel(int profile) {
        return profile == PROFILE_SOVEREIGN ? 5 : 3;
    }

    /** The RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header. */
    public static byte[] toBeSignedRaw(byte[] protectedHeader, byte[] payload) {
        return Cbor.encode(new Cbor.A(List.of(
                new Cbor.T("Signature1"),
                new Cbor.B(protectedHeader),
                new Cbor.B(new byte[0]),
                new Cbor.B(payload))));
    }

    /** The tagged COSE_Sign1 object: 18([protected, {}, payload, signature]). */
    public static byte[] assembleSign1Raw(byte[] protectedHeader, byte[] payload, byte[] sig) {
        return Cbor.encode(new Cbor.Tag(TAG_SIGN1, new Cbor.A(List.of(
                new Cbor.B(protectedHeader),
                new Cbor.M(List.of()),
                new Cbor.B(payload),
                new Cbor.B(sig)))));
    }

    /** Recover [protected, payload, sig] from a tagged COSE_Sign1 object. */
    public static byte[][] parseSign1Raw(byte[] obj) {
        Cbor.Value v = Cbor.decode(obj);
        if (!(v instanceof Cbor.Tag tag) || tag.n != TAG_SIGN1 || !(tag.content instanceof Cbor.A arr)) {
            throw new NaalpException("Malformed", "not a tagged COSE_Sign1");
        }
        List<Cbor.Value> items = arr.items;
        if (items.size() != 4 || !(items.get(0) instanceof Cbor.B p)
                || !(items.get(2) instanceof Cbor.B pl) || !(items.get(3) instanceof Cbor.B s)) {
            throw new NaalpException("Malformed", "malformed COSE_Sign1 array");
        }
        return new byte[][]{p.v, pl.v, s.v};
    }

    // --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

    public static final long TAG_SIGN = 98;

    /** One COSE_Signature protected header: {1: alg} (RFC 9052 §4). */
    public static byte[] legProtected(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    /**
     * The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
     * det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note the
     * five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
     * "Signature1" of a COSE_Sign1.
     */
    public static byte[] signatureToBeSigned(byte[] bodyProt, int signerAlg, byte[] payload) {
        return Cbor.encode(new Cbor.A(List.of(
                new Cbor.T("Signature"),
                new Cbor.B(bodyProt),
                new Cbor.B(legProtected(signerAlg)),
                new Cbor.B(new byte[0]),
                new Cbor.B(payload))));
    }

    /** Build one COSE_Signature leg: [leg_protected_bytes, signature_bytes]. */
    public static byte[][] signatureLeg(byte[] bodyProt, int alg, byte[] seed, byte[] payload) {
        byte[] sprot = legProtected(alg);
        byte[] sig = mldsaSign(alg, seed, signatureToBeSigned(bodyProt, alg, payload));
        return new byte[][]{sprot, sig};
    }

    /** The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]). */
    public static byte[] assembleSignRaw(byte[] bodyProt, byte[] payload, List<byte[][]> legs) {
        List<Cbor.Value> sigArr = new java.util.ArrayList<>();
        for (byte[][] leg : legs) {
            sigArr.add(new Cbor.A(List.of(new Cbor.B(leg[0]), new Cbor.M(List.of()), new Cbor.B(leg[1]))));
        }
        return Cbor.encode(new Cbor.Tag(TAG_SIGN, new Cbor.A(List.of(
                new Cbor.B(bodyProt), new Cbor.M(List.of()), new Cbor.B(payload), new Cbor.A(sigArr)))));
    }

    /** A parsed tag-98 COSE_Sign: body protected header, payload, and ordered [sprot, sig] legs. */
    public static final class RotationParse {
        public final byte[] bodyProt;
        public final byte[] payload;
        public final List<byte[][]> legs;
        RotationParse(byte[] bodyProt, byte[] payload, List<byte[][]> legs) {
            this.bodyProt = bodyProt;
            this.payload = payload;
            this.legs = legs;
        }
    }

    /** Recover the body protected header, payload, and ordered legs from a tagged COSE_Sign object. */
    public static RotationParse parseSignRaw(byte[] obj) {
        Cbor.Value v = Cbor.decode(obj);
        if (!(v instanceof Cbor.Tag tag) || tag.n != TAG_SIGN || !(tag.content instanceof Cbor.A arr)) {
            throw new NaalpException("Malformed", "not a tagged COSE_Sign");
        }
        List<Cbor.Value> items = arr.items;
        if (items.size() != 4 || !(items.get(0) instanceof Cbor.B bp)
                || !(items.get(2) instanceof Cbor.B pl) || !(items.get(3) instanceof Cbor.A sigs)) {
            throw new NaalpException("Malformed", "malformed COSE_Sign array");
        }
        List<byte[][]> legs = new java.util.ArrayList<>();
        for (Cbor.Value sv : sigs.items) {
            if (!(sv instanceof Cbor.A e) || e.items.size() != 3
                    || !(e.items.get(0) instanceof Cbor.B sprot) || !(e.items.get(2) instanceof Cbor.B lsig)) {
                throw new NaalpException("Malformed", "malformed COSE_Signature leg");
            }
            legs.add(new byte[][]{sprot.v, lsig.v});
        }
        return new RotationParse(bp.v, pl.v, legs);
    }

    /** Extract the alg (label 1) value from a serialized leg protected header {1: alg}. */
    public static int algFromProtected(byte[] prot) {
        // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
        // wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
        // before interpreting the header — the empty protected header is pinned to 0x40.
        if (prot.length == 1 && (prot[0] & 0xFF) == 0xA0) {
            throw new NaalpException("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)");
        }
        Cbor.Value v = Cbor.decode(prot);
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("Malformed", "protected header not a map");
        }
        for (Cbor.Pair pr : m.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == 1 && pr.val instanceof Cbor.N n) {
                return (int) n.v;
            }
        }
        throw new NaalpException("Malformed", "no alg in protected header");
    }

    // --- ML-DSA (FIPS 204) ---

    private static MLDSAParameters mldsaParams(int alg) {
        if (alg == ALG_MLDSA65) {
            return MLDSAParameters.ml_dsa_65;
        }
        if (alg == ALG_MLDSA87) {
            return MLDSAParameters.ml_dsa_87;
        }
        throw new NaalpException("UnknownAlg", "alg " + alg + " is not an ML-DSA algorithm");
    }

    /** Derive the public key from a 32-byte seed (NIST ACVP keyGen); returns pk bytes. */
    public static byte[] mldsaKeygen(String param, byte[] seed) {
        MLDSAParameters p = "ML-DSA-87".equals(param) ? MLDSAParameters.ml_dsa_87 : MLDSAParameters.ml_dsa_65;
        if (seed.length != 32) {
            throw new NaalpException("Malformed", "ML-DSA seed must be 32 bytes");
        }
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(p, seed);
        return sk.getPublicKey();
    }

    /** Deterministic (rnd=0) ML-DSA signature over tbs with the key derived from seed. */
    public static byte[] mldsaSign(int alg, byte[] seed, byte[] tbs) {
        MLDSAParameters p = mldsaParams(alg);
        if (seed.length != 32) {
            throw new NaalpException("Malformed", "ML-DSA seed must be 32 bytes");
        }
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(p, seed);
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, sk); // no ParametersWithRandom -> rnd = 32 zero bytes (deterministic)
        signer.update(tbs, 0, tbs.length);
        try {
            return signer.generateSignature();
        } catch (Exception e) {
            throw new NaalpException("SignFailed", e.toString());
        }
    }

    public static boolean mldsaVerify(int alg, byte[] pk, byte[] tbs, byte[] sig) {
        MLDSAParameters p = mldsaParams(alg);
        MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(p, pk);
        MLDSASigner signer = new MLDSASigner();
        signer.init(false, pub);
        signer.update(tbs, 0, tbs.length);
        return signer.verifySignature(sig);
    }

    // --- Ed25519 (RFC 8032) ---

    public static byte[] ed25519Sign(byte[] seed, byte[] msg) {
        if (seed.length != 32) {
            throw new NaalpException("Malformed", "ed25519 secret key must be a 32-byte seed");
        }
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(seed, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, priv);
        signer.update(msg, 0, msg.length);
        return signer.generateSignature();
    }

    public static boolean ed25519Verify(byte[] pk, byte[] msg, byte[] sig) {
        if (pk.length != 32) {
            return false;
        }
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(pk, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, pub);
        signer.update(msg, 0, msg.length);
        return signer.verifySignature(sig);
    }

    // --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

    public static final int ALG_COMPOSITE_65_ED25519 = -65537; // COMPSIG-MLDSA65-Ed25519-SHA512
    public static final int ALG_COMPOSITE_44_ED25519 = -65538; // edge; RESERVED, not implemented
    private static final byte[] COMPOSITE_PREFIX =
            "CompositeAlgorithmSignatures2025".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] COMPOSITE_LABEL_MLDSA65_ED25519 =
            "COMPSIG-MLDSA65-Ed25519-SHA512".getBytes(StandardCharsets.US_ASCII);
    private static final int MLDSA65_SIG_SIZE = 3309;   // FIPS 204 ML-DSA-65 signature size
    public static final int MLDSA65_PUB_SIZE = 1952;    // FIPS 204 ML-DSA-65 pubkey size (split point)

    /**
     * The LAMPS composite message representative M' = Prefix || Label || len(ctx) || ctx ||
     * SHA-512(M) (design.md §4.2). len(ctx) is a single length octet; the N-AALP composite context
     * is empty, so the octet is 0x00. Both legs sign this same M'.
     */
    public static byte[] computeMprime(byte[] label, byte[] ctx, byte[] m) {
        if (ctx.length > 255) {
            throw new NaalpException("Malformed", "composite context exceeds one length octet");
        }
        byte[] h;
        try {
            h = MessageDigest.getInstance("SHA-512").digest(m);
        } catch (Exception e) {
            throw new NaalpException("HashFailed", e.toString());
        }
        byte[] out = new byte[COMPOSITE_PREFIX.length + label.length + 1 + ctx.length + h.length];
        int o = 0;
        System.arraycopy(COMPOSITE_PREFIX, 0, out, o, COMPOSITE_PREFIX.length);
        o += COMPOSITE_PREFIX.length;
        System.arraycopy(label, 0, out, o, label.length);
        o += label.length;
        out[o++] = (byte) ctx.length;               // len(ctx) as a single length octet
        System.arraycopy(ctx, 0, out, o, ctx.length);
        o += ctx.length;
        System.arraycopy(h, 0, out, o, h.length);
        return out;
    }

    /**
     * The LAMPS composite signature value over the COSE ToBeSigned tbs: mldsaSig || tradSig
     * (ML-DSA-65 first, raw concatenation; design.md §4.2). The ML-DSA leg is deterministic (no
     * ParametersWithRandom => rnd=0) with context = the suite Label octets (via
     * ParametersWithContext); the Ed25519 leg signs M' with no context.
     */
    public static byte[] compositeSign(byte[] mldsaSeed, byte[] edSeed, byte[] tbs) {
        if (mldsaSeed.length != 32) {
            throw new NaalpException("Malformed", "ML-DSA seed must be 32 bytes");
        }
        byte[] mprime = computeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, new byte[0], tbs);
        MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, mldsaSeed);
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithContext(sk, COMPOSITE_LABEL_MLDSA65_ED25519));
        signer.update(mprime, 0, mprime.length);
        byte[] mldsaSig;
        try {
            mldsaSig = signer.generateSignature();
        } catch (Exception e) {
            throw new NaalpException("SignFailed", e.toString());
        }
        byte[] tradSig = ed25519Sign(edSeed, mprime);
        byte[] out = new byte[mldsaSig.length + tradSig.length];
        System.arraycopy(mldsaSig, 0, out, 0, mldsaSig.length);   // ML-DSA first (LAMPS order)
        System.arraycopy(tradSig, 0, out, mldsaSig.length, tradSig.length);
        return out;
    }

    /**
     * Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context) validate
     * over M'. A value of the wrong length is malformed and rejected. A stripped or re-interpreted
     * lone leg has no valid composite because M' binds both components (RFC 9955; §4.2/§4.5).
     */
    public static boolean compositeVerify(byte[] mldsaPk, byte[] edPk, byte[] m, byte[] sig) {
        if (sig.length != MLDSA65_SIG_SIZE + 64) {
            return false;
        }
        byte[] mprime = computeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, new byte[0], m);
        MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, mldsaPk);
        MLDSASigner signer = new MLDSASigner();
        signer.init(false, new ParametersWithContext(pub, COMPOSITE_LABEL_MLDSA65_ED25519));
        signer.update(mprime, 0, mprime.length);
        boolean mldsaOk = signer.verifySignature(Arrays.copyOfRange(sig, 0, MLDSA65_SIG_SIZE));
        boolean edOk = ed25519Verify(edPk, mprime, Arrays.copyOfRange(sig, MLDSA65_SIG_SIZE, sig.length));
        return mldsaOk && edOk;
    }

    /** Produce a deterministic tagged COSE_Sign1 object over (protected, payload). */
    public static byte[] coseSign1(int alg, byte[] seed, byte[] protectedHeader, byte[] payload) {
        byte[] tbs = toBeSignedRaw(protectedHeader, payload);
        byte[] sig = mldsaSign(alg, seed, tbs);
        return assembleSign1Raw(protectedHeader, payload, sig);
    }

    /** Verify a raw signature over already-assembled ToBeSigned bytes, dispatching by alg. */
    public static boolean coseVerify1Raw(int alg, byte[] pk, byte[] tbs, byte[] sig) {
        if (alg == ALG_MLDSA65 || alg == ALG_MLDSA87) {
            return mldsaVerify(alg, pk, tbs, sig);
        }
        if (alg == ALG_ED25519) {
            return ed25519Verify(pk, tbs, sig);
        }
        throw new NaalpException("UnknownAlg", "unknown alg " + alg);
    }

    public static boolean coseVerify1(int alg, byte[] pk, byte[] obj) {
        byte[][] parts = parseSign1Raw(obj);
        byte[] tbs = toBeSignedRaw(parts[0], parts[1]);
        return coseVerify1Raw(alg, pk, tbs, parts[2]);
    }
}
