// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.List;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
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
