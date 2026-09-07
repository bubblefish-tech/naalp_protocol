// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;

/**
 * N-AALP C4 identity for the Java SDK: the self-certifying signer id (§5.1) and the NFC rule.
 *
 * <p>signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
 * identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats registry:
 * ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12. The
 * multibase prefix is 'b' (base32 lowercase, no padding).
 */
public final class Identity {
    private static final int MH_SHA256 = 0x12;
    private static final char[] B32 = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();

    private Identity() {}

    private static int multicodec(int alg) {
        switch (alg) {
            case Cose.ALG_ED25519:
                return 0xED;
            case Cose.ALG_MLDSA65:
                return 0x1211;
            case Cose.ALG_MLDSA87:
                return 0x1212;
            default:
                throw new NaalpException("UnknownAlg", "no multicodec for alg " + alg);
        }
    }

    /** LEB128 unsigned varint. */
    static byte[] uvarint(int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long v = n & 0xFFFFFFFFL;
        while (true) {
            int b = (int) (v & 0x7F);
            v >>>= 7;
            if (v != 0) {
                out.write(b | 0x80);
            } else {
                out.write(b);
                break;
            }
        }
        return out.toByteArray();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Base32 (RFC 4648) lowercase, no padding. */
    static String base32NoPad(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(B32[(buffer >>> bits) & 0x1F]);
            }
        }
        if (bits > 0) {
            sb.append(B32[(buffer << (5 - bits)) & 0x1F]);
        }
        return sb.toString();
    }

    /** The self-certifying signer id for (alg, pubkey). */
    public static String signerId(int alg, byte[] pubkey) {
        int mc = multicodec(alg);
        byte[] mcv = uvarint(mc);
        byte[] tagged = new byte[mcv.length + pubkey.length];
        System.arraycopy(mcv, 0, tagged, 0, mcv.length);
        System.arraycopy(pubkey, 0, tagged, mcv.length, pubkey.length);
        byte[] digest = sha256().digest(tagged);
        byte[] mhCode = uvarint(MH_SHA256);
        byte[] mhLen = uvarint(digest.length);
        byte[] mh = new byte[mhCode.length + mhLen.length + digest.length];
        System.arraycopy(mhCode, 0, mh, 0, mhCode.length);
        System.arraycopy(mhLen, 0, mh, mhCode.length, mhLen.length);
        System.arraycopy(digest, 0, mh, mhCode.length + mhLen.length, digest.length);
        return "b" + base32NoPad(mh);
    }

    /**
     * The self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
     * multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public
     * key — using only existing official multicodecs (no minted code) — so stripping or substituting
     * either leg changes the id (=> SignerMismatch before verify). Downgrade-resistant.
     */
    public static String compositeSignerId(int mldsaAlg, byte[] mldsaPub, byte[] edPub) {
        if (mldsaAlg != Cose.ALG_MLDSA65 && mldsaAlg != Cose.ALG_MLDSA87) {
            throw new NaalpException("UnknownAlg", "composite signer id requires an ML-DSA alg, got " + mldsaAlg);
        }
        byte[] mcMl = uvarint(multicodec(mldsaAlg));
        byte[] mcEd = uvarint(multicodec(Cose.ALG_ED25519));
        byte[] preimage = new byte[mcMl.length + mldsaPub.length + mcEd.length + edPub.length];
        int o = 0;
        System.arraycopy(mcMl, 0, preimage, o, mcMl.length);
        o += mcMl.length;
        System.arraycopy(mldsaPub, 0, preimage, o, mldsaPub.length);
        o += mldsaPub.length;
        System.arraycopy(mcEd, 0, preimage, o, mcEd.length);
        o += mcEd.length;
        System.arraycopy(edPub, 0, preimage, o, edPub.length);
        byte[] digest = sha256().digest(preimage);
        byte[] mhCode = uvarint(MH_SHA256);
        byte[] mhLen = uvarint(digest.length);
        byte[] mh = new byte[mhCode.length + mhLen.length + digest.length];
        System.arraycopy(mhCode, 0, mh, 0, mhCode.length);
        System.arraycopy(mhLen, 0, mh, mhCode.length, mhLen.length);
        System.arraycopy(digest, 0, mh, mhCode.length + mhLen.length, digest.length);
        return "b" + base32NoPad(mh);
    }

    public static void checkSigner(String claimed, int alg, byte[] pubkey) {
        if (!signerId(alg, pubkey).equals(claimed)) {
            throw new NaalpException("SignerMismatch", "signer id does not recompute from the key");
        }
    }

    /** Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3). */
    public static void requireNfc(String s) {
        if (!Normalizer.normalize(s, Normalizer.Form.NFC).equals(s)) {
            throw new NaalpException("NonNFC", "string is not Unicode NFC");
        }
    }

    /** Decode a UTF-8 byte payload to a String (matches the adapter's utf8_hex handling). */
    public static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    // ---- key lifecycle: co-signed identity rotation (design.md §5.2; R-5.2, R-5.5) --------
    //
    // ADDED ADDITIVELY (Wave D, feature #64 rooms) — the C4 identity-rotation primitive the room
    // rebind path (Rooms.PrincipalRegistry.rebind, R-1.4) composes on, placed here on the identity
    // spine where the Go reference (impl/go/identity) puts it, NOT duplicated inside Rooms. Mirrors
    // impl/python/naalp/identity (RotationRecord / sign_rotation / verify_rotation / RotationUnauthorized).
    // New types/methods only; no existing member above is changed.

    /** Links an old signer id to a new one from {@code notBefore} (§5.2). Its signed bytes are the
     * deterministic-CBOR map {1:old,2:new,3:not_before}; both keys co-sign those exact bytes. */
    public static final class RotationRecord {
        public final String oldId;
        public final String newId;
        public final long notBefore;

        public RotationRecord(String oldId, String newId, long notBefore) {
            this.oldId = oldId;
            this.newId = newId;
            this.notBefore = notBefore;
        }

        /** Deterministic-CBOR encoding {1:old,2:new,3:not_before} — the bytes both keys sign. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(java.util.List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(oldId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(newId)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(notBefore)))));
        }
    }

    /** Co-sign a rotation with BOTH the old and new keys (§5.2): each is a RAW deterministic ML-DSA
     * signature over the record bytes (matching the reference cose.Signer.Sign). Returns
     * {@code {oldSig, newSig}}. Both keys use the same {@code alg}. */
    public static byte[][] signRotation(RotationRecord r, int alg, byte[] oldSeed, byte[] newSeed) {
        byte[] m = r.bytes();
        byte[] oldSig = Cose.mldsaSign(alg, oldSeed, m);
        byte[] newSig = Cose.mldsaSign(alg, newSeed, m);
        return new byte[][]{oldSig, newSig};
    }

    /** Confirm a rotation is authorized: the old and new keys derive the ids in the record, and BOTH
     * signatures verify over the record bytes. A substitution not co-signed by the old key — or a key
     * whose id does not recompute — is RotationUnauthorized (§5.2, §5.5). Fail-closed. */
    public static void verifyRotation(RotationRecord r, int oldAlg, byte[] oldPub, int newAlg, byte[] newPub,
                                      byte[] oldSig, byte[] newSig) {
        try {
            checkSigner(r.oldId, oldAlg, oldPub);
            checkSigner(r.newId, newAlg, newPub);
        } catch (NaalpException e) {
            throw new NaalpException("RotationUnauthorized", "rotation key id does not recompute from the key");
        }
        byte[] m = r.bytes();
        if (!Cose.coseVerify1Raw(oldAlg, oldPub, m, oldSig) || !Cose.coseVerify1Raw(newAlg, newPub, m, newSig)) {
            throw new NaalpException("RotationUnauthorized", "rotation not co-signed by both keys");
        }
    }

    // ---- revocation record (design.md §5.3; R-5.3, R-5.5) ---------------------------------
    //
    // ADDED ADDITIVELY (identity records + thread port) -- RevocationRecord / RevokedAt /
    // VerifyRevocation mirror the Go reference (impl/go/identity/identity.go) and Rust
    // (impl/rust/src/identity.rs) exactly, graded against the independent oracle
    // vectors/identity_records/cases.json (tools/identity_records_oracle.py).

    /** Marks a key dead from {@code notAfter} (§5.3). Signed bytes: the deterministic-CBOR map
     * {1:key, 2:not_after}. */
    public static final class RevocationRecord {
        public final String key;
        public final long notAfter;

        public RevocationRecord(String key, long notAfter) {
            this.key = key;
            this.notAfter = notAfter;
        }

        /** Deterministic-CBOR encoding {1:key, 2:not_after} -- the bytes the revoker signs. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(key)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(notAfter)))));
        }
    }

    /**
     * Confirms a revocation is validly signed (§5.3): by the key it revokes, or by a
     * deployer-configured recovery key. {@code recoveryIds} is the deployer's set of authorized
     * recovery-key signer ids; a revocation whose signer is neither {@code r.key} nor a member of
     * {@code recoveryIds} is rejected SignerMismatch (§5.5), fail-closed -- an empty
     * {@code recoveryIds} admits only the revoked key itself. The signer id is recomputed from the
     * presented key and checked BEFORE the signature (membership guard first).
     *
     * <p>SECURITY-CRITICAL, fail-closed: the membership check MUST run before the signature check,
     * and MUST actually gate acceptance -- an authorized-key-or-recovery-member candidate signer
     * that is neither is rejected regardless of whether its signature verifies.
     */
    public static void verifyRevocation(RevocationRecord r, int alg, byte[] pub, byte[] sig, List<String> recoveryIds) {
        String id = signerId(alg, pub); // UnknownAlg propagates unchanged
        boolean authorized = id.equals(r.key);
        if (!authorized) {
            for (String rid : recoveryIds) {
                if (rid.equals(id)) {
                    authorized = true;
                    break;
                }
            }
        }
        if (!authorized) {
            throw new NaalpException("SignerMismatch", "revocation signer is neither the revoked key nor a configured recovery id");
        }
        if (!Cose.coseVerify1Raw(alg, pub, r.bytes(), sig)) {
            throw new NaalpException("BadSignature", "signature verification failed");
        }
    }

    /** Whether an object fixed at authoritative position {@code posTime} is after the revocation
     * (KeyRevoked); objects fixed at or before notAfter stay valid (§5.3). */
    public static boolean revokedAt(RevocationRecord r, long posTime) {
        return posTime > r.notAfter;
    }

    // ---- foreign-identity link (design.md §5.4; R-5.4, R-5.5) -----------------------------

    /** Cross-signs a foreign identity to a signer id (§5.4). Signed bytes: the deterministic-CBOR
     * map {1:controls, 2:foreign_id, 3:not_after}. It is signed by the FOREIGN identity's key. */
    public static final class ForeignLinkRecord {
        public final String controls;
        public final String foreignId;
        public final long notAfter;

        public ForeignLinkRecord(String controls, String foreignId, long notAfter) {
            this.controls = controls;
            this.foreignId = foreignId;
            this.notAfter = notAfter;
        }

        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(controls)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(foreignId)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(notAfter)))));
        }
    }

    /**
     * Whether a foreign-identity link confers linkage at time {@code now}. A non-NFC foreign_id is
     * rejected (NonNFC). An expired link or a bad cross-signature confers NO linkage but is not
     * itself an error -- it simply does not link (the object remains valid on its own signature,
     * §5.4/§5.5). It NEVER overrides the key-derived id.
     */
    public static boolean verifyForeignLink(ForeignLinkRecord r, int foreignAlg, byte[] foreignPub, byte[] sig, long now) {
        requireNfc(r.foreignId);
        if (now > r.notAfter) {
            return false; // expired: confers no authority (ignored)
        }
        if (!Cose.coseVerify1Raw(foreignAlg, foreignPub, r.bytes(), sig)) {
            return false; // bad/absent cross-signature: no linkage
        }
        return true;
    }

    // ---- durable identity thread (rotation-surviving attribution, R-1.4) ------------------

    /** One verified rotation step: the record plus the two keys' algs/pubkeys and their
     * co-signatures. */
    public static final class RotationEvidence {
        public final RotationRecord record;
        public final int oldAlg;
        public final byte[] oldPub;
        public final int newAlg;
        public final byte[] newPub;
        public final byte[] oldSig;
        public final byte[] newSig;

        public RotationEvidence(RotationRecord record, int oldAlg, byte[] oldPub, int newAlg, byte[] newPub,
                                 byte[] oldSig, byte[] newSig) {
            this.record = record;
            this.oldAlg = oldAlg;
            this.oldPub = oldPub;
            this.newAlg = newAlg;
            this.newPub = newPub;
            this.oldSig = oldSig;
            this.newSig = newSig;
        }
    }

    /** A durable identity: a root signer id continued by a chain of rotations. */
    public static final class Thread {
        public final String root;
        public final String current;
        public final List<String> chain;

        public Thread(String root, String current, List<String> chain) {
            this.root = root;
            this.current = current;
            this.chain = chain;
        }

        /** Whether an object whose body signer id is {@code signer} belongs to this durable thread
         * (any id in the chain, including a pre-rotation key, R-1.4). */
        public boolean attributable(String signer) {
            for (String id : chain) {
                if (id.equals(signer)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Verifies an ordered rotation chain and returns the durable identity thread. Each rotation
     * must be authorized (co-signed) and link the previous {@code new} to the next {@code old}; a
     * break yields RotationUnauthorized. A receipt signed under any id in Chain is attributable to
     * Root, so it stays attributable after rotation (R-1.4).
     */
    public static Thread resolveThread(List<RotationEvidence> evs) {
        if (evs.isEmpty()) {
            throw new NaalpException("RotationUnauthorized", "empty rotation-evidence chain");
        }
        List<String> chain = new ArrayList<>();
        String root = evs.get(0).record.oldId;
        chain.add(root);
        String prevNew = root;
        for (RotationEvidence e : evs) {
            if (!e.record.oldId.equals(prevNew)) {
                throw new NaalpException("RotationUnauthorized", "rotation chain not contiguous");
            }
            verifyRotation(e.record, e.oldAlg, e.oldPub, e.newAlg, e.newPub, e.oldSig, e.newSig);
            chain.add(e.record.newId);
            prevNew = e.record.newId;
        }
        return new Thread(root, prevNew, chain);
    }
}
