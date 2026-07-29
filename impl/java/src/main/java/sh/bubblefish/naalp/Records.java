// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * N-AALP body builders for the Java SDK — the deterministic-CBOR bodies of the spine records:
 * approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
 * open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
 * transport confidentiality boundary (C11, §12). Each body is exactly what the Go, Rust and Python
 * reference implementations encode, so the bytes are byte-identical.
 */
public final class Records {
    private Records() {}

    private static MessageDigest sha384() {
        try {
            return MessageDigest.getInstance("SHA-384");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    // --- C6 approval + consume ledger (§7) ---

    public static byte[] approvalBody(byte[] approves, String approver, long grant, byte[] nonce, long notAfter) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(approves)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(approver)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(grant)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(nonce)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(notAfter)))));
    }

    public static byte[] approvalId(byte[] approves, String approver, long grant, byte[] nonce, long notAfter) {
        return Cbor.contentId(approvalBody(approves, approver, grant, nonce, notAfter));
    }

    public static byte[] ledgerEntry(long seq, byte[] prev, byte[] approvalId, String by) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(seq)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(prev)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(approvalId)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.T(by)))));
    }

    // --- C7 audit receipt (§8) ---

    public static byte[] receiptBody(byte[] prev, byte[] obj, long seq, long at) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(prev)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(obj)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(seq)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(at)))));
    }

    public static byte[] receiptHead(byte[] body) {
        return sha384().digest(body);
    }

    // --- C8 delivery (§9) ---

    public static byte[] deliveryUpdate(byte[] obj, long stage, long at) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(obj)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(stage)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(at)))));
    }

    // --- C9 streaming (§10) ---

    /** A stream chunk: an absolute offset and its data bytes. */
    public static final class Chunk {
        public final long offset;
        public final byte[] data;
        public Chunk(long offset, byte[] data) { this.offset = offset; this.data = data; }
    }

    /** Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2). */
    public static byte[] streamDigest(List<Chunk> chunks) {
        List<Chunk> sorted = new ArrayList<>(chunks);
        sorted.sort(Comparator.comparingLong(c -> c.offset));
        MessageDigest h = sha384();
        for (Chunk c : sorted) {
            h.update(c.data);
        }
        return h.digest();
    }

    public static byte[] streamOpenBody(byte[] streamId, long effect, byte[] approval, long substream) {
        List<Cbor.Pair> pairs = new ArrayList<>();
        pairs.add(new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)));
        pairs.add(new Cbor.Pair(new Cbor.U(2), new Cbor.U(effect)));
        pairs.add(new Cbor.Pair(new Cbor.U(4), new Cbor.U(substream)));
        if (approval != null && approval.length > 0) { // field 3 present only with an approval binding
            pairs.add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(approval)));
        }
        return Cbor.encode(new Cbor.M(pairs));
    }

    public static byte[] streamCommitBody(byte[] streamId, byte[] digest) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(digest)))));
    }

    public static byte[] streamCheckpointBody(byte[] streamId, long throughOffset, byte[] digestSoFar) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(throughOffset)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(digestSoFar)))));
    }

    // --- C12 foreign carriage (§13) ---

    public static final long CLASS_OPAQUE = 5;

    public static byte[] carriageBody(long protocolId, long cls, long contentType,
                                      byte[] correlation, String method, byte[] foreign) {
        if (cls > CLASS_OPAQUE) {
            throw new NaalpException("MappingError", "carriage class " + cls + " is not defined");
        }
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(protocolId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(cls)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(contentType)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(correlation)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.T(method)),
                new Cbor.Pair(new Cbor.U(6), new Cbor.B(foreign)))));
    }

    // --- C11 transport confidentiality boundary (§12) ---

    private static boolean[] transport(String name) {
        switch (name) {
            case "npamp": return new boolean[]{true, true};
            case "quic": return new boolean[]{true, true};
            case "websocket+wss": return new boolean[]{true, false};
            case "websocket+ws": return new boolean[]{false, false};
            case "https": return new boolean[]{true, false};
            case "http": return new boolean[]{false, false};
            default: return null;
        }
    }

    /** Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label. */
    public static String transportEmit(String name, boolean sensitive, boolean requirePeerAuth) {
        boolean[] t = transport(name);
        if (t == null) {
            throw new NaalpException("UnknownTransport", "unknown transport " + name);
        }
        boolean confidential = t[0];
        boolean peerAuthenticated = t[1];
        if (sensitive && !confidential) {
            return "ConfidentialTransportRequired";
        }
        if (requirePeerAuth && !peerAuthenticated) {
            return "PeerUnauthenticated";
        }
        return "ok";
    }
}
