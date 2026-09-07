// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the worked-example N-AALP object as one line of lowercase hex: the whole
// COSE_Sign1 the reference produces from the fixed 0x2a seed for the Governance
// Approval object (channel 0x0004, kind 1) -- the same construction the Go
// cmd/naalp-worked-example emitter and WorkedExampleKat build. Lives in tools/ (not
// src/main/java) so it is not shipped in the published jar.
// scripts/record_cross_port_objects.py runs this and records the bytes; the
// cross-port object gate compares them to vectors/worked/example.json. Prints ONLY
// the hex so the recorder reads it unambiguously.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public final class WorkedExampleEmit {
    private static final int ALG = Cose.ALG_MLDSA65;
    private static final String ARGS_ID_HEX =
            "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff";

    public static void main(String[] args) {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 0x2a);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        String signerId = Identity.signerId(ALG, pk);
        Cbor.M body = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(Hex.decode(ARGS_ID_HEX))),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(signerId)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(2)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[]{1, 2, 3, 4, 5, 6, 7, 8})),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(1785000000000L))));
        Envelope.Object obj = new Envelope.Object(
                1, 4, 0, signerId.getBytes(StandardCharsets.UTF_8),
                1785000000000L, 2, Cose.PROFILE_PUBLIC, body, null, null, null);
        byte[] signed = Envelope.sign(obj, ALG, seed);
        System.out.println(Hex.encode(signed));
    }
}
