// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link Streaming.Guard} stream-state-table conformance for the Java SDK (design.md §10, § Timers;
 * error code 49). An independent transcription of impl/go/streaming/state_guard_test.go's seven
 * mutation-surviving cases — no shared corpus (a pure state machine, not a byte-producing op), graded
 * here by driving {@link Streaming.Guard} through ordered events and asserting the resulting error
 * kind and the guard's post-event state.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes, matching
 * {@link StreamingKatTest} and {@link PolicyKatTest}.
 *
 * <p>Run (from the repo root, on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java \
 *     impl/java/src/test/java/sh/bubblefish/naalp/StateGuardKatTest.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.StateGuardKatTest
 * </pre>
 */
public final class StateGuardKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        } catch (Throwable t) {
            return t.getClass().getSimpleName();
        }
    }

    private static String state(Streaming.Guard g, byte[] id) {
        return g.state(id).toString();
    }

    private static byte[] id(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // TestGuardRejectsForbiddenTransitions: forbidden (state, event) pairs from the stream state
    // table (design.md §10), each rejected StreamStateError with no state change.  <<< MUTATION TARGET >>>
    private static void testRejectsForbiddenTransitions() {
        byte[] sid = id("stream-forbidden");

        // idle + chunk -> unlisted pair, default StreamStateError.
        Streaming.Guard g1 = Streaming.Guard.newGuard();
        check("chunk_before_open: rejected", errKind(() -> g1.chunk(sid)), "StreamStateError");
        check("chunk_before_open: state unchanged", state(g1, sid), "idle");

        // idle + StreamCheckpoint -> unlisted pair, default StreamStateError.
        Streaming.Guard g2 = Streaming.Guard.newGuard();
        check("checkpoint_before_open: rejected", errKind(() -> g2.checkpoint(sid)), "StreamStateError");
        check("checkpoint_before_open: state unchanged", state(g2, sid), "idle");

        // idle + StreamCommit -> unlisted pair, default StreamStateError.
        Streaming.Guard g3 = Streaming.Guard.newGuard();
        check("commit_before_open: rejected",
                errKind(() -> g3.commit(new Streaming.StreamCommit(sid, new byte[0]), List.of())),
                "StreamStateError");
        check("commit_before_open: state unchanged", state(g3, sid), "idle");

        // open + StreamOpen -> reject (StreamStateError) -- explicit table row.
        byte[] doid = id("stream-double-open");
        Streaming.Guard g4 = Streaming.Guard.newGuard();
        Streaming.StreamOpen open4 = new Streaming.StreamOpen(doid, Policy.IDEMPOTENT_WRITE, null, 0);
        check("double_open: first open succeeds", errKind(() -> g4.open(open4, Policy.IDEMPOTENT_WRITE)), "no-error");
        check("double_open: re-open rejected", errKind(() -> g4.open(open4, Policy.IDEMPOTENT_WRITE)), "StreamStateError");
        check("double_open: state unchanged (still open)", state(g4, doid), "open");

        // committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} -- the first three are
        // explicit table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the
        // unlisted-pair default.
        byte[] acid = id("stream-after-commit");
        Streaming.Guard g5 = Streaming.Guard.newGuard();
        Streaming.StreamOpen open5 = new Streaming.StreamOpen(acid, Policy.IDEMPOTENT_WRITE, null, 0);
        check("events_after_commit: open succeeds", errKind(() -> g5.open(open5, Policy.IDEMPOTENT_WRITE)), "no-error");
        List<Streaming.Chunk> chunks5 = List.of(new Streaming.Chunk(0, "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        Streaming.StreamCommit commit5 = new Streaming.StreamCommit(acid, Streaming.commitDigest(chunks5));
        check("events_after_commit: commit succeeds", errKind(() -> g5.commit(commit5, chunks5)), "no-error");
        check("events_after_commit: state is committed", state(g5, acid), "committed");

        check("events_after_commit: chunk rejected", errKind(() -> g5.chunk(acid)), "StreamStateError");
        check("events_after_commit: checkpoint rejected", errKind(() -> g5.checkpoint(acid)), "StreamStateError");
        check("events_after_commit: commit rejected", errKind(() -> g5.commit(commit5, chunks5)), "StreamStateError");
        check("events_after_commit: re-open rejected", errKind(() -> g5.open(open5, Policy.IDEMPOTENT_WRITE)), "StreamStateError");
        check("events_after_commit: state still committed", state(g5, acid), "committed");
    }

    // TestGuardValidSequenceSucceeds: the false-positive check -- an ordered open -> chunk ->
    // checkpoint -> commit sequence must succeed and drive the state idle -> open -> committed.
    private static void testValidSequenceSucceeds() {
        byte[] sid = id("stream-valid");
        Streaming.Guard g = Streaming.Guard.newGuard();

        check("valid_sequence: unopened is idle", state(g, sid), "idle");

        Streaming.StreamOpen open = new Streaming.StreamOpen(sid, Policy.IDEMPOTENT_WRITE, null, 0);
        check("valid_sequence: open succeeds", errKind(() -> g.open(open, Policy.IDEMPOTENT_WRITE)), "no-error");
        check("valid_sequence: state after open", state(g, sid), "open");

        List<Streaming.Chunk> chunks = List.of(
                new Streaming.Chunk(0, "hello ".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                new Streaming.Chunk(6, "world".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        check("valid_sequence: chunk 0 succeeds", errKind(() -> g.chunk(sid)), "no-error");
        check("valid_sequence: chunk 1 succeeds", errKind(() -> g.chunk(sid)), "no-error");
        check("valid_sequence: checkpoint succeeds", errKind(() -> g.checkpoint(sid)), "no-error");
        check("valid_sequence: chunks/checkpoint keep it open", state(g, sid), "open");

        Streaming.StreamCommit commit = new Streaming.StreamCommit(sid, Streaming.commitDigest(chunks));
        check("valid_sequence: commit succeeds", errKind(() -> g.commit(commit, chunks)), "no-error");
        check("valid_sequence: state after commit", state(g, sid), "committed");
    }

    // TestGuardDigestMismatchIsNotStateError: "open | StreamCommit (digest mismatch) | reject
    // (StreamDigestMismatch)" must surface StreamDigestMismatch, not StreamStateError, and must leave
    // the stream open so a corrected commit still lands.
    private static void testDigestMismatchIsNotStateError() {
        byte[] sid = id("stream-bad-digest");
        Streaming.Guard g = Streaming.Guard.newGuard();
        Streaming.StreamOpen open = new Streaming.StreamOpen(sid, Policy.IDEMPOTENT_WRITE, null, 0);
        check("digest_mismatch: open succeeds", errKind(() -> g.open(open, Policy.IDEMPOTENT_WRITE)), "no-error");
        List<Streaming.Chunk> chunks = List.of(new Streaming.Chunk(0, "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        Streaming.StreamCommit bad = new Streaming.StreamCommit(sid,
                "not-the-real-digest-not-the-real-digest".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        check("digest_mismatch: bad commit rejected StreamDigestMismatch", errKind(() -> g.commit(bad, chunks)), "StreamDigestMismatch");
        check("digest_mismatch: stream stays open", state(g, sid), "open");

        Streaming.StreamCommit good = new Streaming.StreamCommit(sid, Streaming.commitDigest(chunks));
        check("digest_mismatch: corrected commit succeeds", errKind(() -> g.commit(good, chunks)), "no-error");
        check("digest_mismatch: state after corrected commit", state(g, sid), "committed");
    }

    // TestGuardEffectNotAuthorizedLeavesIdle: "idle | StreamOpen (effect not authorized) | reject
    // (EffectNotAuthorized)" must surface EffectNotAuthorized, not StreamStateError, and must leave
    // the stream idle so a properly authorized open on the same stream id still succeeds (R-10.3).
    private static void testEffectNotAuthorizedLeavesIdle() {
        byte[] sid = id("stream-unauthorized");
        Streaming.Guard g = Streaming.Guard.newGuard();

        Streaming.StreamOpen destructive = new Streaming.StreamOpen(sid, Policy.DESTRUCTIVE, null, 0);
        check("effect_not_authorized: rejected", errKind(() -> g.open(destructive, Policy.READ_ONLY)), "EffectNotAuthorized");
        check("effect_not_authorized: stream stays idle", state(g, sid), "idle");

        Streaming.StreamOpen authorized = new Streaming.StreamOpen(sid, Policy.IDEMPOTENT_WRITE, null, 0);
        check("effect_not_authorized: authorized open succeeds", errKind(() -> g.open(authorized, Policy.IDEMPOTENT_WRITE)), "no-error");
        check("effect_not_authorized: state after authorized open", state(g, sid), "open");
    }

    // TestGuardIndependentStreamsDoNotInterfere: the guard is keyed by stream id, so one stream's
    // state never leaks into another's.
    private static void testIndependentStreamsDoNotInterfere() {
        Streaming.Guard g = Streaming.Guard.newGuard();
        byte[] a = id("stream-a");
        byte[] b = id("stream-b");

        Streaming.StreamOpen openA = new Streaming.StreamOpen(a, Policy.IDEMPOTENT_WRITE, null, 0);
        check("independent_streams: open a succeeds", errKind(() -> g.open(openA, Policy.IDEMPOTENT_WRITE)), "no-error");
        // b was never opened; any event on b is still rejected StreamStateError even though a is open.
        check("independent_streams: chunk on unopened b rejected", errKind(() -> g.chunk(b)), "StreamStateError");
        check("independent_streams: chunk on open a succeeds", errKind(() -> g.chunk(a)), "no-error");
    }

    // TestGuardExpireAbandonsOpenStream: Expire on an open stream transitions it "open -> abandoned",
    // a terminal state that then rejects every event with StreamStateError -- including a StreamOpen
    // reusing the id, so an abandoned stream is never re-admitted.
    private static void testExpireAbandonsOpenStream() {
        byte[] sid = id("stream-abandoned");
        Streaming.Guard g = Streaming.Guard.newGuard();
        Streaming.StreamOpen open = new Streaming.StreamOpen(sid, Policy.IDEMPOTENT_WRITE, null, 0);
        check("expire_abandons: open succeeds", errKind(() -> g.open(open, Policy.IDEMPOTENT_WRITE)), "no-error");

        check("expire_abandons: expire succeeds", errKind(() -> g.expire(sid)), "no-error");
        check("expire_abandons: state after expire", state(g, sid), "abandoned");

        // An abandoned stream admits nothing -- chunk, checkpoint, commit, and a StreamOpen reusing
        // the id are all rejected StreamStateError (the id is never re-admitted).
        List<Streaming.Chunk> chunks = List.of(new Streaming.Chunk(0, "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        Streaming.StreamCommit commit = new Streaming.StreamCommit(sid, Streaming.commitDigest(chunks));
        check("expire_abandons: chunk rejected", errKind(() -> g.chunk(sid)), "StreamStateError");
        check("expire_abandons: checkpoint rejected", errKind(() -> g.checkpoint(sid)), "StreamStateError");
        check("expire_abandons: commit rejected", errKind(() -> g.commit(commit, chunks)), "StreamStateError");
        check("expire_abandons: re-open rejected", errKind(() -> g.open(open, Policy.IDEMPOTENT_WRITE)), "StreamStateError");
        check("expire_abandons: state still abandoned", state(g, sid), "abandoned");
    }

    // TestGuardExpireOnNonOpenIsStateError: the idle/commit timer clears when a StreamCommit
    // transitions the stream to committed (§ Timers), so a correct caller fires Expire only while the
    // stream is open. Expire on an idle, committed, or already-abandoned stream is rejected
    // StreamStateError and leaves the state unchanged (fail-closed).
    private static void testExpireOnNonOpenIsStateError() {
        // idle: nothing has been opened.
        byte[] idleId = id("stream-expire-idle");
        Streaming.Guard g1 = Streaming.Guard.newGuard();
        check("expire_non_open[idle]: rejected", errKind(() -> g1.expire(idleId)), "StreamStateError");
        check("expire_non_open[idle]: state unchanged", state(g1, idleId), "idle");

        // committed: the timer should have cleared on commit; a spurious Expire is a state error and
        // must not turn a committed (non-repudiable) stream into an abandoned one.
        byte[] committedId = id("stream-expire-committed");
        Streaming.Guard g2 = Streaming.Guard.newGuard();
        Streaming.StreamOpen open2 = new Streaming.StreamOpen(committedId, Policy.IDEMPOTENT_WRITE, null, 0);
        check("expire_non_open[committed]: open succeeds", errKind(() -> g2.open(open2, Policy.IDEMPOTENT_WRITE)), "no-error");
        List<Streaming.Chunk> chunks2 = List.of(new Streaming.Chunk(0, "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        Streaming.StreamCommit commit2 = new Streaming.StreamCommit(committedId, Streaming.commitDigest(chunks2));
        check("expire_non_open[committed]: commit succeeds", errKind(() -> g2.commit(commit2, chunks2)), "no-error");
        check("expire_non_open[committed]: rejected", errKind(() -> g2.expire(committedId)), "StreamStateError");
        check("expire_non_open[committed]: state unchanged", state(g2, committedId), "committed");

        // already abandoned: a second Expire is a state error and a no-op.
        byte[] twiceId = id("stream-expire-twice");
        Streaming.Guard g3 = Streaming.Guard.newGuard();
        Streaming.StreamOpen open3 = new Streaming.StreamOpen(twiceId, Policy.IDEMPOTENT_WRITE, null, 0);
        check("expire_non_open[already_abandoned]: open succeeds", errKind(() -> g3.open(open3, Policy.IDEMPOTENT_WRITE)), "no-error");
        check("expire_non_open[already_abandoned]: first expire succeeds", errKind(() -> g3.expire(twiceId)), "no-error");
        check("expire_non_open[already_abandoned]: second expire rejected", errKind(() -> g3.expire(twiceId)), "StreamStateError");
        check("expire_non_open[already_abandoned]: state unchanged", state(g3, twiceId), "abandoned");
    }

    private static void run() {
        testRejectsForbiddenTransitions();
        testValidSequenceSucceeds();
        testDigestMismatchIsNotStateError();
        testEffectNotAuthorizedLeavesIdle();
        testIndependentStreamsDoNotInterfere();
        testExpireAbandonsOpenStream();
        testExpireOnNonOpenIsStateError();
    }

    public static void main(String[] args) {
        System.out.println("stream-state guard conformance (Java) — impl/go/streaming/state_guard_test.go mirror");
        run();
        System.out.println(fails == 0 ? "StateGuardKatTest: PASS" : "StateGuardKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
