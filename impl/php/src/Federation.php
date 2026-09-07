<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP Federation higher tier (tier 1) for the PHP SDK — federated ordering by a deterministic
 * reconcile-merge over the shared causal graph (design.md §8.4; design-channels.md §7; R-8.6,
 * R-15A.2, R-15A.3).
 *
 * The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher tier
 * lets multiple independent authorities each order their own scope and reconcile over the shared
 * causal graph — the partial order every authority already signs over (§8.2). Reconcile is a
 * DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break among
 * causally-concurrent objects is the object content id (bytewise ascending). Because it depends only
 * on the causal graph (not on how scopes are split), any split of the same objects reconciles to the
 * same order — so moving from single-authority to federated ordering requires no envelope or object
 * change (R-8.6).
 *
 * An independent transcription of impl/go/federation, graded against the shared
 * vectors/federation/cases.json. The causal partial order is checked by the shared Naalp\Graph (the
 * C7/audit foundation), exactly as the reference reuses the audit layer.
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP cannot deterministically sign or verify ML-DSA (FIPS 204), so the
 * reference's ML-DSA Reconcile-record signature is provided here as an Ed25519 signing DEMONSTRATION
 * (signReconcile / verifyReconcile via ext-sodium) — exercised in isolation, NOT corpus-graded. The
 * corpus-graded deliverable is the pure reconcile / causal-validity / record-bytes logic.
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A node's place in the shared causal graph: its content id and the content ids of its causes
 * (envelope field 8). The federated tier reconciles by these causal edges and the content-id
 * tie-break; the single-authority future-cause position check lives in the baseline tier.
 */
final class CausalNode
{
    public string $id;
    /** @var array<int,string> */
    public array $causes;

    /** @param array<int,string> $causes binary content ids */
    public function __construct(string $id, array $causes)
    {
        $this->id = $id;
        $this->causes = \array_values($causes);
    }
}

/**
 * The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
 * resulting deterministic total order (object content ids). Signed with the C2 crypto over its
 * deterministic-CBOR bytes; it orders the identical signed objects the baseline already produced
 * (no envelope change).
 */
final class ReconcileRecord
{
    /** @var array<int,string> */
    public array $authorities;
    /** @var array<int,string> binary content ids */
    public array $order;

    /**
     * @param array<int,string> $authorities
     * @param array<int,string> $order binary content ids
     */
    public function __construct(array $authorities, array $order)
    {
        $this->authorities = \array_values($authorities);
        $this->order = \array_values($order);
    }

    /** Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}. */
    public function bytes(): string
    {
        $auth = new A(\array_map(static fn(string $a): T => new T($a), $this->authorities));
        $ordr = new A(\array_map(static fn(string $o): B => new B($o), $this->order));
        return Cbor::encode(new M([
            [new U(1), $auth],
            [new U(2), $ordr],
        ]));
    }
}

/**
 * The verify-event reject of the Reconcile state machine (draft "## Reconcile state machine", error
 * code 61): an independent recomputation of the deterministic linearization disagrees with the total
 * order a Reconcile record claims, so the record is rejected whole. Thrown by
 * Federation::verifyReconcileOrder.
 */
class ReconcileMismatch extends \RuntimeException
{
    public string $kind = "ReconcileMismatch";
}

final class Federation
{
    /**
     * Reconcile deterministically merges the objects of a shared causal graph into one total order
     * (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no
     * future-cause) via the shared Naalp\Graph, then linearizes it with Kahn's algorithm, breaking
     * ties among ready nodes by content id (bytewise ascending). The result is causally consistent
     * and deterministic. A duplicate object id (scope overlap) is ordered once (resolved).
     *
     * @param array<int,CausalNode> $nodes
     * @return array<int,string> ordered binary content ids
     */
    public static function reconcile(array $nodes): array
    {
        Graph::verifyCausal(\array_map(
            static fn(CausalNode $n): array => [$n->id, $n->causes, 0],
            $nodes,
        ));

        $count = \count($nodes);
        $ids = [];
        $present = [];
        foreach ($nodes as $n) {
            $ids[] = $n->id;
            $present[\bin2hex($n->id)] = true;
        }
        // keep only causes that are present in this graph (a cause outside the scope is not an edge).
        $causes = [];
        foreach ($nodes as $n) {
            $kept = [];
            foreach ($n->causes as $c) {
                if (\array_key_exists(\bin2hex($c), $present)) {
                    $kept[] = $c;
                }
            }
            $causes[] = $kept;
        }
        $indeg = \array_map('\count', $causes);
        $done = \array_fill(0, $count, false);
        $order = [];
        while (\count($order) < $count) {
            $pick = -1;
            for ($i = 0; $i < $count; $i++) {
                if ($done[$i] || $indeg[$i] !== 0) {
                    continue;
                }
                if ($pick === -1 || \strcmp($ids[$i], $ids[$pick]) < 0) {
                    $pick = $i;
                }
            }
            if ($pick === -1) {
                // unreachable after verifyCausal, but fail-closed rather than loop forever.
                throw new CausalViolation("no ready node (unreachable after verifyCausal)");
            }
            $done[$pick] = true;
            $order[] = $ids[$pick];
            for ($j = 0; $j < $count; $j++) {
                if ($done[$j]) {
                    continue;
                }
                foreach ($causes[$j] as $c) {
                    if ($c === $ids[$pick]) {
                        $indeg[$j] -= 1;
                    }
                }
            }
        }
        return $order;
    }

    /**
     * Reports whether an order places every object's (present) causes before it.
     *
     * @param array<int,string> $order binary content ids
     * @param array<int,CausalNode> $nodes
     */
    public static function causallyValid(array $order, array $nodes): bool
    {
        $pos = [];
        foreach ($order as $k => $id) {
            $pos[\bin2hex($id)] = $k;
        }
        foreach ($nodes as $n) {
            $np = $pos[\bin2hex($n->id)] ?? null;
            if ($np === null) {
                continue;
            }
            foreach ($n->causes as $c) {
                $cp = $pos[\bin2hex($c)] ?? null;
                if ($cp !== null && $cp > $np) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Ed25519 signing DEMONSTRATION (isolation, NOT corpus-graded): a tier-1 ordering authority signs
     * a Reconcile record with a deterministic Ed25519 (RFC 8032) signature over the record's
     * deterministic-CBOR bytes. PHP is PURE-ONLY for ML-DSA, so this stands in for the reference's
     * ML-DSA signature to exercise the signing binding end-to-end.
     */
    public static function signReconcile(ReconcileRecord $record, string $seed): string
    {
        return Cose::ed25519Sign($seed, $record->bytes());
    }

    /** Verify a raw Ed25519 Reconcile-record signature under the authority's public key. */
    public static function verifyReconcile(ReconcileRecord $record, string $pubkey, string $sig): bool
    {
        return Cose::ed25519Verify($pubkey, $record->bytes(), $sig);
    }

    /**
     * verifyReconcileOrder is the verify-event choke point of the Reconcile state machine (draft "##
     * Reconcile state machine"). A verifier independently re-runs the deterministic linearization over
     * the identical causal graph via self::reconcile() and rejects the record whole (ReconcileMismatch)
     * if the recomputed total order differs from the one the record claims. It MUST recompute via
     * self::reconcile() — the content-id tie-break — and NEVER a position/index tie-break, which would
     * spuriously disagree on causally-concurrent objects. A node set that is not a valid partial order
     * propagates CausalViolation, fail-closed. Returns (no throw) only when the record's claimed order
     * is byte-for-byte the deterministic order (verified).
     *
     * This is distinct from the per-port signature-verify verifyReconcile(record, pubkey, sig), which
     * checks the Ed25519 signature over the record bytes; verifyReconcileOrder verifies the ORDER, not
     * the signature. Named ...Order uniformly across all ten ports so one parity token cannot collide
     * with the signature-verify name.
     *
     * @param array<int,CausalNode> $nodes
     */
    public static function verifyReconcileOrder(ReconcileRecord $record, array $nodes): void
    {
        $recomputed = self::reconcile($nodes); // CausalViolation propagates fail-closed
        if (\count($recomputed) !== \count($record->order)) {
            throw new ReconcileMismatch("independent linearization disagrees with the reconcile record's claimed order");
        }
        foreach ($recomputed as $i => $id) {
            if ($id !== $record->order[$i]) {
                throw new ReconcileMismatch("independent linearization disagrees with the reconcile record's claimed order");
            }
        }
    }
}
