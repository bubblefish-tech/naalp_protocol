<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the PHP SDK.
 *
 * verifyCausal enforces no-future-cause (a present cause may not sit at a later position than its
 * effect) and acyclicity. reconcile is the deterministic merge: a topological linearization of the
 * union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).
 *
 * A node is [id: binary string, causes: string[], position: int]. Content ids are used as map
 * keys in hex form to stay clear of PHP's numeric-string key coercion.
 */

declare(strict_types=1);

namespace Naalp;

class CausalViolation extends \RuntimeException
{
    public string $kind = "CausalViolation";
}

final class Graph
{
    /**
     * @param array<int,array{0:string,1:array<int,string>,2:int}> $nodes
     */
    public static function verifyCausal(array $nodes): void
    {
        $idx = [];
        foreach ($nodes as $i => $node) {
            $idx[\bin2hex($node[0])] = $i;
        }
        // no future cause
        foreach ($nodes as $node) {
            [$nid, $causes, $pos] = $node;
            foreach ($causes as $c) {
                $key = \bin2hex($c);
                if (\array_key_exists($key, $idx)) {
                    $j = $idx[$key];
                    if ($nodes[$j][2] > $pos) {
                        throw new CausalViolation("cause at a later position than its effect");
                    }
                }
            }
        }
        // acyclic (3-colour DFS over effect -> cause edges)
        $count = \count($nodes);
        $color = \array_fill(0, $count, 0); // 0 WHITE, 1 GRAY, 2 BLACK

        $hasCycle = function (int $i) use (&$hasCycle, &$color, $nodes, $idx): bool {
            $color[$i] = 1;
            foreach ($nodes[$i][1] as $c) {
                $key = \bin2hex($c);
                if (!\array_key_exists($key, $idx)) {
                    continue;
                }
                $j = $idx[$key];
                if ($color[$j] === 1) {
                    return true;
                }
                if ($color[$j] === 0 && $hasCycle($j)) {
                    return true;
                }
            }
            $color[$i] = 2;
            return false;
        };

        for ($i = 0; $i < $count; $i++) {
            if ($color[$i] === 0 && $hasCycle($i)) {
                throw new CausalViolation("causal graph contains a cycle");
            }
        }
    }

    /**
     * Deterministic topological merge over the union causal DAG; ties break by content id.
     *
     * @param array<int,array{0:string,1:array<int,string>,2:int}> $nodes
     * @return array<int,string> ordered list of content ids (binary strings)
     */
    public static function reconcile(array $nodes): array
    {
        self::verifyCausal($nodes);
        $count = \count($nodes);
        $ids = [];
        $present = [];
        foreach ($nodes as $node) {
            $ids[] = $node[0];
            $present[\bin2hex($node[0])] = true;
        }
        $causes = [];
        foreach ($nodes as $node) {
            $kept = [];
            foreach ($node[1] as $c) {
                if (\array_key_exists(\bin2hex($c), $present)) {
                    $kept[] = $c;
                }
            }
            $causes[] = $kept;
        }
        $indeg = \array_map('count', $causes);
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
                        break;
                    }
                }
            }
        }
        return $order;
    }

    /**
     * The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}.
     *
     * @param array<int,string> $authorities
     * @param array<int,string> $order binary content ids
     */
    public static function reconcileRecord(array $authorities, array $order): string
    {
        $auth = new A(\array_map(static fn(string $a): T => new T($a), $authorities));
        $ordr = new A(\array_map(static fn(string $o): B => new B($o), $order));
        return Cbor::encode(new M([
            [new U(1), $auth],
            [new U(2), $ordr],
        ]));
    }
}
