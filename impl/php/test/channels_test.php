<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C10 channels conformance for the PHP SDK (design-channels.md §1..§20; R-11.1..11.4, R-15A.1..15A.3),
// graded against the shared independent per-channel corpus vectors/channels/<name>/cases.json (NOT
// produced by this code; Go/Rust/PHP all grade the SAME files, so Go == Rust == PHP == oracle). A
// channel surface is a thin body over the one spine (design.md §2..§10): it adds only kind codes and
// their declared effects; this file exercises the twenty-channel baseline registry, the per-channel
// state-machine transition guard (AllowedTransition), the Spatial coordinate-frame cycle check
// (CheckFrameTree/TransformCycle), and the durable Workflow input/approval gate whose crash test
// proves InputGateBypass cannot occur (design-channels.md §18).
//
// CORPUS-GRADED (pure, non-circular): every channel's id/name/kinds/states/transitions/errors equal
// the independent oracle. AllowedTransition, CheckFrameTree, and the WorkflowGate crash scenario are
// exercised against representative cases mirroring impl/go/channels/channels_test.go (behavioral
// authority) and impl/rust/src/channels.rs (second reference) — no channel-local encoding, signature,
// or identity is introduced (R-11.3), so these are ad hoc scenario checks, not corpus vectors.
//
// Written test-first: Naalp\Channels::channel() / ::allowedTransition() / ::checkFrameTree() /
// ::openWorkflowGate() are absent until Channels.php is extended, so this fails RED with a fatal
// "call to undefined method" / "class not found". The InputGateBypass mutation anchor: neutering the
// input-gate check in WorkflowGate::run() so "running before input" succeeds flips the
// "task ran before its input gate (InputGateBypass)" and the post-crash re-check below it RED.
//
// Run:  php test/channels_test.php   (from impl/php/) — no signing/intl surface, no extra extensions.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Channels;

$fails = 0;
function check(string $name, string $got, string $want): void
{
    global $fails;
    if ($got === $want) {
        echo "  ok   $name\n";
    } else {
        $fails++;
        echo "  FAIL $name\n       got  $got\n       want $want\n";
    }
}

/** Run $fn and return the caught error's ->kind (or "no-error" / the class name). */
function err_kind(callable $fn): string
{
    try {
        $fn();
        return "no-error";
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
}

/** Walk up from this dir to the repository's shared corpus at $rel (the independent oracle). */
function shared_vectors(string $rel): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/' . $rel;
        if (\is_file($p)) {
            return \json_decode(\file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = \dirname($d);
    }
    throw new RuntimeException("vectors/$rel not found");
}

/** A fresh, unique WAL path in the OS temp dir (created at runtime, never a committed path). */
function fresh_wal(): string
{
    return \tempnam(\sys_get_temp_dir(), 'naalp_wfgate_');
}

echo "channels conformance (PHP) — graded vs vectors/channels/<name>/cases.json\n";

// 1. TestTableMatchesOracle: every one of the 20 channels' id/name/kinds/states/transitions/errors
//    equal the independent per-channel oracle (=> Go == Rust == PHP, which grade the same vectors). A
//    field-dropping or reordering table diverges here.
$names = [];
for ($id = 0x0000; $id <= 0x0013; $id++) {
    $ch = Channels::channel($id);
    if ($ch === null) {
        $fails++;
        echo "  FAIL channel {$id} missing from the table\n";
        continue;
    }
    $names[$id] = $ch->name;
    $c = shared_vectors('channels/' . \strtolower($ch->name) . '/cases.json');
    check("{$ch->name} id == oracle", (string) $ch->id, (string) $c["channel_id"]);
    check("{$ch->name} name == oracle", $ch->name, $c["name"]);
    check("{$ch->name} kind count == oracle", (string) \count($ch->kinds), (string) \count($c["kinds"]));
    foreach ($ch->kinds as $i => $k) {
        [$code, $kname, $effect, $variable] = $k;
        $o = $c["kinds"][$i];
        check("{$ch->name} kind {$i} code == oracle", (string) $code, (string) $o["code"]);
        check("{$ch->name} kind {$i} name == oracle", $kname, $o["name"]);
        check("{$ch->name} kind {$i} effect == oracle", (string) $effect, (string) $o["effect"]);
        check("{$ch->name} kind {$i} variable == oracle", $variable ? "true" : "false", $o["variable"] ? "true" : "false");
    }
    check("{$ch->name} states == oracle", \implode(",", $ch->states), \implode(",", $c["states"]));
    check("{$ch->name} transition count == oracle", (string) \count($ch->transitions), (string) \count($c["transitions"]));
    foreach ($ch->transitions as $i => [$from, $to]) {
        $ot = $c["transitions"][$i];
        check("{$ch->name} transition {$i} == oracle", "{$from}->{$to}", "{$ot['from']}->{$ot['to']}");
    }
    check("{$ch->name} errors == oracle", \implode(",", $ch->errors), \implode(",", $c["errors"]));
}

// 2. TestCompleteness: all twenty channels present (ids 0..19, none thinned), every kind a valid
//    declared effect (R-11.1/R-11.2). An unregistered id must resolve to null (channel(0x00FF)).
check("all 20 channel names populated", (string) \count($names), "20");
check("unregistered channel id resolves to null", Channels::channel(0x00FF) === null ? "null" : "present", "null");

// 3. TestStateMachine: representative channels permit their declared transitions and reject others —
//    mirrors impl/go/channels/channels_test.go TestStateMachine byte-for-byte.
$smCases = [
    [0x0001, "offered", "accepted", true],    // Memory
    [0x0001, "live", "revoked", true],        // Memory
    [0x0001, "revoked", "live", false],       // Memory regression
    [0x000E, "order", "fulfil", true],        // Commerce
    [0x000E, "offer", "fulfil", false],       // Commerce skip
    [0x0011, "awaiting-input", "running", true],  // Workflow
    [0x0011, "created", "running", false],        // Workflow gate skip
];
foreach ($smCases as [$ch, $from, $to, $ok]) {
    $got = Channels::allowedTransition($ch, $from, $to);
    check(\sprintf("channel 0x%04x %s->%s allowed", $ch, $from, $to), $got ? "true" : "false", $ok ? "true" : "false");
}
check("unregistered channel has no allowed transitions", Channels::allowedTransition(0x00FF, "a", "b") ? "true" : "false", "false");

// 4. TestTransformCycle: Spatial's named error fires on a cyclic coordinate-frame tree; a valid tree
//    (a DAG rooted at "") is accepted.
$tree = ["base" => "", "arm" => "base", "hand" => "arm"];
check("valid frame tree accepted", err_kind(fn() => Channels::checkFrameTree($tree)), "no-error");
$cyclic = ["a" => "b", "b" => "c", "c" => "a"];
check("cyclic frame tree rejected (TransformCycle)", err_kind(fn() => Channels::checkFrameTree($cyclic)), "TransformCycle");

// 5. TestWorkflowInputGateBypass: the gated crash test (design-channels.md §18) — a task cannot reach
//    "running" without passing the input/approval gate, and a crash (close -> reopen) recovers to the
//    pre-gate status rather than bypassing it. THE mutation anchor for this port.
$wal = fresh_wal();
$g = Channels::openWorkflowGate($wal);
$g->create("t1", false);
check("task ran before its input gate (InputGateBypass)", err_kind(fn() => $g->run("t1")), "InputGateBypass");
$g->close();
// Simulate a crash right after Create: the durable status is still the pre-gate status.
$g2 = Channels::openWorkflowGate($wal);
check("crash recovers pre-gate status (not bypassed)", (string) $g2->status("t1"), "awaiting-input");
check("task ran after crash without passing the gate (InputGateBypass)", err_kind(fn() => $g2->run("t1")), "InputGateBypass");
// Supplying input opens the gate; only then may it run.
check("supply input opens the gate", err_kind(fn() => $g2->supplyInput("t1")), "no-error");
check("task runs after input supplied", err_kind(fn() => $g2->run("t1")), "no-error");
check("status after run is running", (string) $g2->status("t1"), "running");
$g2->close();
@\unlink($wal);

// 6. Approval-gated variant: Create(needsApproval=true) lands in "awaiting-approval", not
//    "awaiting-input"; SupplyInput advances it to "approved"; Run before that is still InputGateBypass.
$wal2 = fresh_wal();
$g3 = Channels::openWorkflowGate($wal2);
$g3->create("t2", true);
check("approval-gated task lands in awaiting-approval", (string) $g3->status("t2"), "awaiting-approval");
check("approval-gated task run before approval rejected (InputGateBypass)", err_kind(fn() => $g3->run("t2")), "InputGateBypass");
$g3->supplyInput("t2");
check("approval-gated task status after supply is approved", (string) $g3->status("t2"), "approved");
check("approval-gated task runs after approval", err_kind(fn() => $g3->run("t2")), "no-error");
$g3->close();
@\unlink($wal2);

// 7. TaskStateError: creating a task that already exists, or supplying input to a task that is not
//    awaiting input/approval, is rejected (not silently accepted / not InputGateBypass).
$wal3 = fresh_wal();
$g4 = Channels::openWorkflowGate($wal3);
$g4->create("dup", false);
check("re-creating an existing task rejected (TaskStateError)", err_kind(fn() => $g4->create("dup", false)), "TaskStateError");
check("supplying input to an unknown task rejected (TaskStateError)", err_kind(fn() => $g4->supplyInput("unknown")), "TaskStateError");
$g4->supplyInput("dup");
$g4->run("dup");
check("supplying input to a running task rejected (TaskStateError)", err_kind(fn() => $g4->supplyInput("dup")), "TaskStateError");
$g4->close();
@\unlink($wal3);

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
