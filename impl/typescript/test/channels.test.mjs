// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C10 channels parity conformance for the TypeScript SDK (task #174): the state-machine +
// WorkflowGate surfaces (design-channels.md §1..§20; R-11.1..11.4, R-15A.1..15A.3), graded against
// the shared independent per-channel corpus vectors/channels/<name>/cases.json (NOT produced by this
// code) -- the same 20-channel oracle Go and Rust grade (impl/go/channels/channels_test.go,
// impl/rust/src/channels.rs). Covers: channel(id) returning the full frozen ChannelSpec (kinds,
// states, transitions, errors) matching the oracle for all twenty channels; allowedTransition's
// accept/reject state-machine verdicts; checkFrameTree's TransformCycle accept/reject (valid tree vs
// cyclic); and the durable WAL-backed WorkflowGate crash test that proves InputGateBypass cannot be
// bypassed even across a close/reopen (design-channels.md §18).
//
// Ported from impl/go/channels/channels.go (behavioral authority) with impl/rust/src/channels.rs as a
// second reference; the existing lookup/checkEffect/channelName/UnknownKind/EffectDeclarationMismatch
// surfaces are pre-existing and are exercised only incidentally here (their own coverage lives
// elsewhere via delegation.test.mjs/rooms.test.mjs's imports).
//
// MUTATION TARGET (InputGateBypass, the fail-closed anchor): neutering the input-gate check in
// WorkflowGate.run() so a task may Run before SupplyInput flips
// 'channels workflow input gate: Run before SupplyInput is InputGateBypass, durable across a crash'
// on its very first assertion.
//
// Run:  node --test test/channels.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

import * as channels from '../naalp/channels.mjs';

// ---- vector loading: vectors/channels/<dir>/cases.json, one per channel (walk up to repo root) ----

function repoRootFrom(startDir) {
  let d = startDir;
  for (let i = 0; i < 6; i++) {
    if (existsSync(join(d, 'vectors', 'channels'))) return d;
    d = dirname(d);
  }
  throw new Error('vectors/channels not found by walking up from ' + startDir);
}

const ROOT = repoRootFrom(dirname(fileURLToPath(import.meta.url)));

function loadChannel(dir) {
  const p = join(ROOT, 'vectors', 'channels', dir, 'cases.json');
  return JSON.parse(readFileSync(p, 'utf-8'));
}

// The twenty channel vector subdirs, lowercase channel names (matches channels_test.go's loader).
const CHANNEL_DIRS = [
  'control', 'memory', 'capability', 'identity', 'governance', 'immune', 'federation', 'settlement',
  'compliance', 'sensory', 'telemetry', 'audit', 'stream', 'bridge', 'commerce', 'interaction',
  'discovery', 'workflow', 'knowledge', 'spatial',
];

function withTempGate(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'naalp-channels-'));
  const path = join(dir, 'wf.wal');
  try {
    return fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---- channel(id) / ChannelSpec: table matches the independent oracle, all twenty channels --------

test('channels channel(id) matches the oracle for all twenty channels (kinds, states, transitions, errors)', () => {
  assert.equal(CHANNEL_DIRS.length, 20, 'twenty channel vector dirs enumerated');
  for (const dir of CHANNEL_DIRS) {
    const c = loadChannel(dir);
    const got = channels.channel(c.channel_id);
    assert.ok(got !== undefined, `${dir}: channel(${c.channel_id}) must be registered`);
    assert.equal(got.id, c.channel_id, `${dir}: id`);
    assert.equal(got.name, c.name, `${dir}: name`);

    assert.equal(got.kinds.length, c.kinds.length, `${dir}: kind count`);
    for (let i = 0; i < c.kinds.length; i++) {
      assert.equal(got.kinds[i].code, c.kinds[i].code, `${dir} kind ${i}: code`);
      assert.equal(got.kinds[i].name, c.kinds[i].name, `${dir} kind ${i}: name`);
      assert.equal(got.kinds[i].effect, c.kinds[i].effect, `${dir} kind ${i}: effect`);
      assert.equal(got.kinds[i].variable, c.kinds[i].variable, `${dir} kind ${i}: variable`);
    }

    assert.deepEqual(got.states, c.states, `${dir}: states`);

    assert.equal(got.transitions.length, c.transitions.length, `${dir}: transition count`);
    for (let i = 0; i < c.transitions.length; i++) {
      assert.equal(got.transitions[i].from, c.transitions[i].from, `${dir} transition ${i}: from`);
      assert.equal(got.transitions[i].to, c.transitions[i].to, `${dir} transition ${i}: to`);
    }

    assert.deepEqual(got.errors, c.errors, `${dir}: errors`);
  }
});

test('channels completeness: all twenty channel ids 0x0000..0x0013 registered, none thinned', () => {
  for (let id = 0x0000; id <= 0x0013; id++) {
    const c = channels.channel(id);
    assert.ok(c !== undefined, `channel ${id.toString(16)} missing`);
    assert.ok(c.kinds.length > 0, `channel ${c.name} has no kinds (thinned surface)`);
    for (const k of c.kinds) {
      assert.ok(k.effect >= 0 && k.effect <= 3, `${c.name}.${k.name} has invalid effect ${k.effect}`);
    }
  }
  assert.equal(channels.channel(0x00FF), undefined, 'an unregistered channel id is undefined, not thrown');
});

// ---- allowedTransition: representative accept/reject state-machine verdicts ----------------------

test('channels allowedTransition: representative transitions accept/reject as the oracle table declares', () => {
  const cases = [
    [0x0001, 'offered', 'accepted', true],    // Memory
    [0x0001, 'live', 'revoked', true],        // Memory
    [0x0001, 'revoked', 'live', false],       // Memory regression
    [0x000E, 'order', 'fulfil', true],        // Commerce
    [0x000E, 'offer', 'fulfil', false],       // Commerce skip
    [0x0011, 'awaiting-input', 'running', true],  // Workflow
    [0x0011, 'created', 'running', false],        // Workflow gate skip
  ];
  for (const [ch, from, to, want] of cases) {
    assert.equal(channels.allowedTransition(ch, from, to), want, `0x${ch.toString(16)} ${from}->${to}`);
  }
  assert.equal(channels.allowedTransition(0x00FF, 'a', 'b'), false, 'an unregistered channel permits nothing');
});

// ---- checkFrameTree: Spatial's TransformCycle, valid tree accepted / cyclic tree rejected ---------

test('channels checkFrameTree accepts a valid tree and rejects a cyclic one (TransformCycle)', () => {
  const tree = { base: '', arm: 'base', hand: 'arm' };
  assert.doesNotThrow(() => channels.checkFrameTree(tree), 'a valid frame tree must not be rejected');

  const cyclic = { a: 'b', b: 'c', c: 'a' };
  assert.throws(
    () => channels.checkFrameTree(cyclic),
    (e) => e.kind === 'TransformCycle',
    'a cyclic frame tree must be rejected TransformCycle',
  );
});

// ---- WorkflowGate: the durable input-gate crash test (design-channels.md §18) ----------------------

test('channels workflow input gate: Run before SupplyInput is InputGateBypass, durable across a crash', () => {
  withTempGate((path) => {
    const g = channels.openWorkflowGate(path);
    g.create('t1', false);

    // Running before input is InputGateBypass.
    assert.throws(
      () => g.run('t1'),
      (e) => e.kind === 'InputGateBypass',
      'a task must not run before its input gate is passed',
    );

    // Simulate a crash right after create(): close flushes/closes the WAL.
    g.close();
    const g2 = channels.openWorkflowGate(path);
    assert.equal(g2.status('t1'), 'awaiting-input', 'a crash must not bypass the gate');
    assert.throws(
      () => g2.run('t1'),
      (e) => e.kind === 'InputGateBypass',
      'a task must not run after a crash without passing the gate',
    );

    // Supplying input opens the gate; only then may it run.
    g2.supplyInput('t1');
    assert.doesNotThrow(() => g2.run('t1'), 'a task must run once its input has been supplied');
    assert.equal(g2.status('t1'), 'running');
    g2.close();
  });
});

test('channels workflow gate: an approval-gated task passes via SupplyInput -> approved -> running', () => {
  withTempGate((path) => {
    const g = channels.openWorkflowGate(path);
    g.create('t2', true); // needsApproval
    assert.equal(g.status('t2'), 'awaiting-approval');
    assert.throws(() => g.run('t2'), (e) => e.kind === 'InputGateBypass');
    g.supplyInput('t2');
    assert.equal(g.status('t2'), 'approved');
    g.run('t2');
    assert.equal(g.status('t2'), 'running');
    g.close();
  });
});

test('channels workflow gate: re-creating an existing task is TaskStateError', () => {
  withTempGate((path) => {
    const g = channels.openWorkflowGate(path);
    g.create('t3', false);
    assert.throws(() => g.create('t3', false), (e) => e.kind === 'TaskStateError');
    g.close();
  });
});

test('channels workflow gate: supplyInput/run on an unknown task is TaskStateError', () => {
  withTempGate((path) => {
    const g = channels.openWorkflowGate(path);
    assert.throws(() => g.supplyInput('ghost'), (e) => e.kind === 'TaskStateError');
    assert.throws(() => g.run('ghost'), (e) => e.kind === 'TaskStateError');
    assert.equal(g.status('ghost'), undefined);
    g.close();
  });
});

test('channels workflow gate: status persists correctly across multiple tasks in one WAL', () => {
  withTempGate((path) => {
    const g = channels.openWorkflowGate(path);
    g.create('a', false);
    g.create('b', true);
    g.supplyInput('a');
    g.run('a');
    assert.equal(g.status('a'), 'running');
    assert.equal(g.status('b'), 'awaiting-approval');
    g.close();

    const g2 = channels.openWorkflowGate(path);
    assert.equal(g2.status('a'), 'running');
    assert.equal(g2.status('b'), 'awaiting-approval');
    g2.close();
  });
});
