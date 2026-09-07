// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C10 channel registry for the TypeScript SDK — the frozen twenty-channel baseline surface
// (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
// effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
// the design, cross-checked against the shared conformance corpus (== Go == Rust == Python == oracle).
//
// task #174: brings the channel state-machine + WorkflowGate surfaces to parity with the behavioral
// authority impl/go/channels/channels.go (impl/rust/src/channels.rs as a second reference) --
// channel(id)/ChannelSpec (the full per-channel descriptor: kinds, states, transitions, errors),
// allowedTransition (the state-machine transition guard), checkFrameTree (Spatial's TransformCycle
// acyclic check, design-channels.md §20), and the durable, WAL-backed WorkflowGate input/approval gate
// whose crash test proves InputGateBypass cannot occur (design-channels.md §18): a task's status is
// fsynced before it is acknowledged (persist-before-ack, spine §9.2), so a crash (close -> reopen)
// recovers to the last durable pre-gate status rather than bypassing the gate. WAL framing follows the
// sibling naalp/approval Ledger idiom (length-prefixed records, fsync per append, JS's single-threaded
// synchronous critical section giving the same exactly-once/no-TOCTOU guarantee as the Go mutex).

import { openSync, existsSync, readSync, writeSync, fsyncSync, closeSync } from 'node:fs';

const RO = 0, IW = 1, NIW = 2, DE = 3; // read_only, idempotent_write, non_idempotent_write, destructive

// Each channel entry: { name, kinds: [[code,name,effect,variable], ...], states: [...],
// transitions: [[from,to], ...], errors: [...] } -- the frozen baseline registry
// (design-channels.md §1..§20), transcribed from impl/go/channels/channels.go's Table (== Rust table()).
const TABLE = new Map([
  [0x0000, { name: 'Control',
    kinds: [[0, 'Hello', RO, false], [1, 'Bye', IW, false], [2, 'Ack', RO, false], [3, 'Error', RO, false]],
    states: ['open', 'closing'], transitions: [['open', 'closing']], errors: ['UnknownKind', 'ProfileMismatch'] }],
  [0x0001, { name: 'Memory',
    kinds: [[0, 'MemoryOffer', IW, false], [1, 'MemoryAccept', IW, false], [2, 'MemoryWrite', NIW, false],
      [3, 'MemoryRead', RO, false], [4, 'MemoryExpire', DE, false], [5, 'MemoryRevoke', DE, false]],
    states: ['offered', 'accepted', 'live', 'expired', 'revoked'],
    transitions: [['offered', 'accepted'], ['accepted', 'live'], ['live', 'expired'], ['live', 'revoked']],
    errors: ['AccessDenied', 'MemoryError'] }],
  [0x0002, { name: 'Capability',
    kinds: [[0, 'CapIssue', NIW, false], [1, 'CapDelegate', NIW, false], [2, 'CapRevoke', DE, false], [3, 'CapLookup', RO, false]],
    states: ['issued', 'delegated', 'revoked', 'expired'],
    transitions: [['issued', 'delegated'], ['delegated', 'delegated'], ['issued', 'revoked'], ['delegated', 'revoked'], ['issued', 'expired'], ['delegated', 'expired']],
    errors: ['CapExceedsParent', 'CapRevoked'] }],
  [0x0003, { name: 'Identity',
    kinds: [[0, 'Rotation', NIW, false], [1, 'Revocation', DE, false], [2, 'ForeignLink', IW, false], [3, 'KeyAnnounce', RO, false]],
    states: ['active', 'rotated', 'revoked'],
    transitions: [['active', 'rotated'], ['rotated', 'rotated'], ['active', 'revoked'], ['rotated', 'revoked']],
    errors: ['RotationUnauthorized', 'KeyRevoked', 'SignerMismatch'] }],
  [0x0004, { name: 'Governance',
    kinds: [[0, 'PolicyPublish', NIW, false], [1, 'Approval', NIW, false], [2, 'ApprovalHeld', RO, false], [3, 'Consume', NIW, false], [4, 'GatewayDecision', NIW, false], [5, 'DecisionRecord', NIW, false], [6, 'EgressAttestation', NIW, false], [7, 'HazardAuthorization', NIW, false]],
    states: ['requested', 'held', 'approved', 'consumed', 'expired'],
    transitions: [['requested', 'held'], ['requested', 'approved'], ['approved', 'consumed'], ['held', 'approved'], ['requested', 'expired'], ['approved', 'expired']],
    errors: ['ApprovalRequired', 'ApprovalMismatch', 'AlreadyConsumed', 'EffectNotAuthorized'] }],
  [0x0005, { name: 'Immune',
    kinds: [[0, 'AnomalyReport', RO, false], [1, 'Quarantine', DE, false], [2, 'QuarantineLift', NIW, false]],
    states: ['normal', 'quarantined', 'lifted', 'permanent'],
    transitions: [['normal', 'quarantined'], ['quarantined', 'lifted'], ['quarantined', 'permanent']],
    errors: ['AccessDenied'] }],
  [0x0006, { name: 'Federation',
    kinds: [[0, 'AuthorityAnnounce', RO, false], [1, 'ScopeReceipt', NIW, false]],
    states: ['announced', 'ordering'], transitions: [['announced', 'ordering']],
    errors: ['AuthorityUnknown', 'ScopeOverlapConflict'] }],
  [0x0007, { name: 'Settlement',
    kinds: [[0, 'SettleIntent', NIW, false], [1, 'SettleReceipt', NIW, false], [2, 'SettleReject', IW, false], [3, 'PaymentImport', NIW, false], [4, 'PaymentChargeBinding', NIW, false]],
    states: ['intent', 'receipt', 'reject'], transitions: [['intent', 'receipt'], ['intent', 'reject']],
    errors: ['ValueMismatch', 'SettleExpired'] }],
  [0x0008, { name: 'Compliance',
    kinds: [[0, 'ComplianceRecord', NIW, false], [1, 'ComplianceQuery', RO, false], [2, 'ComplianceReport', RO, false]],
    states: ['appended'], transitions: [], errors: ['RecordUnsigned', 'JurisdictionUnknown'] }],
  [0x0009, { name: 'Sensory',
    kinds: [[0, 'Observation', RO, false], [1, 'Subscribe', IW, false], [2, 'Unsubscribe', IW, false]],
    states: ['active', 'cancelled'], transitions: [['active', 'cancelled']], errors: ['SubscriptionUnknown'] }],
  [0x000A, { name: 'Telemetry',
    kinds: [[0, 'Metric', RO, false], [1, 'HealthReport', RO, false]],
    states: ['stateless'], transitions: [], errors: ['MetricMalformed'] }],
  [0x000B, { name: 'Audit',
    kinds: [[0, 'Receipt', NIW, false], [1, 'AuditQuery', RO, false], [2, 'ForkProof', RO, false], [3, 'CheckpointRoot', NIW, false], [4, 'WitnessCosign', NIW, false], [5, 'InclusionProof', RO, false]],
    states: ['appended'], transitions: [], errors: ['ChainBroken', 'Equivocation', 'ReceiptUnsigned'] }],
  [0x000C, { name: 'Stream',
    kinds: [[0, 'StreamOpen', RO, true], [1, 'StreamCommit', RO, false], [2, 'StreamCheckpoint', RO, false]],
    states: ['open', 'committed'], transitions: [['open', 'committed']],
    errors: ['StreamDigestMismatch', 'FlowControlError'] }],
  [0x000D, { name: 'Bridge',
    kinds: [[0, 'Carriage', RO, true]],
    states: ['carried'], transitions: [],
    errors: ['EnvelopeMalformed', 'ProtocolUnsupported', 'MethodUnsupported', 'NotDelivered', 'EffectNotAuthorized'] }],
  [0x000E, { name: 'Commerce',
    kinds: [[0, 'Offer', RO, false], [1, 'Order', NIW, false], [2, 'Fulfil', NIW, false], [3, 'Cancel', DE, false]],
    states: ['offer', 'order', 'fulfil', 'cancel'],
    transitions: [['offer', 'order'], ['order', 'fulfil'], ['order', 'cancel']],
    errors: ['OfferExpired', 'ApprovalRequired', 'OrderMismatch'] }],
  [0x000F, { name: 'Interaction',
    kinds: [[0, 'Elicit', RO, false], [1, 'Respond', IW, false], [2, 'Confirm', NIW, false], [3, 'UiEvent', NIW, false]],
    states: ['elicit', 'respond', 'confirm', 'timeout'],
    transitions: [['elicit', 'respond'], ['elicit', 'confirm'], ['elicit', 'timeout']],
    errors: ['InteractionTimeout', 'ElicitUnauthorized'] }],
  [0x0010, { name: 'Discovery',
    kinds: [[0, 'DiscoveryRecord', RO, false], [1, 'DiscoveryQuery', RO, false]],
    states: ['fresh', 'stale'], transitions: [['fresh', 'stale']],
    errors: ['RecordExpired', 'TrustAnchorUnknown'] }],
  [0x0011, { name: 'Workflow',
    kinds: [[0, 'TaskCreate', NIW, false], [1, 'TaskInput', NIW, false], [2, 'TaskCancel', DE, false], [3, 'TaskResult', NIW, false]],
    states: ['created', 'awaiting-input', 'awaiting-approval', 'running', 'result', 'cancelled'],
    transitions: [['created', 'awaiting-input'], ['created', 'awaiting-approval'], ['awaiting-input', 'running'],
      ['awaiting-approval', 'running'], ['running', 'result'], ['created', 'cancelled'], ['awaiting-input', 'cancelled'],
      ['awaiting-approval', 'cancelled'], ['running', 'cancelled']],
    errors: ['TaskStateError', 'InputGateBypass', 'ApprovalRequired'] }],
  [0x0012, { name: 'Knowledge',
    kinds: [[0, 'Assert', NIW, false], [1, 'Retract', DE, false], [2, 'KnowledgeQuery', RO, false]],
    states: ['asserted', 'retracted'], transitions: [['asserted', 'retracted']],
    errors: ['FactUnsigned', 'RetractUnknown'] }],
  [0x0013, { name: 'Spatial',
    kinds: [[0, 'FrameDefine', IW, false], [1, 'Pose', RO, false], [2, 'StateUpdate', RO, false], [3, 'SnapshotQuery', RO, false]],
    states: ['defined', 'observed'], transitions: [['defined', 'observed']],
    errors: ['FrameUnknown', 'TransformCycle'] }],
]);

const DESTRUCTIVE = DE;

export class UnknownKind extends Error { constructor(m) { super(m); this.kind = 'UnknownKind'; } }
export class EffectDeclarationMismatch extends Error { constructor(m) { super(m); this.kind = 'EffectDeclarationMismatch'; } }

// A named, fail-closed channels error for the state-machine/WorkflowGate surfaces (TransformCycle,
// InputGateBypass, TaskStateError, Malformed); .kind is the stable error kind mirroring the Go/Rust
// cose.Error{Kind,Msg} shape, following the PolicyError/ApprovalError convention used elsewhere in
// this SDK for a module whose new surfaces span more than one or two named errors.
export class ChannelsError extends Error { constructor(kind, msg = '') { super(msg ? `${kind}: ${msg}` : kind); this.kind = kind; } }

export function lookup(channel, kind) {
  // Return [name, effect, variable] for a (channel, kind), or raise UnknownKind.
  channel = Number(channel); kind = Number(kind);
  const ch = TABLE.get(channel);
  if (ch === undefined) throw new UnknownKind('channel 0x' + channel.toString(16).padStart(4, '0') + ' not registered');
  for (const [code, name, effect, variable] of ch.kinds) {
    if (code === kind) return [name, effect, variable];
  }
  throw new UnknownKind('kind ' + kind + ' not in channel 0x' + channel.toString(16).padStart(4, '0'));
}

/**
 * Return the registered channel name (e.g. 0x000F -> 'Interaction'), or raise UnknownKind. Reads the
 * same TABLE lookup() uses, so it is the single source of truth for channel names.
 * @param {bigint|number} channel
 * @returns {string}
 */
export function channelName(channel) {
  channel = Number(channel);
  const ch = TABLE.get(channel);
  if (ch === undefined) throw new UnknownKind('channel 0x' + channel.toString(16).padStart(4, '0') + ' not registered');
  return ch.name;
}

export function checkEffect(channel, kind, effect) {
  // A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3.
  effect = Number(effect);
  const [, declared, variable] = lookup(channel, kind);
  if (variable) {
    if (effect > DESTRUCTIVE) throw new EffectDeclarationMismatch('effect ' + effect + ' out of range');
    return;
  }
  if (effect !== declared) throw new EffectDeclarationMismatch('object effect ' + effect + ' != declared ' + declared);
}

// ---- Channel / ChannelSpec: the full frozen per-channel descriptor --------------------------------

/**
 * @typedef {{code:number, name:string, effect:number, variable:boolean}} KindSpec
 * @typedef {{id:number, name:string, kinds:KindSpec[], states:string[],
 *            transitions:{from:string,to:string}[], errors:string[]}} ChannelSpec
 */

/**
 * Return the ChannelSpec for a channel id -- mirrors Go channels.Channel(id)/Rust channel(id): a plain
 * accessor over the frozen registry, not a security check, so an unregistered id returns `undefined`
 * (JS's Map.get idiom / Rust's Option::None) rather than throwing.
 * @param {bigint|number} id
 * @returns {ChannelSpec|undefined}
 */
export function channel(id) {
  id = Number(id);
  const ch = TABLE.get(id);
  if (ch === undefined) return undefined;
  return {
    id,
    name: ch.name,
    kinds: ch.kinds.map(([code, name, effect, variable]) => ({ code, name, effect, variable })),
    states: ch.states.slice(),
    transitions: ch.transitions.map(([from, to]) => ({ from, to })),
    errors: ch.errors.slice(),
  };
}

// ---- AllowedTransition: the channel state-machine transition guard --------------------------------

/**
 * Report whether `channel` permits a state transition from -> to (design-channels.md §1..§20). An
 * unregistered channel permits nothing (mirrors Go/Rust: false, not thrown -- this is a query, not a
 * fail-closed authorization gate on its own; the fail-closed anchor is WorkflowGate.run below).
 * @param {bigint|number} channel
 * @param {string} from
 * @param {string} to
 * @returns {boolean}
 */
export function allowedTransition(channel, from, to) {
  const ch = TABLE.get(Number(channel));
  if (ch === undefined) return false;
  return ch.transitions.some(([a, b]) => a === from && b === to);
}

// ---- CheckFrameTree: Spatial's TransformCycle (design-channels.md §20) -----------------------------

/**
 * Enforce Spatial's TransformCycle: the coordinate-frame child->parent links (a plain object mapping a
 * frame name to its parent frame name, "" or absent meaning a root) must form a tree (acyclic). Uses
 * the identical white/gray/black DFS as impl/go/channels.CheckFrameTree / impl/rust channels::check_frame_tree.
 * Throws ChannelsError('TransformCycle') on a cycle; returns undefined on a valid tree.
 * @param {Record<string,string>} parent
 */
export function checkFrameTree(parent) {
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map();
  const parentOf = (f) => Object.prototype.hasOwnProperty.call(parent, f) ? parent[f] : undefined;
  function visit(f) {
    color.set(f, GRAY);
    const p = parentOf(f);
    if (p !== undefined && p !== '') {
      const c = color.get(p) ?? WHITE;
      if (c === GRAY) return true;
      if (c === WHITE && visit(p)) return true;
    }
    color.set(f, BLACK);
    return false;
  }
  for (const f of Object.keys(parent)) {
    if ((color.get(f) ?? WHITE) === WHITE && visit(f)) {
      throw new ChannelsError('TransformCycle', 'coordinate frame tree contains a cycle');
    }
  }
}

// ---- WorkflowGate: the durable Workflow input gate (design-channels.md §18) ------------------------
//
// A durable, WAL-backed task-status tracker. A task's status is persisted (written + fsynced) before
// it is acknowledged (spine §9.2, persist-before-ack), so a crash (close -> reopen) recovers to the
// last durable status and can NEVER bypass the input/approval gate: reaching "running" requires an
// explicit SupplyInput step that a crash cannot manufacture. WAL records are length-prefixed (4-byte
// big-endian) `task \x00 status` bodies, matching impl/go/channels.WorkflowGate's on-disk format byte
// for byte (so a WAL written by one port's gate replays correctly under any other port's gate).

// WorkflowGate errors use ChannelsError directly (kind: 'InputGateBypass' | 'TaskStateError' | 'Malformed').

function errInputGateBypass() {
  return new ChannelsError('InputGateBypass', 'a task reached running without passing the input/approval gate');
}
function errTaskState() {
  return new ChannelsError('TaskStateError', 'workflow task state transition not permitted');
}

export class WorkflowGate {
  constructor(fd) {
    this._fd = fd;
    this._status = new Map(); // task name -> durable status
    this._pos = 0;            // append offset in the WAL
    this._replay();
  }

  // Read the WAL from the start, rebuilding the status map. Each record is length-prefixed
  // (uint32 big-endian) so the log is self-framing, matching impl/go/channels.WorkflowGate.replay().
  _replay() {
    let pos = 0;
    for (;;) {
      const lenBuf = Buffer.alloc(4);
      const n = readSync(this._fd, lenBuf, 0, 4, pos);
      if (n === 0) break;
      if (n !== 4) throw new ChannelsError('Malformed', 'truncated workflow gate length prefix');
      pos += 4;
      const reclen = lenBuf.readUInt32BE(0);
      const rec = Buffer.alloc(reclen);
      const m = readSync(this._fd, rec, 0, reclen, pos);
      if (m !== reclen) throw new ChannelsError('Malformed', 'truncated workflow gate record');
      pos += reclen;
      const nul = rec.indexOf(0);
      if (nul < 0) throw new ChannelsError('Malformed', 'workflow gate record missing task/status separator');
      const task = rec.subarray(0, nul).toString('utf8');
      const status = rec.subarray(nul + 1).toString('utf8');
      this._status.set(task, status);
    }
    this._pos = pos;
  }

  // Append one `task \x00 status` record, fsynced before returning (persist-before-ack, spine §9.2).
  _persist(task, status) {
    const taskBuf = Buffer.from(task, 'utf8');
    const statusBuf = Buffer.from(status, 'utf8');
    const rec = Buffer.concat([taskBuf, Buffer.from([0]), statusBuf]);
    const lenPrefix = Buffer.alloc(4);
    lenPrefix.writeUInt32BE(rec.length, 0);
    const frame = Buffer.concat([lenPrefix, rec]);
    writeSync(this._fd, frame, 0, frame.length, this._pos);
    this._pos += frame.length;
    fsyncSync(this._fd); // persist-before-ack (spine §9.2)
    this._status.set(task, status);
  }

  /**
   * Record a new task in a non-terminal pre-gate status. TaskCreate never lands in "running": it
   * lands in "awaiting-input" (or "awaiting-approval" when needsApproval), persisted before returning.
   * Re-creating an already-known task is TaskStateError.
   * @param {string} task
   * @param {boolean} needsApproval
   */
  create(task, needsApproval) {
    if (this._status.has(task)) throw errTaskState();
    this._persist(task, needsApproval ? 'awaiting-approval' : 'awaiting-input');
  }

  /**
   * Advance a task past its input gate (awaiting-input -> input-supplied) or approval gate
   * (awaiting-approval -> approved). Only these transitions may precede run(). Any other current
   * status (including unknown) is TaskStateError.
   * @param {string} task
   */
  supplyInput(task) {
    switch (this._status.get(task)) {
      case 'awaiting-input': this._persist(task, 'input-supplied'); return;
      case 'awaiting-approval': this._persist(task, 'approved'); return;
      default: throw errTaskState();
    }
  }

  /**
   * Move a task to "running" only if it has passed the gate. A task still "awaiting-input" or
   * "awaiting-approval" is InputGateBypass -- forbidden, and durable across a crash because the
   * status a reopened gate observes is exactly the last fsynced status. Any other unknown status is
   * TaskStateError.
   * @param {string} task
   */
  run(task) {
    switch (this._status.get(task)) {
      case 'input-supplied':
      case 'approved':
        this._persist(task, 'running');
        return;
      case 'awaiting-input':
      case 'awaiting-approval':
        throw errInputGateBypass();
      default:
        throw errTaskState();
    }
  }

  /**
   * The task's durable status, or `undefined` if the task is unknown (mirrors Go's (status, bool)).
   * @param {string} task
   * @returns {string|undefined}
   */
  status(task) {
    return this._status.get(task);
  }

  /** Flush and close the WAL. Every persist() already fsyncs before acknowledging, so the WAL is
   * already durable; this closes the underlying file descriptor. */
  close() {
    closeSync(this._fd);
  }
}

/**
 * Open (creating if needed) a WAL-backed WorkflowGate and replay it, mirroring
 * impl/go/channels.OpenWorkflowGate / impl/rust open_workflow_gate.
 * @param {string} path
 * @returns {WorkflowGate}
 */
export function openWorkflowGate(path) {
  const fd = existsSync(path) ? openSync(path, 'r+') : openSync(path, 'w+');
  try {
    return new WorkflowGate(fd);
  } catch (e) {
    closeSync(fd); // a corrupt WAL leaves no open descriptor behind
    throw e;
  }
}
