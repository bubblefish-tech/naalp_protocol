export function approvalBody(approves: any, approver: any, grant: any, nonce: any, notAfter: any): any;
export function approvalId(approves: any, approver: any, grant: any, nonce: any, notAfter: any): Uint8Array<ArrayBuffer>;
export function ledgerEntry(seq: any, prev: any, approvalIdBytes: any, by: any): any;
export function receiptBody(prev: any, obj: any, seq: any, at: any): any;
export function receiptHead(body: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function deliveryUpdate(obj: any, stage: any, at: any): any;
export function streamDigest(chunks: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function streamOpenBody(streamId: any, effect: any, approval: any, substream: any): any;
export function streamCommitBody(streamId: any, digest: any): any;
export function streamCheckpointBody(streamId: any, throughOffset: any, digestSoFar: any): any;
export function carriageBody(protocolId: any, cls: any, contentType: any, correlation: any, method: any, foreign: any): any;
export function transportEmit(name: any, sensitive: any, requirePeerAuth: any): "ConfidentialTransportRequired" | "PeerUnauthenticated" | "ok";
export const CLASS_JSONRPC: 0;
export const CLASS_HTTP: 1;
export const CLASS_MSG: 2;
export const CLASS_STREAM: 3;
export const CLASS_DOC: 4;
export const CLASS_OPAQUE: 5;
export class MappingError extends Error {
    constructor(m: any);
    kind: string;
}
export class UnknownTransport extends Error {
    constructor(m: any);
    kind: string;
}
