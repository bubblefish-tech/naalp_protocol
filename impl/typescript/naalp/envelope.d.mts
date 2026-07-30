export function sign(obj: any, alg: any, seed: any): any;
export function verify(profile: any, alg: any, pubkey: any, kindValidator: any, objBytes: any, knownCext?: any): Object_;
export const FIELD_ID: 1;
export const FIELD_KIND: 2;
export const FIELD_CHANNEL: 3;
export const FIELD_TIER: 4;
export const FIELD_SIGNER: 5;
export const FIELD_CREATED: 6;
export const FIELD_EFFECT: 7;
export const FIELD_CAUSES: 8;
export const FIELD_PROFILE: 9;
export const FIELD_BODY: 10;
export const FIELD_EXT: 11;
export const FIELD_CEXT: 12;
export const NAALP_VERSION: 1;
export class EnvelopeError extends Error {
    constructor(kind: any, msg?: string);
    kind: any;
}
export class Object_ {
    /**
     * A decoded N-AALP object body. `id` is set by sign() (content id §2.3).
     * @param {object} fields
     * @param {bigint|number} fields.kind object kind (§2.1)
     * @param {bigint|number} fields.channel channel id (§2.1)
     * @param {Uint8Array|number[]} fields.signer signer-id bytes
     * @param {bigint|number} fields.created creation time, epoch ms
     * @param {bigint|number} fields.effect closed effect label (§6)
     * @param {*} fields.body a CBOR value (e.g. new M([...]))
     * @param {bigint|number} [fields.tier] tier (default 0)
     * @param {bigint|number} [fields.profile] profile (default Public)
     * @param {Array<Uint8Array|number[]>|null} [fields.causes] causal parents
     * @param {*} [fields.ext] non-critical extensions map (field 11) or null
     * @param {*} [fields.cext] critical extensions map (field 12) or null
     */
    constructor({ kind, channel, signer, created, effect, body, tier, profile, causes, ext, cext }?: {
        kind: bigint | number;
        channel: bigint | number;
        signer: Uint8Array | number[];
        created: bigint | number;
        effect: bigint | number;
        body: any;
        tier?: bigint | number;
        profile?: bigint | number;
        causes?: Array<Uint8Array | number[]> | null;
        ext?: any;
        cext?: any;
    });
    id: any;
    kind: bigint;
    channel: bigint;
    tier: bigint;
    signer: Uint8Array<ArrayBuffer>;
    created: bigint;
    effect: bigint;
    causes: Uint8Array<ArrayBuffer>[];
    profile: bigint;
    body: any;
    ext: any;
    cext: any;
    bodyMap(includeId: any): cbor.M;
    contentId(): Uint8Array<ArrayBuffer>;
}
export { Object_ as Object };
import * as cbor from './cbor.mjs';
