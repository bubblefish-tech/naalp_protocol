export function signerId(alg: any, pubkey: any): string;
export function checkSigner(claimed: any, alg: any, pubkey: any): void;
export function requireNFC(s: any): void;
export class UnknownAlg extends Error {
    constructor(m: any);
    kind: string;
}
export class SignerMismatch extends Error {
    constructor(m: any);
    kind: string;
}
export class NonNFC extends Error {
    constructor(m: any);
    kind: string;
}
