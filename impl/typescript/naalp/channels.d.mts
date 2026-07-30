export function lookup(channel: any, kind: any): (string | number | boolean)[];
export function checkEffect(channel: any, kind: any, effect: any): void;
export class UnknownKind extends Error {
    constructor(m: any);
    kind: string;
}
export class EffectDeclarationMismatch extends Error {
    constructor(m: any);
    kind: string;
}
