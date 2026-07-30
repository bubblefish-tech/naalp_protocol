export function encode(v: any): any;
export function decode(data: any): any;
export function contentId(body: any): Uint8Array<ArrayBuffer>;
export class NonCanonical extends Error {
    constructor(msg: any);
    kind: string;
}
export class U {
    constructor(v: any);
    v: bigint;
}
export class N {
    constructor(v: any);
    v: bigint;
}
export class B {
    constructor(v: any);
    v: Uint8Array<ArrayBuffer>;
}
export class T {
    constructor(v: any);
    v: string;
}
export class A {
    constructor(items: any);
    items: any[];
}
export class M {
    constructor(pairs: any);
    pairs: any[];
}
export class Tag {
    constructor(n: any, content: any);
    n: bigint;
    content: any;
}
