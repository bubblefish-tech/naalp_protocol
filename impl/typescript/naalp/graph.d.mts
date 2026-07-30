export function verifyCausal(nodes: any): void;
export function reconcile(nodes: any): any[];
export function reconcileRecord(authorities: any, order: any): any;
export class CausalViolation extends Error {
    constructor(m: any);
    kind: string;
}
