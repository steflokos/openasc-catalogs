// tools/lint/lib/closure.mjs
//
// The capability calculus the catalogs are written for, as a few small pure functions. This mirrors the
// consumer in the openasc.org site (src/engine/capabilityHandler.ts and src/engine/attackPathEngine.ts,
// `computeClosure` with no active controls): every "*" domain binds to the single analysis domain, a
// requirement is an AND/OR tree of Action:Class:Domain nodes, and threats fire in leveled rounds, each round
// seeing only what was held at the end of the previous one. If the site engine changes, change this too.

export const DOMAINS = ['Powertrain', 'Chassis', 'Body', 'Infotainment', 'ADAS', 'Telematics', 'Backend', 'External'];

const MAX_WAYS = 64;

export function bind(node, domain) {
    return node.domain === '*' ? { action: node.action, assetClass: node.assetClass, domain } : node;
}

export const keyOf = (node) => `${node.action}:${node.assetClass}:${node.domain}`;

export const boundKey = (node, domain) => keyOf(bind(node, domain));

const isLeaf = (cond) => 'action' in cond;

/** All capability nodes in a requirement tree, in order. */
export function leavesOf(cond, out = []) {
    if (!cond) return out;
    if (isLeaf(cond)) out.push(cond);
    else for (const child of cond.AND ?? cond.OR ?? []) leavesOf(child, out);
    return out;
}

export function satisfied(cond, held, domain) {
    if (!cond) return true;
    if (isLeaf(cond)) return held.has(boundKey(cond, domain));
    if (cond.AND) return cond.AND.every((c) => satisfied(c, held, domain));
    if (cond.OR) return cond.OR.some((c) => satisfied(c, held, domain));
    return true;
}

/** Disjunctive normal form: each way is the set of bound capability keys that together satisfy the tree. */
export function waysOf(cond, domain) {
    if (!cond) return [[]];
    if (isLeaf(cond)) return [[boundKey(cond, domain)]];
    if (cond.AND) {
        let ways = [[]];
        for (const child of cond.AND) {
            const childWays = waysOf(child, domain);
            const next = [];
            for (const a of ways) for (const b of childWays) next.push([...new Set([...a, ...b])]);
            ways = next.slice(0, MAX_WAYS);
        }
        return ways;
    }
    if (cond.OR) return cond.OR.flatMap((c) => waysOf(c, domain)).slice(0, MAX_WAYS);
    return [[]];
}

/** `refines` targets: the umbrella entries. Consumers never use them as connectors. */
export function umbrellaIds(items) {
    return new Set(items.filter((i) => i.refines).map((i) => i.refines));
}

/**
 * Raw closure (no controls) of `pool` in `domain`: which threats fire, in which round, and which capabilities
 * end up held. Same fixpoint as computeClosure with an empty active-control set.
 */
export function rawClosure(pool, domain) {
    const held = new Map();
    const fired = new Map();
    let round = 0;
    let changed = true;
    while (changed) {
        changed = false;
        const snapshot = new Set(held.keys());
        const granted = [];
        for (const t of pool) {
            if (fired.has(t.id) || !satisfied(t.requires, snapshot, domain)) continue;
            fired.set(t.id, round);
            changed = true;
            for (const g of t.grants ?? []) granted.push(boundKey(g, domain));
        }
        for (const k of granted) if (!held.has(k)) held.set(k, round);
        round++;
    }
    return { fired, held, rounds: round };
}
