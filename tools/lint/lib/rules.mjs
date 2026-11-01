// tools/lint/lib/rules.mjs
//
// Semantic rules over the catalogs: what JSON Schema cannot say. A rule is data:
//   { id, severity: 'error' | 'warn' | 'info', scope: ['threats' | 'controls' | 'assets'], title, run(ctx) }
// and `run` returns { findings: [{ ids: string[], message: string }], metrics?: object }.
// Severity is about intent, not about how unusual something looks (see lint.mjs for the policy):
//   error = a contradiction or impossibility whatever the author meant
//   warn  = what an entry declares and what it does disagree: the owner fixes it or accepts it (lint-allow.json)
//   info  = a fact or a measurement, never a verdict

import { DOMAINS, bind, boundKey, instanceClosure, keyOf, leavesOf, rawClosure, waysOf } from './closure.mjs';
import { CONVENTION, PROPERTIES, implied, rubricProblems, supports } from './rubric.mjs';
import { TAG_PATTERNS } from './tagPatterns.mjs';

const triple = (n) => `${n.action}:${n.assetClass}:${n.domain}`;
const uniq = (xs) => [...new Set(xs)];
const pct = (a, b) => (b === 0 ? 0 : Math.round((100 * a) / b));

/** Two nodes can describe the same capability in some analysis domain (a `*` side matches any domain). */
const compatible = (a, b) =>
    a.action === b.action && a.assetClass === b.assetClass && (a.domain === b.domain || a.domain === '*' || b.domain === '*');

function visitGates(cond, fn) {
    if (!cond || 'action' in cond) return;
    const children = cond.AND ?? cond.OR ?? [];
    fn(cond, cond.AND ? 'AND' : 'OR', children);
    for (const c of children) visitGates(c, fn);
}

/** Can the requirement be met without using any of the `banned` leaf nodes (compared by identity)? */
function satisfiableWithout(cond, banned) {
    if ('action' in cond) return !banned.includes(cond);
    if (cond.AND) return cond.AND.every((c) => satisfiableWithout(c, banned));
    return (cond.OR ?? []).some((c) => satisfiableWithout(c, banned));
}

/** Entry name, marked when it is an umbrella (a `refines` parent): consumers never use those as connectors. */
const label = (ctx, t) => (ctx.umbrellaT.has(t.id) ? `${t.name} [umbrella]` : t.name);

const requirementsOf = (ctx) => [
    ...ctx.threats.filter((t) => t.requires).map((t) => ({ id: t.id, field: 'requires', cond: t.requires })),
    ...ctx.controls.filter((c) => c.overriddenBy).map((c) => ({ id: c.id, field: 'overriddenBy', cond: c.overriddenBy })),
];

const domainsList = (ds) => (ds.length === DOMAINS.length ? 'all 8 domains' : ds.join(', '));

export const RULES = [
    // ---------------------------------------------------------------- controls as gates
    {
        id: 'S1a', severity: 'warn', scope: ['controls'],
        title: 'control whose declared bypass can never be satisfied: every way in its overriddenBy needs a capability the control itself denies (a deliberate hard block simply declares no overriddenBy; decide: hard block, real bypass, or accept)',
        run(ctx) {
            const findings = [];
            for (const c of ctx.controls) {
                if (!c.overriddenBy) continue;
                const bad = DOMAINS.filter((d) => {
                    const denied = new Set((c.denies ?? []).map((n) => boundKey(n, d)));
                    const ways = waysOf(c.overriddenBy, d);
                    return ways.length > 0 && ways.every((w) => w.some((k) => denied.has(k)));
                });
                if (bad.length) findings.push({ ids: [c.id], message: `${c.name}: self-defeating bypass in ${domainsList(bad)}` });
            }
            return { findings };
        },
    },
    {
        id: 'S1b', severity: 'info', scope: ['controls'],
        title: 'control that holds in an analysis domain because no declared bypass can be reached from the catalog (solid there; the whole catalog, no controls, cannot supply any way in overriddenBy)',
        run(ctx) {
            const findings = [];
            for (const c of ctx.controls) {
                if (!c.overriddenBy) continue;
                const bad = DOMAINS.filter((d) => {
                    const held = ctx.catalogClosure(d).held;
                    const denied = new Set((c.denies ?? []).map((n) => boundKey(n, d)));
                    return !waysOf(c.overriddenBy, d).some((w) => w.every((k) => held.has(k) && !denied.has(k)));
                });
                if (bad.length) findings.push({ ids: [c.id], message: `${c.name}: nothing in the catalog defeats it in ${domainsList(bad)}` });
            }
            return { findings };
        },
    },
    {
        id: 'S1c', severity: 'error', scope: ['controls'],
        title: 'control whose overriddenBy shares a capability with its denies (a bypass that needs what the control stops can never be taken)',
        run(ctx) {
            const findings = [];
            const alwaysDead = new Set(RULES.find((r) => r.id === 'S1a').run(ctx).findings.map((f) => f.ids[0]));
            for (const c of ctx.controls) {
                if (alwaysDead.has(c.id)) continue;
                const shared = [];
                for (const d of c.denies ?? []) for (const l of leavesOf(c.overriddenBy)) if (compatible(d, l)) shared.push(triple(l));
                if (shared.length) findings.push({ ids: [c.id], message: `${c.name}: overlap on ${uniq(shared).join(', ')}` });
            }
            return { findings };
        },
    },
    {
        id: 'S2', severity: 'warn', scope: ['controls'],
        title: "control that denies in a named domain, so it does nothing in the others (use `*` unless the control's own text ties it to the domain or to the border between two, a cloud service for example; record the reason in lint-allow.json)",
        run(ctx) {
            const findings = ctx.controls
                .filter((c) => (c.denies ?? []).some((d) => d.domain !== '*'))
                .map((c) => ({ ids: [c.id], message: `${c.name}: denies in ${uniq(c.denies.filter((d) => d.domain !== '*').map(triple)).join(', ')}` }));
            return { findings };
        },
    },
    {
        id: 'S18', severity: 'warn', scope: ['controls'],
        title: 'control that applies in a domain (it denies there, or in every domain with `*`) but whose way past it names only other domains, so it can never be bypassed there (say `*` if the bypass does not depend on the domain, or record intent in lint-allow.json)',
        run(ctx) {
            // a leaf can be met in domain d only when it names `*` or d; OR needs one such leaf, AND needs all
            const meetable = (cond, d) => (cond.action ? cond.domain === '*' || cond.domain === d : cond.AND ? cond.AND.every((x) => meetable(x, d)) : (cond.OR ?? []).some((x) => meetable(x, d)));
            const findings = [];
            for (const c of ctx.controls) {
                if (!c.overriddenBy) continue;
                const stuck = DOMAINS.filter((d) => (c.denies ?? []).some((g) => g.domain === '*' || g.domain === d) && !meetable(c.overriddenBy, d));
                if (stuck.length) findings.push({ ids: [c.id], message: `${c.name}: no way past it can be met in ${domainsList(stuck)} (its bypass names only ${uniq(leavesOf(c.overriddenBy).map((w) => w.domain)).join(', ')})` });
            }
            return { findings };
        },
    },
    {
        id: 'S3', severity: 'warn', scope: ['controls'],
        title: "child control whose domain scope differs from its parent's (wider: child has a domain the parent lacks; narrower: parent is `*`, child is concrete only)",
        run(ctx) {
            const findings = [];
            const domainsOfControl = (c) => new Set((c.denies ?? []).map((d) => d.domain));
            for (const c of ctx.controls) {
                const parent = c.refines && ctx.controlById.get(c.refines);
                if (!parent) continue;
                const cd = domainsOfControl(c);
                const pd = domainsOfControl(parent);
                const widens = [...cd].filter((d) => (d === '*' ? !pd.has('*') : !pd.has('*') && !pd.has(d)));
                const narrows = pd.has('*') && cd.size > 0 && !cd.has('*');
                if (widens.length) findings.push({ ids: [c.id, parent.id], message: `${c.name}: wider than ${parent.id} (adds ${widens.join(', ')})` });
                else if (narrows) findings.push({ ids: [c.id, parent.id], message: `${c.name}: narrower than ${parent.id} (only ${[...cd].join(', ')})` });
            }
            return { findings };
        },
    },
    {
        id: 'S13', severity: 'info', scope: ['controls'],
        title: 'control that denies nothing any concrete threat grants (it gates nothing)',
        run(ctx) {
            const grants = ctx.concrete.flatMap((t) => t.grants ?? []);
            const findings = ctx.controls
                .filter((c) => (c.denies ?? []).length > 0 && !c.denies.some((d) => grants.some((g) => compatible(d, g))))
                .map((c) => ({ ids: [c.id], message: `${c.name}: denies ${c.denies.map(triple).join(', ')}` }));
            return { findings };
        },
    },

    {
        id: 'S20', severity: 'warn', scope: ['threats'],
        title: 'threat whose name states a domain (Backend, Infotainment, ...) but which has a `*` capability, so in another domain it would act on that domain instead (name the domain, or drop it from the title if the effect really is domain-independent)',
        run(ctx) {
            const findings = [];
            for (const t of ctx.concrete) {
                const named = DOMAINS.filter((d) => new RegExp(`\\b${d}\\b`, 'i').test(t.name));
                if (!named.length) continue;
                const wild = [...leavesOf(t.requires), ...(t.grants ?? [])].filter((g) => g.domain === '*');
                if (wild.length) findings.push({ ids: [t.id], message: `${t.name}: names ${named.join(' and ')}, but ${uniq(wild.map(triple)).join(', ')}` });
            }
            return { findings };
        },
    },

    // ---------------------------------------------------------------- reachability and chaining
    {
        id: 'S4a', severity: 'error', scope: ['threats'],
        title: 'concrete threat that fires in no analysis domain (unreachable from any entry point)',
        run(ctx) {
            const findings = ctx.concrete.filter((t) => ctx.reach.get(t.id).length === 0).map((t) => ({ ids: [t.id], message: t.name }));
            return { findings };
        },
    },
    {
        id: 'S4b', severity: 'warn', scope: ['threats'],
        title: 'concrete threat that fires in some analysis domains but not all 8',
        run(ctx) {
            const findings = ctx.concrete
                .filter((t) => ctx.reach.get(t.id).length > 0 && ctx.reach.get(t.id).length < DOMAINS.length)
                .map((t) => {
                    const fires = ctx.reach.get(t.id);
                    return { ids: [t.id], message: `${t.name}: fires in ${fires.length} of 8 (${fires.join(', ')})` };
                });
            return { findings };
        },
    },
    {
        id: 'S5', severity: 'info', scope: ['threats'],
        title: 'single-root reach: share of the other concrete threats that fire when one zero-prerequisite threat is the only entry point (no controls)',
        run(ctx) {
            const domain = ctx.opts.domain;
            const others = ctx.nonRoot;
            const rows = ctx.roots.map((r) => {
                const c = rawClosure([r, ...others], domain);
                const fired = c.fired.size - 1;
                const keys = [`Inject:Network:${domain}`, `Elevate:Executable:${domain}`, `Execute:Peripheral:${domain}`].filter((k) => c.held.has(k));
                return { id: r.id, name: r.name, fired, share: pct(fired, others.length), keys };
            }).sort((a, b) => b.fired - a.fired);
            const shown = rows.filter((r) => r.share >= ctx.opts.reachShare);
            return {
                findings: shown.map((r) => ({
                    ids: [r.id],
                    message: `${r.name}: ${r.fired} of ${others.length} other threats fire (${r.share}%)${r.keys.length ? `; holds ${r.keys.join(', ')}` : ''}`,
                })),
                metrics: { domain, roots: ctx.roots.length, otherThreats: others.length, rootsAtOrAbove: ctx.opts.reachShare, rootsShown: shown.length, all: rows.map((r) => [r.id, r.fired]) },
            };
        },
    },
    {
        id: 'S8', severity: 'info', scope: ['threats'],
        title: 'zero-prerequisite concrete threat with `*` on grants (the attacker lands in whichever domain is analysed)',
        run(ctx) {
            const findings = ctx.roots
                .filter((t) => (t.grants ?? []).some((g) => g.domain === '*'))
                .map((t) => ({ ids: [t.id], message: `${t.name}: grants ${t.grants.filter((g) => g.domain === '*').map(triple).join(', ')}` }));
            return { findings };
        },
    },
    {
        id: 'S12', severity: 'error', scope: ['threats', 'controls'],
        title: 'requirement leaf that no other concrete threat can ever grant (unsatisfiable)',
        run(ctx) {
            const findings = [];
            for (const { id, field, cond } of requirementsOf(ctx)) {
                for (const leaf of leavesOf(cond)) {
                    const granted = ctx.concrete.some((t) => t.id !== id && (t.grants ?? []).some((g) => compatible(leaf, g)));
                    if (!granted) findings.push({ ids: [id], message: `${field} ${triple(leaf)} has no granting threat` });
                }
            }
            return { findings };
        },
    },

    // ---------------------------------------------------------------- compromises vs grants
    {
        id: 'S6a', severity: 'info', scope: ['threats'],
        title: 'consequence listing: compromises lists a property that no grant supports directly under the shape rubric (fine as a TARA worst case; it adds no outcome to a goal)',
        run(ctx) {
            const findings = [];
            let pairs = 0;
            let unsupportedPairs = 0;
            for (const t of ctx.threats) {
                const grants = t.grants ?? [];
                const supported = new Set(grants.flatMap((g) => supports(g)));
                for (const p of t.compromises ?? []) {
                    for (const g of grants) { pairs++; if (!supports(g).includes(p)) unsupportedPairs++; }
                }
                const missing = (t.compromises ?? []).filter((p) => !supported.has(p));
                if (missing.length) findings.push({ ids: [t.id], message: `${label(ctx, t)}: ${missing.join(', ')} not direct; grants ${uniq(grants.map((g) => `${g.action}:${g.assetClass}`)).join(', ') || 'none'}` });
            }
            return { findings, metrics: { threats: findings.length, concreteThreats: findings.filter((f) => !ctx.umbrellaT.has(f.ids[0])).length, pairs, unsupportedPairs } };
        },
    },
    {
        id: 'S6b', severity: 'warn', scope: ['threats'],
        title: "a grant's primary property (first in its rubric row, e.g. Extract -> Confidentiality, Modify / Inject / Execute / Elevate -> Integrity, Disrupt -> Availability) is not listed in compromises",
        run(ctx) {
            const findings = [];
            for (const t of ctx.threats) {
                const needed = uniq((t.grants ?? []).map((g) => implied(g)).filter(Boolean));
                const missing = needed.filter((p) => !(t.compromises ?? []).includes(p));
                if (missing.length) findings.push({ ids: [t.id], message: `${label(ctx, t)}: grants imply ${missing.join(', ')}, not listed` });
            }
            return { findings };
        },
    },
    {
        id: 'S6d', severity: 'warn', scope: ['threats'],
        title: 'goal with no outcome under the rubric (a property and domain that no concrete threat can satisfy); metrics list outcomes per property and domain, with the current engine count',
        run(ctx) {
            const findings = [];
            const table = {};
            // rubric: the capability's own action and class decide (compromises plays no part); current engine: every grant of a threat listing the property
            const shapesFor = (domain, property, rubric) => {
                const shapes = new Set();
                for (const t of ctx.concrete) {
                    if (!rubric && !(t.compromises ?? []).includes(property)) continue;
                    for (const g of t.grants ?? []) {
                        const b = bind(g, domain);
                        if (b.domain === domain && (!rubric || supports(g).includes(property))) shapes.add(keyOf(b));
                    }
                }
                return shapes.size;
            };
            for (const d of DOMAINS) {
                table[d] = {};
                for (const p of PROPERTIES) {
                    const rubric = shapesFor(d, p, true);
                    table[d][p] = { rubric, currentEngine: shapesFor(d, p, false) };
                    if (rubric === 0) findings.push({ ids: [], message: `${p} in ${d}: no outcome` });
                }
            }
            return { findings, metrics: { shapesPerPropertyByDomain: table } };
        },
    },
    {
        id: 'S6e', severity: 'error', scope: ['threats'],
        title: 'property rubric file (catalogs/property-rubric.json) is structurally invalid: every action needs a row (an empty list for none), properties must be known and unique',
        run() {
            return { findings: rubricProblems().map((p) => ({ ids: [], message: p })) };
        },
    },
    {
        id: 'S6c', severity: 'info', scope: ['threats'],
        title: "compromises lists a property that is unusual for the threat's granted actions, judged by the catalog's own majority convention (consistency, not correctness)",
        run(ctx) {
            const { MIN_N, SHARE } = CONVENTION;
            const count = new Map();
            const listed = new Map();
            for (const t of ctx.concrete) {
                for (const a of uniq((t.grants ?? []).map((g) => g.action))) {
                    count.set(a, (count.get(a) ?? 0) + 1);
                    const m = listed.get(a) ?? new Map();
                    for (const p of t.compromises ?? []) m.set(p, (m.get(p) ?? 0) + 1);
                    listed.set(a, m);
                }
            }
            const convention = new Map();
            for (const [a, n] of count) {
                if (n < MIN_N) continue;
                convention.set(a, new Set([...listed.get(a)].filter(([, c]) => c / n >= SHARE).map(([p]) => p)));
            }
            const findings = [];
            for (const t of ctx.concrete) {
                const actions = uniq((t.grants ?? []).map((g) => g.action)).filter((a) => convention.has(a));
                if (actions.length === 0) continue;
                const usual = new Set(actions.flatMap((a) => [...convention.get(a)]));
                const odd = (t.compromises ?? []).filter((p) => !usual.has(p));
                if (odd.length) findings.push({ ids: [t.id], message: `${t.name}: ${odd.join(', ')} unusual for ${actions.join(' + ')}` });
            }
            const table = Object.fromEntries([...convention].map(([a, s]) => [a, { threats: count.get(a), conventional: [...s] }]));
            return { findings, metrics: { convention: table } };
        },
    },

    // ---------------------------------------------------------------- structure (what the schema cannot see)
    {
        id: 'S7a', severity: 'info', scope: ['threats', 'controls'],
        title: 'AND / OR gate with a single child (style: equivalent to the bare node)',
        run(ctx) {
            const findings = [];
            for (const { id, field, cond } of requirementsOf(ctx)) {
                let n = 0;
                visitGates(cond, (g, k, children) => { if (children.length === 1) n++; });
                if (n) findings.push({ ids: [id], message: `${n} single-child gate(s) in ${field}` });
            }
            return { findings };
        },
    },
    {
        id: 'S7b', severity: 'info', scope: ['threats'],
        title: 'threat that grants (part of) its own requirement (a post-exploitation technique needs a foothold of that kind from elsewhere; "no other way to fire" says so)',
        run(ctx) {
            const findings = [];
            for (const t of ctx.threats) {
                if (!t.requires) continue;
                const own = leavesOf(t.requires).filter((l) => (t.grants ?? []).some((g) => compatible(l, g)));
                if (!own.length) continue;
                const escapes = satisfiableWithout(t.requires, own);
                findings.push({ ids: [t.id], message: `${label(ctx, t)}: grants its own ${uniq(own.map(triple)).join(', ')}${escapes ? ' (another way to fire exists)' : ' (no other way to fire)'}` });
            }
            return { findings, metrics: { concreteThreats: findings.filter((f) => !ctx.umbrellaT.has(f.ids[0])).length } };
        },
    },
    {
        id: 'S7c', severity: 'info', scope: ['threats', 'controls'],
        title: 'gate or list holding both a concrete-domain node and a `*` node for the same action and class (the concrete one adds cross-domain reach, or is redundant)',
        run(ctx) {
            const findings = [];
            const shadowed = (nodes) => {
                const out = [];
                for (const w of nodes.filter((l) => l.domain === '*'))
                    for (const c of nodes.filter((l) => l.domain !== '*' && l.action === w.action && l.assetClass === w.assetClass)) out.push(`${triple(c)} beside ${triple(w)}`);
                return out;
            };
            for (const { id, field, cond } of requirementsOf(ctx)) {
                const hits = [];
                visitGates(cond, (g, k, children) => hits.push(...shadowed(children.filter((c) => 'action' in c)).map((h) => `${h} in ${k}`)));
                if (hits.length) findings.push({ ids: [id], message: `${field}: ${hits.join('; ')}` });
            }
            for (const i of [...ctx.threats, ...ctx.controls]) {
                for (const field of ['grants', 'denies']) {
                    const hits = shadowed(i[field] ?? []);
                    if (hits.length) findings.push({ ids: [i.id], message: `${field}: ${hits.join('; ')}` });
                }
            }
            return { findings };
        },
    },
    {
        id: 'S7d', severity: 'error', scope: ['threats', 'controls', 'assets'],
        title: 'duplicate id; duplicate capability node in one list or gate; duplicate or empty metadata',
        run(ctx) {
            const findings = [];
            for (const [name, items] of [['threats', ctx.threats], ['controls', ctx.controls], ['assets', ctx.assets]]) {
                if (!ctx.kinds.includes(name)) continue;
                const seen = new Set();
                for (const i of items) {
                    if (seen.has(i.id)) findings.push({ ids: [i.id], message: 'duplicate id' });
                    seen.add(i.id);
                    const tags = i.metadata ?? [];
                    if (tags.length === 0) findings.push({ ids: [i.id], message: 'metadata is empty or missing' });
                    if (new Set(tags).size !== tags.length) findings.push({ ids: [i.id], message: 'duplicate metadata tag' });
                    for (const field of ['grants', 'denies']) {
                        const keys = (i[field] ?? []).map(triple);
                        if (new Set(keys).size !== keys.length) findings.push({ ids: [i.id], message: `duplicate node in ${field}` });
                    }
                    for (const cond of [i.requires, i.overriddenBy]) {
                        visitGates(cond, (g, k, children) => {
                            const keys = children.filter((c) => 'action' in c).map(triple);
                            if (new Set(keys).size !== keys.length) findings.push({ ids: [i.id], message: `duplicate node in a ${k} gate` });
                        });
                    }
                }
            }
            return { findings };
        },
    },
    {
        id: 'S7e', severity: 'error', scope: ['threats', 'controls', 'assets'],
        title: 'refines / partOf that does not point to an existing entry, or `refines` that is not the id-prefix parent',
        run(ctx) {
            const findings = [];
            const sets = { threats: ctx.threatById, controls: ctx.controlById, assets: ctx.assetById };
            for (const [name, items] of [['threats', ctx.threats], ['controls', ctx.controls], ['assets', ctx.assets]]) {
                if (!ctx.kinds.includes(name)) continue;
                for (const i of items) {
                    if (i.refines) {
                        const expected = i.id.replace(/\.[^.]+$/, '');
                        if (!sets[name].has(i.refines)) findings.push({ ids: [i.id], message: `refines ${i.refines}, which does not exist` });
                        else if (i.refines !== expected) findings.push({ ids: [i.id], message: `refines ${i.refines}, id prefix says ${expected}` });
                    }
                    if (i.partOf && !sets[name].has(i.partOf)) findings.push({ ids: [i.id], message: `partOf ${i.partOf}, which does not exist` });
                }
            }
            return { findings };
        },
    },
    {
        id: 'S7f', severity: 'warn', scope: ['threats', 'controls', 'assets'],
        title: 'field the schema does not define (the schemas do not set additionalProperties)',
        run(ctx) {
            const findings = [];
            for (const [name, items] of [['threats', ctx.threats], ['controls', ctx.controls], ['assets', ctx.assets]]) {
                if (!ctx.kinds.includes(name)) continue;
                const known = new Set(Object.keys(ctx.schemas[name]?.properties ?? {}));
                for (const i of items) {
                    const extra = Object.keys(i).filter((k) => !known.has(k));
                    if (extra.length) findings.push({ ids: [i.id], message: `unknown field(s): ${extra.join(', ')}` });
                }
            }
            return { findings };
        },
    },

    // ---------------------------------------------------------------- families and umbrellas
    {
        id: 'S9', severity: 'info', scope: ['threats'],
        title: 'same-name technique copies that differ in tags, requires or grants',
        run(ctx) {
            const groups = new Map();
            for (const t of ctx.threats) {
                const k = t.name.trim().toLowerCase();
                groups.set(k, [...(groups.get(k) ?? []), t]);
            }
            const findings = [];
            for (const g of groups.values()) {
                if (g.length < 2) continue;
                const differ = [];
                if (new Set(g.map((t) => JSON.stringify([...(t.metadata ?? [])].sort()))).size > 1) differ.push('metadata');
                if (new Set(g.map((t) => JSON.stringify(t.requires ?? null))).size > 1) differ.push('requires');
                if (new Set(g.map((t) => JSON.stringify((t.grants ?? []).map(triple).sort()))).size > 1) differ.push('grants');
                if (differ.length) findings.push({ ids: g.map((t) => t.id), message: `${g[0].name}: ${differ.join(', ')} differ` });
            }
            return { findings };
        },
    },
    {
        id: 'S11', severity: 'info', scope: ['threats'],
        title: "umbrella threat whose grants or tags are not covered by its children's",
        run(ctx) {
            const findings = [];
            for (const p of ctx.threats.filter((t) => ctx.umbrellaT.has(t.id))) {
                const kids = ctx.threats.filter((t) => t.refines === p.id);
                const kidGrants = new Set(kids.flatMap((k) => (k.grants ?? []).map(triple)));
                const kidTags = new Set(kids.flatMap((k) => k.metadata ?? []));
                const extraGrants = (p.grants ?? []).map(triple).filter((g) => !kidGrants.has(g));
                const extraTags = (p.metadata ?? []).filter((t) => !kidTags.has(t));
                const parts = [];
                if (extraGrants.length) parts.push(`grants no child grants: ${extraGrants.join(', ')}`);
                if (extraTags.length) parts.push(`tags no child has: ${extraTags.join(', ')}`);
                if (parts.length) findings.push({ ids: [p.id], message: `${p.name} (${kids.length} children): ${parts.join('; ')}` });
            }
            return { findings };
        },
    },

    // ---------------------------------------------------------------- metadata and assets
    {
        id: 'S10', severity: 'info', scope: ['threats', 'controls', 'assets'],
        title: 'tag vs text: entries naming a technology that has a dictionary tag but lack it, and entries carrying the tag without naming it (heuristic)',
        run(ctx) {
            const findings = [];
            const entries = [...(ctx.kinds.includes('threats') ? ctx.threats : []), ...(ctx.kinds.includes('controls') ? ctx.controls : []), ...(ctx.kinds.includes('assets') ? ctx.assets : [])];
            for (const [tag, re] of TAG_PATTERNS) {
                const missing = [];
                const extra = [];
                for (const e of entries) {
                    const named = re.test(`${e.name} ${e.description}`);
                    const has = (e.metadata ?? []).includes(tag);
                    if (named && !has) missing.push(e.id);
                    if (has && !named) extra.push(e.id);
                }
                if (missing.length || extra.length) {
                    const some = (ids) => (ids.length ? ` (${ids.slice(0, 8).join(' ')}${ids.length > 8 ? ` +${ids.length - 8}` : ''})` : '');
                    findings.push({
                        ids: [],
                        message: `${tag}: named in the text but not tagged on ${missing.length}${some(missing)}; tagged but not named on ${extra.length}${some(extra)}`,
                        detail: { tag, missing, extra },
                    });
                }
            }
            return { findings, metrics: { patterns: TAG_PATTERNS.length } };
        },
    },
    {
        id: 'S15', severity: 'info', scope: ['assets'],
        title: 'impact rationale that argues from threat scalability or attack effort (Fleet-Wide, per-device, physical access) instead of the damage scenario; the README keeps scalability on threats only',
        run(ctx) {
            const re = /fleet-wide|scalab|per-device|per-vehicle|single-vehicle|physical access/i;
            const findings = [];
            for (const a of ctx.assets) {
                const cells = [];
                for (const s of ['oem', 'roadUser', 'supplier'])
                    for (const c of ['safety', 'financial', 'operational', 'privacy']) {
                        const r = a.impact?.[s]?.[c]?.rationale ?? '';
                        if (re.test(r)) cells.push(`${s}.${c}`);
                    }
                if (cells.length) findings.push({ ids: [a.id], message: `${a.name}: ${cells.join(', ')}` });
            }
            return { findings, metrics: { assets: findings.length } };
        },
    },
    {
        id: 'S16', severity: 'warn', scope: ['assets'],
        title: 'oem.safety above None (README: an OEM has no direct physical-safety state; exposure from road-user harm belongs in oem.financial / oem.operational)',
        run(ctx) {
            const findings = ctx.assets
                .filter((a) => (a.impact?.oem?.safety?.level ?? 'None') !== 'None')
                .map((a) => ({ ids: [a.id], message: `${a.name}: oem.safety ${a.impact.oem.safety.level}` }));
            return { findings };
        },
    },
    {
        id: 'S17', severity: 'warn', scope: ['assets'],
        title: 'privacy impact rated above None while Confidentiality is not among the asset\'s cybersecurityProperties',
        run(ctx) {
            const findings = [];
            for (const a of ctx.assets) {
                const rated = ['oem', 'roadUser', 'supplier'].filter((s) => (a.impact?.[s]?.privacy?.level ?? 'None') !== 'None');
                if (rated.length && !(a.cybersecurityProperties ?? []).includes('Confidentiality'))
                    findings.push({ ids: [a.id], message: `${a.name}: privacy rated for ${rated.join(', ')}` });
            }
            return { findings };
        },
    },
    {
        id: 'S19', severity: 'warn', scope: ['assets'],
        title: 'asset whose name does not match the domain it is bound to (it names several domains but is bound to one: split it into one asset per domain; it names one domain but is bound to another or to `*`)',
        run(ctx) {
            const findings = [];
            for (const a of ctx.assets) {
                const named = DOMAINS.filter((d) => new RegExp(`\\b${d}\\b`, 'i').test(a.name));
                if (named.length > 1 && a.domain !== '*') findings.push({ ids: [a.id], message: `${a.name}: names ${named.join(' and ')}, bound to ${a.domain}` });
                else if (named.length === 1 && a.domain !== named[0]) findings.push({ ids: [a.id], message: `${a.name}: names ${named[0]}, bound to ${a.domain}` });
            }
            return { findings };
        },
    },
    {
        id: 'S14', severity: 'info', scope: ['assets'],
        title: 'asset bound to no domain (`*`)',
        run(ctx) {
            const wild = ctx.assets.filter((a) => a.domain === '*');
            return {
                findings: wild.length ? [{ ids: wild.map((a) => a.id), message: `${wild.length} of ${ctx.assets.length} assets have domain *` }] : [],
                metrics: { assets: ctx.assets.length, wildcard: wild.length },
            };
        },
    },
    {
        id: 'F1', severity: 'error', scope: ['threats'],
        title: 'starting point (no requires) without an attackVector, or an attackVector on a threat that is not a starting point',
        run(ctx) {
            const findings = [];
            const umbrellas = new Set(ctx.threats.filter((t) => t.refines).map((t) => t.refines));
            for (const t of ctx.threats) {
                if (!t.requires && !t.attackVector && !umbrellas.has(t.id)) findings.push({ ids: [t.id], message: `${t.name}: starting point with no attackVector` });
                if (t.requires && t.attackVector) findings.push({ ids: [t.id], message: `${t.name}: attackVector on a threat that needs something first` });
            }
            return { findings };
        },
    },
    {
        id: 'F2', severity: 'warn', scope: ['threats'],
        title: 'attack path too shallow: from remote (Network) starting points, code changes in an in-vehicle domain take fewer than 3 steps; from Physical ones, fewer than 2 (README "Layers of an attack path")',
        run(ctx) {
            const findings = [];
            const limits = { Network: 3, Physical: 2 };
            const metrics = {};
            for (const [vector, min] of Object.entries(limits)) {
                const held = instanceClosure(ctx.threats, vector);
                for (const d of ['Powertrain', 'Chassis', 'Body', 'ADAS']) {
                    for (const k of ['Modify:Executable', 'Elevate:Executable']) {
                        const round = held.get(`${k}:${d}`);
                        metrics[`${vector}.${k}:${d}`] = round ?? null;
                        if (round !== undefined && round < min) findings.push({ ids: [`${k}:${d}`], message: `${vector}: ${k}:${d} in ${round} step(s)` });
                    }
                }
            }
            return { findings, metrics };
        },
    },
];
