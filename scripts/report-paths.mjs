// scripts/report-paths.mjs
//
// How deep the attack paths in the catalog are. Every `*` threat and control is instantiated once per domain (both
// sides bound to that domain); named-domain entries stay as they are and are the only way between domains. From the
// starting points (threats with no `requires`, optionally only those of one attack vector) it runs the fixpoint and
// prints, per domain, the round in which key capabilities are first held (round 1 = a starting point gives it), how
// much of the catalog fires, and how many control instances end up bypassed.
//
//   node scripts/report-paths.mjs            all starting points
//   node scripts/report-paths.mjs --json     machine-readable
import { readFileSync } from 'node:fs';
import { DOMAINS, bind, boundKey, satisfied, umbrellaIds } from '../tools/lint/lib/closure.mjs';

const load = (f) => JSON.parse(readFileSync(new URL(`../catalogs/${f}.json`, import.meta.url), 'utf8'));
const threats = load('threats').threats;
const controls = load('controls').controls;
const isTemplate = (t) => JSON.stringify([t.requires ?? null, t.grants ?? [], t.denies ?? [], t.overriddenBy ?? null]).includes('"domain":"*"');

function instances(items) {
    const umbrellas = umbrellaIds(items);
    const out = [];
    for (const t of items) {
        if (umbrellas.has(t.id)) continue;
        if (isTemplate(t)) for (const d of DOMAINS) out.push({ ...t, id: `${t.id}@${d}`, base: t.id, domain: d });
        else out.push({ ...t, base: t.id, domain: 'Telematics' }); // named entries: binding domain is irrelevant
    }
    return out;
}

const TI = instances(threats);
const CI = instances(controls);

function closure(vector) {
    const held = new Map();
    const fired = new Map();
    const by = new Map();
    let round = 0;
    for (let changed = true; changed; ) {
        changed = false;
        round++;
        const snap = new Set(held.keys());
        const granted = [];
        for (const t of TI) {
            if (fired.has(t.id)) continue;
            if (!t.requires && vector && t.attackVector && t.attackVector !== vector) continue;
            if (!t.requires && vector && !t.attackVector) continue;
            if (!satisfied(t.requires, snap, t.domain)) continue;
            fired.set(t.id, round);
            changed = true;
            for (const g of t.grants ?? []) granted.push([boundKey(g, t.domain), t]);
        }
        for (const [k, t] of granted) if (!held.has(k)) { held.set(k, round); by.set(k, t); }
    }
    return { held, fired, by };
}

const KEYS = ['Execute:Executable', 'Elevate:Executable', 'Modify:Executable', 'Modify:Data', 'Execute:Peripheral', 'Inject:Network'];
const VECTORS = [null, 'Network', 'Adjacent', 'Local', 'Physical'];
const report = { threats: threats.length, controls: controls.length, threatInstances: TI.length, controlInstances: CI.length, vectors: {} };
for (const v of VECTORS) {
    const { held, fired } = closure(v);
    const perDomain = {};
    for (const d of DOMAINS) {
        const row = {};
        for (const k of KEYS) row[k] = held.get(`${k}:${d}`) ?? null;
        row.fired = TI.filter((t) => t.domain === d && isTemplate(t) && fired.has(t.id)).length;
        perDomain[d] = row;
    }
    const bypassed = CI.filter((c) => !c.overriddenBy || satisfied(c.overriddenBy, new Set(held.keys()), c.domain)).length;
    report.vectors[v ?? 'Any'] = { fired: fired.size, bypassed, perDomain };
}

// --why Modify:Executable:Powertrain [--vector Network]: one shortest chain that gives it
const why = process.argv.indexOf('--why');
if (why > 0) {
    const vi = process.argv.indexOf('--vector');
    const { held, by } = closure(vi > 0 ? process.argv[vi + 1] : null);
    const seen = new Set();
    const explain = (key, depth) => {
        const t = by.get(key);
        if (!t) { console.log(`${'  '.repeat(depth)}${key}: never`); return; }
        console.log(`${'  '.repeat(depth)}${key} (round ${held.get(key)}) <- ${t.id} ${t.name}${t.attackVector ? ` [${t.attackVector}]` : ''}`);
        if (seen.has(t.id)) return;
        seen.add(t.id);
        const leaves = [];
        const walk = (c) => { if (!c) return; if (c.action) leaves.push(boundKey(c, t.domain)); else if (c.AND) c.AND.forEach(walk); else if (c.OR) { const ok = c.OR.filter((x) => !x.action || held.has(boundKey(x, t.domain))); const best = ok.sort((a, b) => (held.get(boundKey(a, t.domain)) ?? 99) - (held.get(boundKey(b, t.domain)) ?? 99))[0]; walk(best); } };
        walk(t.requires);
        for (const l of leaves) explain(l, depth + 1);
    };
    explain(process.argv[why + 1], 0);
    process.exit(0);
}
if (process.argv.includes('--json')) { console.log(JSON.stringify(report, null, 2)); process.exit(0); }
console.log(`${report.threats} threats (${report.threatInstances} instances), ${report.controls} controls (${report.controlInstances} instances)`);
console.log('Round in which a capability is first held (1 = a starting point gives it; - = never)');
for (const [v, r] of Object.entries(report.vectors)) {
    console.log(`\n## Starting points: ${v}  - ${r.fired} threat instances fire, ${r.bypassed}/${report.controlInstances} control instances can be bypassed`);
    console.log(['Domain'.padEnd(13), ...KEYS.map((k) => k.padEnd(19))].join(''));
    for (const [d, row] of Object.entries(r.perDomain)) console.log([d.padEnd(13), ...KEYS.map((k) => String(row[k] ?? '-').padEnd(19))].join(''));
}
