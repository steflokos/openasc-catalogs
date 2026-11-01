// tools/lint/lint.mjs
//
// Semantic lint for the catalogs: the checks JSON Schema (scripts/validate.js) cannot express. It reads the
// catalogs and never modifies them.
//
//   node tools/lint/lint.mjs [threats|controls|assets|all] [--json] [--strict] [--domain <Domain>] [--share <0-100>]
//                         [--rule S1a,S4a] [--limit <n|all>]
//
//   --strict   exit 1 when any `error` rule has findings (off by default: the catalogs are being cleaned up)
//   --json     machine-readable output, stable enough to diff before/after a change
//   --domain   analysis domain for the single-root reach rule S5 (default Powertrain)
//   --share    S5 lists roots that make at least this percent of the other threats fire (default 25)
//   --rule     run only these rule ids
//   --limit    findings printed per rule in text mode (default 10)
//
// Severity is about intent, not about how unusual something looks. A solid control, a threat that needs a foothold of
// its own kind, an asset that is not bound to one domain: none of these is wrong by itself.
//   error  a contradiction or impossibility whatever the author meant (duplicate id, dangling `refines`, a requirement
//          nothing can ever grant)
//   warn   what an entry declares and what it does disagree; the owner decides to fix it or to accept it
//   info   a fact or a measurement, never a verdict
// Accepting a finding is recorded in lint-allow.json with a reason: { "S2": { "C.03.9": "Backend-only by nature" } }.
// An accepted finding leaves the list and is counted ("N accepted"), never hidden. The key is the finding's first id.
//
// Rules live in lib/rules.mjs, the capability calculus in lib/closure.mjs (mirrors the openasc.org engine),
// the draft property rubric in lib/rubric.mjs, and the tag text patterns in lib/tagPatterns.mjs.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DOMAINS, rawClosure, umbrellaIds } from './lib/closure.mjs';
import { RULES } from './lib/rules.mjs';
import { TAG_PATTERNS } from './lib/tagPatterns.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const readJson = (rel, fallback) => {
    const file = path.join(root, rel);
    if (!fs.existsSync(file)) {
        if (fallback !== undefined) return fallback;
        throw new Error(`missing file: ${rel}`);
    }
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
};

// ---- arguments
const args = process.argv.slice(2);
const flag = (name) => args.includes(`--${name}`);
const option = (name, fallback) => {
    const at = args.indexOf(`--${name}`);
    return at >= 0 && args[at + 1] !== undefined ? args[at + 1] : fallback;
};
const VALUE_OPTIONS = ['--domain', '--share', '--rule', '--limit'];
const positional = args.filter((a, i) => !a.startsWith('--') && !VALUE_OPTIONS.includes(args[i - 1]));
const target = positional[0] ?? 'all';
if (!['all', 'threats', 'controls', 'assets'].includes(target)) {
    console.error(`Unknown target "${target}". Use threats, controls, assets or all.`);
    process.exit(2);
}
const kinds = target === 'all' ? ['threats', 'controls', 'assets'] : [target];
const domain = option('domain', 'Powertrain');
if (!DOMAINS.includes(domain)) {
    console.error(`Unknown domain "${domain}". Use one of ${DOMAINS.join(', ')}.`);
    process.exit(2);
}
const reachShare = Number(option('share', 25));
const onlyRules = option('rule', '')?.split(',').filter(Boolean) ?? [];
const limitArg = option('limit', '10');
const limit = limitArg === 'all' ? Infinity : Number(limitArg);

// ---- context
const threats = readJson('catalogs/threats.json').threats;
const controls = readJson('catalogs/controls.json').controls;
const assets = readJson('catalogs/assets.json').assets;
const schemas = {
    threats: readJson('schemas/threat.schema.json'),
    controls: readJson('schemas/control.schema.json'),
    assets: readJson('schemas/asset.schema.json'),
};

const umbrellaT = umbrellaIds(threats);
const concrete = threats.filter((t) => !umbrellaT.has(t.id));
const closures = new Map();
const catalogClosure = (d) => {
    if (!closures.has(d)) closures.set(d, rawClosure(concrete, d));
    return closures.get(d);
};
const reach = new Map(concrete.map((t) => [t.id, DOMAINS.filter((d) => catalogClosure(d).fired.has(t.id))]));

const ctx = {
    threats, controls, assets, schemas, kinds,
    umbrellaT,
    umbrellaC: umbrellaIds(controls),
    concrete,
    roots: concrete.filter((t) => !t.requires),
    nonRoot: concrete.filter((t) => t.requires),
    threatById: new Map(threats.map((t) => [t.id, t])),
    controlById: new Map(controls.map((c) => [c.id, c])),
    assetById: new Map(assets.map((a) => [a.id, a])),
    allow: readJson('tools/lint/lint-allow.json', {}),
    opts: { domain, reachShare },
    catalogClosure,
    reach,
};

// the tag patterns must use tags that exist in the dictionary the schema enforces
const dictionary = new Set(schemas.threats.properties.metadata.items.enum);
const stray = TAG_PATTERNS.map(([tag]) => tag).filter((tag) => !dictionary.has(tag));
if (stray.length) console.error(`lint: tagPatterns.mjs uses tags that are not in the schema dictionary: ${stray.join(', ')}`);

// ---- run
const selected = RULES.filter((r) => r.scope.some((s) => kinds.includes(s)) && (onlyRules.length === 0 || onlyRules.includes(r.id)));
const knownIds = new Set([...threats, ...controls, ...assets].map((e) => e.id));
for (const [ruleId, entries] of Object.entries(ctx.allow)) {
    if (!RULES.some((r) => r.id === ruleId)) console.error(`lint: lint-allow.json names an unknown rule "${ruleId}"`);
    for (const id of Object.keys(entries)) if (!knownIds.has(id)) console.error(`lint: lint-allow.json accepts "${id}" for ${ruleId}, but no such entry exists`);
}

const results = selected.map((rule) => {
    const { findings: all, metrics } = rule.run(ctx);
    const accepts = ctx.allow[rule.id] ?? {};
    const accepted = all.filter((f) => f.ids.length > 0 && accepts[f.ids[0]] !== undefined).map((f) => ({ id: f.ids[0], reason: accepts[f.ids[0]] }));
    const findings = all.filter((f) => !(f.ids.length > 0 && accepts[f.ids[0]] !== undefined));
    return { id: rule.id, severity: rule.severity, scope: rule.scope, title: rule.title, count: findings.length, accepted: accepted.length, findings, ...(accepted.length ? { acceptedBy: accepted } : {}), ...(metrics ? { metrics } : {}) };
});

if (flag('json')) {
    console.log(JSON.stringify({
        catalogs: { threats: threats.length, concreteThreats: concrete.length, umbrellaThreats: umbrellaT.size, controls: controls.length, assets: assets.length },
        rules: results,
    }, null, 2));
} else {
    console.log(`OpenASC semantic lint: ${threats.length} threats (${concrete.length} concrete, ${umbrellaT.size} umbrella), ${controls.length} controls, ${assets.length} assets`);
    console.log(`Target: ${target}. Analysis domains for reachability: ${DOMAINS.length}. Single-root reach domain: ${domain}.`);
    const label = { error: 'ERROR', warn: 'WARN ', info: 'INFO ' };
    for (const r of results) {
        console.log(`\n[${r.id} ${label[r.severity]}] ${r.title}: ${r.count} finding${r.count === 1 ? '' : 's'}${r.accepted ? `, ${r.accepted} accepted by design` : ''}`);
        for (const f of r.findings.slice(0, limit)) {
            const ids = f.ids.length > 6 ? `${f.ids.slice(0, 6).join(' ')} +${f.ids.length - 6}` : f.ids.join(' ');
            console.log(`    ${ids ? `${ids.padEnd(8)}  ` : ''}${f.message}`);
        }
        if (r.findings.length > limit) console.log(`    ... ${r.findings.length - limit} more (use --limit all)`);
    }
    const bySeverity = (s) => results.filter((r) => r.severity === s && r.count > 0);
    console.log('\nSummary');
    for (const s of ['error', 'warn', 'info']) {
        const rs = bySeverity(s);
        console.log(`  ${label[s]} ${rs.length} rule(s) with findings: ${rs.map((r) => `${r.id}=${r.count}`).join(' ') || '-'}`);
    }
    const acceptedTotal = results.reduce((n, r) => n + r.accepted, 0);
    if (acceptedTotal) console.log(`  ${acceptedTotal} finding(s) accepted by design (lint-allow.json)`);
}

const errors = results.filter((r) => r.severity === 'error' && r.count > 0);
if (flag('strict') && errors.length) process.exitCode = 1;
