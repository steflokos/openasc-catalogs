// tools/lint/lib/rubric.mjs
//
// Reads catalogs/property-rubric.json: which granted capabilities count as "this security property is compromised", the
// outcomes of a goal (README, section "Outcomes"). It is a different question from what `compromises` lists:
// `compromises` is the TARA-facing, worst-case damage list and stays as the author wrote it; the rubric decides which
// grants ARE the compromise, so a goal is not satisfied by every capability a listing threat happens to grant.
//
// The openasc.org site keeps an embedded copy of this table (src/engine/propertyRubric.ts) and its tests compare the two.
// Rules S6a-S6e use it. CONVENTION below is the catalog's own majority practice, measured from the data by rule S6c,
// kept as information for comparison.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROPERTIES = ['Confidentiality', 'Integrity', 'Availability', 'Authenticity', 'Non Repudiation'];
export const ACTIONS = ['Extract', 'Intercept', 'Modify', 'Inject', 'Disrupt', 'Execute', 'Elevate', 'Fault'];

const file = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../catalogs/property-rubric.json');
export const RUBRIC = JSON.parse(fs.readFileSync(file, 'utf-8'));

/** Structural problems in the rubric file, as plain strings (empty = valid). Reported by rule S6e. */
export function rubricProblems(rubric = RUBRIC) {
    const problems = [];
    const checkRow = (where, row) => {
        if (!Array.isArray(row)) return problems.push(`${where}: not an array`);
        const bad = row.filter((p) => !PROPERTIES.includes(p));
        if (bad.length) problems.push(`${where}: unknown property ${bad.join(', ')}`);
        if (new Set(row).size !== row.length) problems.push(`${where}: duplicate property`);
    };
    for (const a of ACTIONS) if (!(rubric.byAction ?? {})[a]) problems.push(`byAction: missing action ${a} (use an empty list for none)`);
    for (const [a, row] of Object.entries(rubric.byAction ?? {})) {
        if (!ACTIONS.includes(a)) problems.push(`byAction: unknown action ${a}`);
        checkRow(`byAction.${a}`, row);
    }
    for (const [k, row] of Object.entries(rubric.byActionClass ?? {})) {
        if (!/^[A-Z][a-z]+:[A-Z][a-z]+$/.test(k) || !ACTIONS.includes(k.split(':')[0])) problems.push(`byActionClass: bad key ${k}`);
        checkRow(`byActionClass.${k}`, row);
    }
    return problems;
}

/** The properties this granted capability counts as compromising (a row keyed on the capability's action and class only). */
export function supports(grant, rubric = RUBRIC) {
    return rubric.byActionClass?.[`${grant.action}:${grant.assetClass}`] ?? rubric.byAction?.[grant.action] ?? [];
}

/** The primary property of a grant (first in its row), which a threat granting it should list in `compromises` (rule S6b). */
export function implied(grant, rubric = RUBRIC) {
    return supports(grant, rubric)[0] ?? null;
}

/** CONVENTION parameters (rule S6c): an action needs at least MIN_N concrete threats granting it, and a property is "conventional" for it at SHARE or more. */
export const CONVENTION = { MIN_N: 5, SHARE: 0.6 };
