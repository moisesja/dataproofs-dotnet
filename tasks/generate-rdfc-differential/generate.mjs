// Regenerates the RDFC-1.0 differential corpus: seeded datasets plus the canonical N-Quads that
// rdf-canonize, the implementation the reference Data Integrity stack signs with, produces for them.
// RdfCanonicalizationDifferentialTests checks them against this library byte for byte.
//
//   cd tasks/generate-rdfc-differential && npm install && npm run generate
//
// The seed is fixed, so a rerun with the same rdf-canonize version reproduces the file exactly.
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const rdfCanonize = require('rdf-canonize');
const { version } = require('rdf-canonize/package.json');

const PER_FAMILY = 170;
const OUTPUT = fileURLToPath(new URL('../../tests/fixtures/generated/rdfc-differential.json', import.meta.url));

// mulberry32: small, seedable, and the same in every Node version.
let state = 0x40404040;
function random() {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const int = (low, high) => low + Math.floor(random() * (high - low + 1));
const pick = list => list[int(0, list.length - 1)];

const LETTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'];
const predicate = letter => `<urn:p:${letter}>`;

// A tree of unnamed objects, the shape compact JSON-LD gives a credential.
function tree(maxNodes, literals, letters) {
  const quads = [];
  const nodes = int(3, maxNodes);
  for(let i = 1; i < nodes; i++) {
    quads.push(`_:n${int(0, i - 1)} ${predicate(pick(letters))} _:n${i} .`);
  }
  for(let i = 0; i < nodes; i++) {
    for(let j = int(0, 2); j > 0; j--) {
      quads.push(`_:n${i} <urn:p:name> "${pick(literals)}" .`);
    }
  }
  return quads;
}

// An arbitrary graph of blank nodes, self-references included.
function graph(maxNodes, letters) {
  const quads = [];
  const nodes = int(3, maxNodes);
  for(let i = int(nodes, 2 * nodes); i > 0; i--) {
    quads.push(`_:n${int(0, nodes - 1)} ${predicate(pick(letters))} _:n${int(0, nodes - 1)} .`);
  }
  return quads;
}

// A credential with an array of unnamed items, each optionally owning a nested object.
function credential(item) {
  const blankSubject = random() < 0.5;
  const subject = blankSubject ? '_:cs' : `<did:example:${int(0, 1e9)}>`;
  const id = `<urn:uuid:${int(0, 1e9)}>`;
  const quads = [`${id} <urn:p:credentialSubject> ${subject} .`, `${id} <urn:p:issuer> <did:example:issuer> .`];
  const letters = [pick(LETTERS), pick(LETTERS), pick(LETTERS), pick(LETTERS)];
  const shared = `"${int(0, 1e6)}"`;
  for(let i = int(2, 5) - 1; i >= 0; i--) {
    quads.push(`${subject} ${predicate(letters[0])} _:i${i} .`);
    quads.push(...item(i, letters, shared));
  }
  return quads;
}

// One blank node related to another through several named graphs, so its list of related nodes repeats.
function repeatedAcrossGraphs() {
  const quads = ['_:r <urn:p:name> "unique" .'];
  for(let i = int(2, 6) - 1; i >= 0; i--) {
    quads.push(`_:a <urn:p:a> _:r <urn:g:${i}> .`, `_:b <urn:p:a> _:r <urn:g:${i}> .`);
  }
  return quads;
}

// Predicates outside ASCII: RDFC-1.0 hashes the IRI as written, not percent-encoded.
function nonAsciiPredicates() {
  const letters = ['\u00e9', '\u65e5', '\u0416', '\ud83d\ude00', 'a'];
  const iri = () => `<https://e.example/${pick(letters)}>`;
  const quads = [];
  const nodes = int(4, 8);
  for(let i = 0; i < nodes; i++) {
    quads.push(`_:n${int(0, nodes - 1)} ${iri()} _:n${int(0, nodes - 1)} .`);
  }
  return quads;
}

const FAMILIES = {
  'tree, mostly distinct literals': () => tree(9, Array.from({ length: 40 }, (_, i) => `v${i}`), ['a', 'b', 'c']),
  'tree, few literals': () => tree(9, ['x', 'y'], ['a', 'b']),
  'tree, one literal and one predicate': () => tree(9, ['x'], ['a']),
  'graph with self-references': () => graph(6, ['a', 'b']),
  'credential, every object has its own value': () => credential((i, [, a, b, c]) => [
    `_:i${i} ${predicate(a)} "item-${i}-${int(0, 1e6)}" .`, `_:i${i} ${predicate(b)} _:c${i} .`, `_:c${i} ${predicate(c)} "child-${i}-${int(0, 1e6)}" .`]),
  'credential, identical flat items': () => credential((i, [, a], shared) => [`_:i${i} ${predicate(a)} ${shared} .`]),
  'credential, same-looking items with distinct children': () => credential((i, [, , b, c]) => [
    `_:i${i} ${predicate(b)} _:c${i} .`, `_:c${i} ${predicate(c)} "child-${i}-${int(0, 1e6)}" .`]),
  'credential, distinct items sharing a nested value': () => credential((i, [, a, b, c], shared) => [
    `_:i${i} ${predicate(a)} "item-${i}-${int(0, 1e6)}" .`, `_:i${i} ${predicate(b)} _:c${i} .`, `_:c${i} ${predicate(c)} ${shared} .`]),
  'credential, identical items with identical children': () => credential((i, [, , b, c], shared) => [
    `_:i${i} ${predicate(b)} _:c${i} .`, `_:c${i} ${predicate(c)} ${shared} .`]),
  'blank node repeated across graphs': repeatedAcrossGraphs,
  'non-ASCII predicates': nonAsciiPredicates,
};

const cases = [];
for(const [family, make] of Object.entries(FAMILIES)) {
  for(let i = 0; i < PER_FAMILY; i++) {
    const input = `${[...new Set(make())].join('\n')}\n`;
    // Every fifth case hashes with SHA-384, which the suites use for P-384 keys.
    const hash = i % 5 === 4 ? 'SHA384' : 'SHA256';
    const expected = await rdfCanonize.canonize(input, {
      algorithm: 'RDFC-1.0',
      inputFormat: 'application/n-quads',
      format: 'application/n-quads',
      messageDigestAlgorithm: hash.toLowerCase(),
      maxWorkFactor: 3,
      maxDeepIterations: 100000,
    });
    cases.push({ family, hash, input, expected });
  }
}

writeFileSync(OUTPUT, `${JSON.stringify({ generator: 'tasks/generate-rdfc-differential', rdfCanonize: version, cases }, null, 0)}\n`);
console.log(`wrote ${cases.length} cases from rdf-canonize ${version}`);
