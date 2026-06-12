# Provenance — W3C RDF Dataset Canonicalization (RDFC-1.0) test suite

Vendored per `dataproofs-prd.md` AC-2.

## Origin

- **Repository:** https://github.com/w3c/rdf-canon
- **Git commit SHA (pinned):** `15619df2fda7a4ca88308733789b6774517f9638`
  (commit date 2026-02-24, "Automated report generation")
- **Source path within repository:** `tests/`
- **Retrieval method:** `git clone --depth 1 https://github.com/w3c/rdf-canon`
- **Retrieval date:** 2026-06-11

## Contents (local transformations: none — all files are byte-identical copies)

| Local path | Source path | Notes |
|---|---|---|
| `manifest.jsonld` | `tests/manifest.jsonld` | Machine-readable manifest (JSON-LD, inline `@context`, self-contained offline). Primary manifest for the test runner. |
| `manifest.ttl` | `tests/manifest.ttl` | Same manifest in Turtle, kept intact as the canonical W3C form. |
| `rdfc10/` | `tests/rdfc10/` | All 150 test-case files: 129 `.nq` (inputs `testNNN-in.nq` and expected canonical outputs `testNNN-rdfc10.nq`) and 21 `.json` (expected issued-identifier maps `testNNN-rdfc10map.json`). |
| `LICENCE.md` | `tests/LICENCE.md` | W3C Test Suite License / W3C 3-clause BSD License. |
| `README.md` | `tests/README.md` | Upstream description of test types and execution. |

Upstream files NOT vendored (generator tooling and rendered docs, not needed by a
manifest-driven runner): `index.html`, `manifest` (rendered HTML), `manifest.csv`
(editing source from which the `.ttl`/`.jsonld` manifests are generated),
`mk_manifest.rb`, `mk_vocab.rb`, `template.haml`, `vocab_template.haml`,
`vocab.html`, `vocab.jsonld`, `vocab.ttl`, `vocab_context.jsonld`.

## Fixture counts (AC-2 count assertion)

- **Total manifest entries: 86** (identical in `manifest.jsonld` `entries` and
  `manifest.ttl` `a rdfc:RDFC10*Test` subjects). AC-2 asserts the test-run count
  matches this number.
- By type:
  - `rdfc:RDFC10EvalTest` (canonicalization, byte-compare against `*-rdfc10.nq`): **64**
  - `rdfc:RDFC10MapTest` (issued-identifier map, compare against `*-rdfc10map.json`): **21**
  - `rdfc:RDFC10NegativeEvalTest` (must fail/abort): **1** (`#test074c`, 10-node
    blank-node clique "poison" graph; has an `action` but no `result`)
- Test-case files in `rdfc10/`: **150**; every file referenced by a manifest
  `action`/`result` exists, and no file on disk is unreferenced (verified at
  vendoring time).
- Entries carrying a non-default `hashAlgorithm` ("SHA384"): **2**
  (`#test075c`, `#test075m`). All other entries use the RDFC-1.0 default SHA-256.

## Integrity verification performed at vendoring time

- `diff -rq` between the cloned `tests/rdfc10/` and the vendored `rdfc10/`: byte-identical.
- `cmp` on both manifest files: byte-identical.
- Manifest cross-check: 86 entries in `manifest.jsonld` == 86 typed test subjects
  in `manifest.ttl`; 150 distinct referenced files, 0 missing, 0 orphaned.
