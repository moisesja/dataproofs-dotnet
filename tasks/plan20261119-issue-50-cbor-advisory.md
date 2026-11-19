# Plan — issue #50: lift `System.Formats.Cbor` above GHSA-vmv3-wvjp-wqpj

Branch `fix/issue-50-cbor-advisory`, from `origin/main` at `19c36e0`.

## Owner's intent

Issue #50, "Done when":

> `System.Formats.Cbor` is at 10.0.15 or later, and a DataProofs release carrying it is published.

This PR covers the first half. The release is prepared separately, after the six issues of this run, so
this PR picks no version number and touches no release file.

The impact the issue names: every consumer that treats warnings as errors fails restore with `NU1902`,
because the vulnerable version arrives transitively. credentials-dotnet `main` no longer restores.

## Findings before the change (`origin/main`, 2026-11-19, SDK 10.0.404)

- The advisory ([GHSA-vmv3-wvjp-wqpj](https://github.com/advisories/GHSA-vmv3-wvjp-wqpj), CVE-2026-118747,
  published 2026-11-10, read through `gh api /advisories/GHSA-vmv3-wvjp-wqpj`): "Colliding CBOR map keys can
  hash-flood uniqueness checks; the fix uses seeded Marvin hashing." Affected on the 10.x line:
  `>= 10.0.0-0, < 10.0.15`, patched in 10.0.15. The 11.x line is patched in 11.0.0.
- **Two** packages reference `System.Formats.Cbor` directly, not one: `DataProofsDotnet.Cose` (COSE_Sign1,
  CWT) and `DataProofsDotnet.Rdfc` (the bbs-2023 `proofValue`). `DataProofsDotnet.Legacy` (through Rdfc) and
  `DataProofsDotnet.Extensions.DependencyInjection` (through Cose and Rdfc) carry it transitively. The
  published 2.0.0 nuspecs of Cose and Rdfc both declare `System.Formats.Cbor` `10.0.8`. One pin in
  `Directory.Packages.props` serves both, so this is the same change, not a wider scope.
- The repository's own restore is red on `main`: `dotnet restore DataProofsDotnet.sln` exits 1 with 18
  `error NU1902: Warning As Error: Package 'System.Formats.Cbor' 10.0.8 ...` (every project whose graph holds
  Cose or Rdfc). The last `main` CI run (2026-11-02) predates the advisory, so it shows green.
- `dotnet list DataProofsDotnet.sln package --vulnerable --include-transitive --no-restore` (after a restore
  with `-p:TreatWarningsAsErrors=false`, since the listing restores first and fails otherwise) reports only
  `System.Formats.Cbor 10.0.8` (Moderate, GHSA-vmv3-wvjp-wqpj), in 18 projects. The other `10.0.8` pins
  (`Microsoft.Extensions.Logging.Abstractions`, `Microsoft.Extensions.DependencyInjection*`) are not flagged.
- `System.Formats.Cbor` 10.0.15 declares no dependency for `net10.0`, the same as 10.0.8, so the bump adds no
  package to any graph.

## Decisions

1. **Version: `10.0.15`.** The flat-container index lists `10.0.9` … `10.0.15` on the 10.x line and `11.0.0`
   as the newest version. 10.0.15 is both the newest 10.0.x patch and the first patched one.
   - *11.0.0* (also patched) lost: every package here targets `net10.0`, the other runtime pins are on the 10.x
     line, and a major-line move for one dependency is a choice the owner should make on its own merits, not
     inside an advisory fix. It would also raise the floor every consumer resolves to the 11.x line.
   - *A version range* such as `[10.0.15, 11.0.0)` lost: central package management already emits the pin as a
     `>= 10.0.15` minimum in the nuspec, which is what lets a consumer float to later patches, and the
     repository pins exact versions everywhere else.
2. **Scope: only `System.Formats.Cbor`.** The `Microsoft.Extensions.*` `10.0.8` pins carry no advisory (the
   listing above), so lifting them for symmetry would raise the DI package's floor for consumers with no cause.
   The `Microsoft.Extensions.DependencyInjection:10.0.8` prerequisite in `ci.yml` `ac-10` and in
   `tasks/smoke/DependencyInjection` stays for the same reason.
3. **CHANGELOG under `## [Unreleased]` → `### Security`**, naming the advisory, the CVE, the new version, both
   packages that reference it directly and the two that carry it transitively, that no API, behaviour or
   emitted byte changes, and what a consumer does now: upgrade to the release, or until then add a direct
   `System.Formats.Cbor` `10.0.15` reference (verified below before it is written down).
4. **No PRD change.** The PRD names `System.Formats.Cbor` as Cose's and Rdfc's dependency without a version,
   and no requirement changes.
5. **The `Directory.Packages.props` comment** records why the pin sits where it does, in the style of the
   AngleSharp and SourceLink entries.

## Items

- [x] Read the brief, `CLAUDE.md`, `CONTRIBUTING.md`, `RELEASING.md`, all of `tasks/lessons.md`
- [x] Reproduce the failure on `main` (solution restore, vulnerability listing)
- [x] Choose the version from the flat-container index; record the alternatives
- [ ] Bump the pin; CHANGELOG entry
- [ ] Vulnerability listing after: no vulnerable package in any project
- [ ] Consumer reproduction under warnings-as-errors: published 2.0.0 fails, the branch's packed packages restore
      clean, the documented workaround restores clean
- [ ] Packed nuspecs of Cose and Rdfc declare `System.Formats.Cbor` `10.0.15`
- [ ] `dotnet build DataProofsDotnet.sln -c Release /warnaserror` clean
- [ ] `dotnet test DataProofsDotnet.sln -c Release`: all pass, zero skips
- [ ] Gates: `ac-6` dependency hygiene, `ac-10` pack and smoke, `ac-12` JIT legs
- [ ] Adversarial pass (narrow, 20 minutes): does 10.0.15 actually restore and ship, and does anything still
      resolve a vulnerable version
- [ ] PR, CI green

## Review

(Filled in as review rounds happen.)
