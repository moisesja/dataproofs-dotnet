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
   AngleSharp and SourceLink entries. It also said "Cose only", which was already wrong (Rdfc's bbs-2023
   `proofValue` uses it), so it now names both.
6. **The `ac-10` gate is fixed in this PR (adversarial finding, own commit).** The adversarial pass showed the
   smoke can pass while testing the published, vulnerable 2.0.0: `ac-10` packs at the dev-default
   `DataProofsVersion`, which is 2.0.0, the published version, and a package cache that already holds the
   published `DataProofsDotnet.Cose` 2.0.0 serves it in place of the packed one. The smoke then resolved
   `System.Formats.Cbor` 10.0.8 and passed with only a `NU1902` warning, because the temp console app is
   outside the repository and does not treat warnings as errors. Reachability: on a fresh GitHub runner the
   cache starts empty and `dotnet add package --source <feed>` restores only from the feed (SDK 10.0.403 in
   the 2026-11-02 `main` run installs every `DataProofsDotnet.*` from `local-feed`; a local probe on SDK
   10.0.404 shows `--source` restricting the restore to that one source). So CI was not testing the
   wrong package today; any machine whose cache holds the published version was.
   - Fix: pack at `0.0.0-smoke.<run_id>.<run_attempt>`, a version no release uses, so nothing but the feed
     can supply it; and run the smoke app with `-p:TreatWarningsAsErrors=true`, the way the consumers named
     in the issue build, so a dependency with a known advisory fails `ac-10` instead of warning. That second
     half is the consumer-shaped regression test for this issue: it fails on `main`'s packages and passes on
     this branch (evidence below).
   - *Bump the dev-default `DataProofsVersion`* lost: the brief rules out picking a version number here, and
     the collision would come back after every release until the next bump.
   - *`-warnaserror:NU1901;…`* (only the audit codes) lost: semicolons split MSBuild property lists on the
     command line, and full warnings-as-errors is what the consumers in the issue use. The smoke programs
     compile warning-free under it (all five pass on the branch).
   - The stale comment in `Directory.Build.props` ("no collision with any published version") and the smoke
     README's procedure are updated with it. The README heading also claimed `publish.yml` runs the smoke; it
     does not, so the heading now names `ci.yml` only.

## Items

- [x] Read the brief, `CLAUDE.md`, `CONTRIBUTING.md`, `RELEASING.md`, all of `tasks/lessons.md`
- [x] Reproduce the failure on `main` (solution restore, vulnerability listing)
- [x] Choose the version from the flat-container index; record the alternatives
- [x] Bump the pin; CHANGELOG entry (`9e02da0`)
- [x] Vulnerability listing after: no vulnerable package in any project
- [x] Consumer reproduction under warnings-as-errors: published 2.0.0 fails, the branch's packed packages restore
      clean, the documented workaround restores clean
- [x] Packed nuspecs of Cose and Rdfc declare `System.Formats.Cbor` `10.0.15`
- [x] `dotnet build DataProofsDotnet.sln -c Release /warnaserror` clean
- [x] `dotnet test DataProofsDotnet.sln -c Release`: all pass, zero skips
- [x] `ac-10` hardened (`785f34f`), its regression check run against `main` and the branch
- [x] Gates: `ac-6` dependency hygiene, `ac-10` pack and smoke, `ac-12` JIT legs
- [x] Adversarial pass (narrow): does 10.0.15 actually restore and ship, and does anything still
      resolve a vulnerable version
- [ ] PR, CI green

## Verification (2026-11-19, macOS, SDK 10.0.404)

| Check | `origin/main` | this branch |
| --- | --- | --- |
| `dotnet restore DataProofsDotnet.sln` | exit 1, 18 × `error NU1902` (`System.Formats.Cbor` 10.0.8) | exit 0, no `NU19xx` |
| `dotnet list … package --vulnerable --include-transitive --no-restore` | 18 projects flag `System.Formats.Cbor` 10.0.8; nothing else | 33 of 33 projects "no vulnerable packages" |
| Resolved `System.Formats.Cbor` (`--include-transitive`) | 10.0.8 | 10.0.15 in all 18 projects that carry it |
| Packed nuspec, Cose and Rdfc | 10.0.8 (also every published version, 0.1.0-preview.1 to 2.0.0, on nuget.org) | 10.0.15; Core, Jose, Legacy, DI declare no CBOR dependency |
| Throwaway consumer, `TreatWarningsAsErrors`, isolated `NUGET_PACKAGES`, one per package (Cose, Rdfc, Legacy, DI) | published 2.0.0: restore exit 1, `error NU1902` each | packed from the branch: restore exit 0 each, resolves 10.0.15 |
| Workaround: all four at published 2.0.0 plus a direct `System.Formats.Cbor` 10.0.15 | | restore exit 0, build 0 errors, resolves 10.0.15 |
| `ac-10` as changed (run-unique version, smoke under `TreatWarningsAsErrors`), local emulation | Core, Jose `OK`; Cose, Rdfc, DI exit 1 with `error NU1902` (main packed with `-p:TreatWarningsAsErrors=false`, since its own restore fails) | all five `OK`, every `DataProofsDotnet.*` from the local feed, 10.0.15 |
| `dotnet build DataProofsDotnet.sln -c Release /warnaserror` | | 0 warnings, 0 errors |
| `dotnet test DataProofsDotnet.sln -c Release` | | 3,307 passed, 0 failed, 0 skipped (ApiSurface 5, Core 539, Jose 1,336, Cose 129, Rdfc 990, Legacy 297, DI 11) |
| `ac-6`: `tasks/dependency-hygiene` (project and packed graphs), ApiSurface tests | | `RESULT: CLEAN`; 5 passed |
| `ac-12` JIT and reflection-disabled legs: emit, compare, verify | | emit 50 checks; 28 deterministic values identical; verify 32 checks; output carries `System.Formats.Cbor` 10.0.15 (`10.0.15+8e0f8ed2`). The native leg was run by the adversarial agent only; CI runs it |

## Adversarial pass

One fresh agent, given the issue, the diff and an attack list (what ships; `ac-10` as CI runs it; `ac-12`;
anything else resolving a vulnerable version), in an isolated worktree and package cache.

- What ships: no finding. Cose and Rdfc nuspecs declare 10.0.15; Legacy and DI get CBOR only through them.
- `ac-10`: finding, reproduced by the agent with a pre-populated cache; fixed in `785f34f` (decision 6).
- `ac-12`: no finding (agent's run, not mine: `AotSmoke` and the file-based app resolve 10.0.15, a native
  `osx-arm64` publish references 10.0.15, emit, compare, cross-verify and the IL-warning scan passed).
- Anything else: no finding. No `#:package`, `VersionOverride` or lock file; test projects take the central
  pin. Cosmetic, pre-existing: the `tasks/smoke/*/*.csproj` files are stale (`DataProofsDotnet.*` 0.1.0,
  `NetCrypto` 1.0.0-preview.1) and fail restore with `NU1008`; CI copies only their `Program.cs`. Left for a
  follow-up, as it is unrelated to the advisory.

## Review

(Filled in as review rounds happen.)
