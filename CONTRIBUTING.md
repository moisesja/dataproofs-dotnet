# Contributing to dataproofs-dotnet

This repository is spec-driven: [`dataproofs-prd.md`](dataproofs-prd.md) is normative for
functionality, and the governing W3C/IETF specifications win over any porting source. Changes
that alter behavior must keep the PRD current.

## Prerequisites

- .NET 10 SDK (pinned by `global.json`)
- Git
- Any editor; the repo carries `.editorconfig`

## Getting started

```bash
git clone https://github.com/moisesja/dataproofs-dotnet.git
cd dataproofs-dotnet
dotnet restore DataProofsDotnet.sln
dotnet build DataProofsDotnet.sln
dotnet test DataProofsDotnet.sln
```

## Project structure

```
src/        five publishable packages (Core, Jose, Cose, Rdfc, Extensions.DependencyInjection)
tests/      one test project per package + ApiSurface.Tests (hygiene gates) + vendored fixtures/
samples/    narrated console samples — every public API member must appear in at least one (FR-21)
tasks/      CI gate tooling (samples-coverage, dependency-hygiene, api-surface-scan, ...) and plan docs
docs/       supplementary documentation
```

## Code style

- File-scoped namespaces, 4-space indentation (enforced by `.editorconfig`)
- Nullable reference types and warnings-as-errors are on repo-wide
- Public API changes must be declared in the package's `PublicAPI.Unshipped.txt`
  (PublicApiAnalyzers, FR-24)
- Serialization in `src/` is source-generated (native AOT, NFR-7): never call a reflection-based
  `JsonSerializer` overload — the AOT analyzers fail the build. Use the typed `JsonTypeInfo<T>`
  accessors (`DataProofsJsonOptions.*TypeInfo`, `JoseJson.*TypeInfo`, `RdfcJson`, `LegacyJson`) and add
  any newly serialized type to that package's `JsonSerializerContext`. Build JSON with
  `JsonObject`/`JsonNode`, and cast to `JsonNode` when passing a derived node or a string to
  `JsonArray.Add` (the generic overload is reflection-based)
- A dependency is not covered by those analyzers. If `ac-12` reports a new IL warning from a
  dependency, trace it: if the path is reachable, stop using it (and ban it in `BannedSymbols.txt` with
  the reason); only a warning shown unreachable goes on `tasks/aot-smoke/known-il-warnings.txt`, with
  that reason

## Tests

- xunit + FluentAssertions (pinned at 7.x — do not bump; v8 changed license)
- Conformance fixtures are vendored under `tests/fixtures/<source>/` with a `PROVENANCE.md`
  per source; tests never fetch from the network
- Skipped theories fail conformance jobs — fix or remove, never skip

## Pull requests

- Keep changes minimal and focused; one concern per PR
- All `ac-1` … `ac-12` CI jobs must be green before merging to `main`. This is a maintainer procedure:
  as of 2026-10-27 GitHub does not enforce it (no branch protection or rulesets on `main`; PRD §9)
- Update samples and docs alongside code changes
