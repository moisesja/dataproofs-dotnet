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
tasks/      CI gate tooling (samples-coverage, parity-diff, dependency-hygiene, ...) and plan docs
docs/       supplementary documentation
```

## Code style

- File-scoped namespaces, 4-space indentation (enforced by `.editorconfig`)
- Nullable reference types and warnings-as-errors are on repo-wide
- Public API changes must be declared in the package's `PublicAPI.Unshipped.txt`
  (PublicApiAnalyzers, FR-24)

## Tests

- xunit + FluentAssertions (pinned at 7.x — do not bump; v8 changed license)
- Conformance fixtures are vendored under `tests/fixtures/<source>/` with a `PROVENANCE.md`
  per source; tests never fetch from the network
- Skipped theories fail conformance jobs — fix or remove, never skip

## Pull requests

- Keep changes minimal and focused; one concern per PR
- All `ac-1` … `ac-11` CI jobs must be green to merge to `main`
- Update samples and docs alongside code changes
