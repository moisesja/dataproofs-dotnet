# Reproducible BBS cross-stack check

Requires .NET 10 with native BBS available and Node.js 18+.

```sh
cd tasks/check-bbs-interop
npm ci --ignore-scripts
npm test
```

The script runs the current .NET BBS sample, writes only public proof/key artifacts into a fresh
temporary directory, and verifies two different disclosures with the pinned JavaScript stack.
It also requires tampering of a mandatory value to fail. Context resolution is entirely local;
unrecognized retrievals fail. Missing native BBS fails the check instead of silently skipping it.

The checked-in lockfile pins the development-only oracle dependencies; they are not runtime NuGet
dependencies. CI runs this check in the existing `ac-1` job. The reverse verification direction uses the committed W3C `derivedRevealDocument.json`
in `Bbs2023ConformanceTests`. This small cross-stack check is bounded interoperability evidence,
not a replacement for specification tests. In particular, the Unicode code-point correction is
intentionally incompatible with this oracle's UTF-16 ordering for affected character pairs.

The previous PR's separate 120-credential/26,000-dataset experiments are historical reports, not
reproducible evidence supplied by this script. The separate `generate-rdfc-differential` tool
regenerates the committed 1,870-case canonicalization corpus.
