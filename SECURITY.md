# Security Policy

dataproofs-dotnet produces and verifies security-critical artifacts: W3C Data Integrity proofs,
JWS/JWE envelopes, SD-JWT credentials with Key Binding, and COSE_Sign1/CWT structures. Flaws in
canonicalization, signature verification, proof-purpose/controller authorization, disclosure
digest checking, or key handling are security vulnerabilities, not ordinary bugs.

## Supported versions

| Version | Supported |
|---|---|
| latest release | ✅ |
| older releases | ❌ — upgrade to latest |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

How to report: use GitHub private vulnerability reporting at
<https://github.com/moisesja/dataproofs-dotnet/security/advisories/new>.

What to expect:

- Acknowledgement within 48 hours
- A remediation plan within 7 days
- Credit in the advisory and CHANGELOG if desired

## Known limitations

- **`bbs-2023` mandatory disclosure is not yet cryptographically enforced.** The W3C `bbs-2023`
  cryptosuite binds the mandatory-disclosure group into the BBS signature `header`. NetCrypto v1's
  BBS provider does not expose that `header` parameter, so a holder can currently present a derived
  proof that omits an issuer-designated mandatory statement and it will still verify. Treat
  `bbs-2023` as **experimental** (it is pinned to a Candidate Recommendation *draft*) and do not
  rely on its mandatory-disclosure guarantee until this is resolved. Tracked in
  [`docs/dependencies/netcrypto-bbs-header.md`](docs/dependencies/netcrypto-bbs-header.md)
  (upstream: moisesja/crypto-dotnet#2). The other four cryptosuites and all enveloping proofs are
  unaffected.

## Scope

In scope: anything in `src/` — proof creation/verification logic, canonicalization, envelope
parsing, algorithm negotiation, key intake, randomness use, timing side channels in comparisons.

Out of scope: vulnerabilities in upstream dependencies (report to NetCrypto, NetCid, dotNetRDF,
or the .NET runtime as appropriate — though a report here that we mitigate is welcome), samples
misuse, and issues requiring a compromised host.
