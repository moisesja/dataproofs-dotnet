# BBS lifecycle and untrusted-input admission

Run `dotnet run --project samples/DataProofsDotnet.Samples.BbsSelectiveDisclosure` from the repository root. The sample verifies its lifecycle and admission checks; native BBS must be installed to exercise them.

`VerificationAdmission.cs` demonstrates a deliberately small credential service profile:

| Boundary | Example policy |
| --- | --- |
| Decompressed request body | 32 KiB; host must enforce before buffering, helper checks again before parsing |
| JSON depth | 16 |
| Total JSON values | 2,048 |
| Items in any array | 128 |
| Proofs | One BBS proof object |
| `proofValue` | 16 KiB characters, considerably below the library's 1 MiB format ceiling |
| Concurrent verifications | Two per process, with no in-process waiting queue |
| Context content | Bundled, pinned offline V2 and examples contexts only |

These numbers are example admission limits, not measured latency promises. Benchmark the accepted profile with the deployed native library and hardware before choosing production limits. The proof limit bounds the number of encoded hidden-message scalars, while JSON shape limits address expansion work that the RDF canonicalizer's later work budget cannot cover. Apply limits to decompressed data; a `Content-Length` check alone does not suffice. Limit ingress rate and concurrent requests across replicas as well as within each process. Return a rejection or busy response without starting verification when admission fails.

Native BBS verification is synchronous and cannot be cancelled by timing out an awaiting HTTP request. For a hard execution deadline, run verification in bounded worker processes that can be terminated and replaced. Merely abandoning a task leaves the work running. The helper bounds admission and concurrency; it does not promise a hard execution-time bound.

`TryVerify` returns false for admission rejection and true when a verification result is available. An admitted document is accepted only when `result.Verified` is true. This is a work-admission example: the caller must separately establish issuer/key authorization and its presentation/replay policy.

`KnownContexts` checks URI values, not retrieved content. The default offline loader provides the pinned content in this example. If replacing it, use approved immutable context copies or verify approved content hashes, including imported/scoped contexts. A mutable URL allowlist or first-fetch cache is insufficient.

BBS issuance and derivation require document contexts only at the root. Nested `@context` members, even inside literal data, are conservatively refused. Selection preserves null data inside whole JSON literals; the skolemizer's other documented limitations still apply. Derived proofs preserve the base proof context. Upgrading from older BBS/RDFC wire behavior can require reissuance by the original issuer; a verifier cannot repair a third party's signature.
