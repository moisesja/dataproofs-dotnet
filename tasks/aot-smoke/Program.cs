// ============================================================
// AC-12 — native AOT publish and JIT parity (PRD NFR-7, issue #27)
// ============================================================
// Exercises every DataProofsDotnet package with fixed keys and timestamps and records what it
// produced, so the same program can be compared across runtimes:
//
//   AotSmoke emit <report.json>             run every path, self-verify, write the report
//   AotSmoke verify <report.json>           verify another run's outputs (signatures, envelopes, JWEs)
//   AotSmoke compare <a.json> <b.json> ...  the "deterministic" sections must be byte-identical
//
// CI runs it under JIT, under JIT with reflection-based serialization disabled, as a .NET 10
// file-based app and as a native-AOT binary; see tasks/aot-smoke/README.md. Every failed expectation
// prints "FAILED: …" and exits 1.

return await DataProofsDotnet.Tools.AotSmoke.SmokeMain.RunAsync(args);
