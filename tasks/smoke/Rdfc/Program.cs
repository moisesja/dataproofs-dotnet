// ============================================================
// AC-10 smoke — DataProofsDotnet.Rdfc
// ============================================================
// RDFC-1.0 canonicalization of a self-contained JSON-LD document through the public canonicalizer,
// using the offline document loader (no network). Asserts non-empty, valid N-Quads output and that
// the result is deterministic across runs. Prints OK and exits 0 on success.
//
// Self-contained by design: the AC-10 clean-room copies ONLY this Program.cs into a fresh console
// app, so the document is inlined here (its @context is in the offline loader's bundled set).

using System.Text;
using System.Text.Json;
using DataProofsDotnet.Rdfc;

Console.WriteLine("=== DataProofsDotnet.Rdfc smoke — RDFC-1.0 canonicalization (offline) ===");

// 1. The document to canonicalize. Its only @context (credentials/v2) is bundled in the offline
//    loader, so canonicalization needs no network access (FR-10 fail-closed posture).
const string jsonLd = """
    {
      "@context": [ "https://www.w3.org/ns/credentials/v2" ],
      "id": "urn:uuid:11111111-2222-3333-4444-555555555555",
      "type": [ "VerifiableCredential" ],
      "issuer": "did:example:issuer",
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": { "id": "did:example:subject" }
    }
    """;
using var doc = JsonDocument.Parse(jsonLd);

// 2. Canonicalize through the public interface. The default ctor uses the offline loader.
var canonicalizer = new RdfcDocumentCanonicalizer();
byte[] canonicalBytes = canonicalizer.CanonicalizeJsonLd(doc.RootElement);
string nquads = Encoding.UTF8.GetString(canonicalBytes);

Check(canonicalBytes.Length > 0, "canonicalization produced non-empty output");
Check(nquads.Contains("VerifiableCredential", StringComparison.Ordinal)
      || nquads.Contains("credentials#", StringComparison.Ordinal),
    "canonical N-Quads reference the credential type");
Check(nquads.TrimEnd().EndsWith(".", StringComparison.Ordinal), "N-Quads statements terminate with '.'");
Console.WriteLine($"  canonicalized to {nquads.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length} N-Quad statement(s)");

// 3. Determinism: a second canonicalization of the same document is byte-identical (NFR-5).
byte[] again = new RdfcDocumentCanonicalizer().CanonicalizeJsonLd(doc.RootElement);
Check(again.AsSpan().SequenceEqual(canonicalBytes), "canonicalization is deterministic across runs");
Console.WriteLine("  determinism confirmed");

Console.WriteLine("OK — DataProofsDotnet.Rdfc smoke passed.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.Error.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
