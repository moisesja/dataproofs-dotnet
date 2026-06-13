// ============================================================
// AC-10 smoke — DataProofsDotnet.Rdfc
// ============================================================
// RDFC-1.0 canonicalization of a bundled JSON-LD document through the public canonicalizer, using
// the offline document loader (no network). Asserts non-empty, valid N-Quads output and that the
// result is deterministic across runs. Prints OK and exits 0 on success.

using System.Reflection;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.Rdfc;

Console.WriteLine("=== DataProofsDotnet.Rdfc smoke — RDFC-1.0 canonicalization (offline) ===");

// 1. Load the bundled document (embedded resource; its @context is in the offline loader's set).
string jsonLd = ReadEmbedded("bundled-document.jsonld");
using var doc = JsonDocument.Parse(jsonLd);

// 2. Canonicalize through the public interface. The default ctor uses the offline loader, so no
//    network access occurs (FR-10 fail-closed posture).
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

static string ReadEmbedded(string fileName)
{
    var assembly = Assembly.GetExecutingAssembly();
    string resource = assembly.GetManifestResourceNames()
        .Single(n => n.EndsWith(fileName, StringComparison.Ordinal));
    using var stream = assembly.GetManifestResourceStream(resource)!;
    using var reader = new StreamReader(stream);
    return reader.ReadToEnd();
}

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.Error.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
