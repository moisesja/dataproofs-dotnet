using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Tests.Conformance;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// Shared helpers for the SD-JWT / SD-JWT VC conformance suites (AC-3 steps 1, 5, 7). Reads the
/// vendored RFC 9901 and draft-ietf-oauth-sd-jwt-vc-16 fixtures and supplies the issuer-key
/// resolver and the order-insensitive JSON comparison the reconstruction theories need.
/// </summary>
internal static class SdJwtFixtureSupport
{
    /// <summary>The P-256 public JWK (RFC 9901 Appendix A.5) that validates every RFC 9901 / SD-JWT VC example signature.</summary>
    public static Jwk Rfc9901IssuerKey()
    {
        using var doc = Fixtures.LoadJson("ietf", "rfc9901", "appendix-a5-issuer-public-key.json");
        return Fixtures.ToJwk(doc.RootElement.GetProperty("issuer_public_key_jwk"));
    }

    /// <summary>A kid → JWK resolver that returns <paramref name="key"/> for any kid (the fixtures use a single Issuer key).</summary>
    public static Func<string, Jwk?> SingleKeyResolver(Jwk key) => _ => key;

    public static JsonDocument Load(string source, string file) => Fixtures.LoadJson("ietf", source, file);

    /// <summary>
    /// Compare two JSON nodes ignoring object-member order (RFC 8259: object members are unordered)
    /// and numeric formatting. Arrays remain order-sensitive (SD-JWT array semantics are positional).
    /// </summary>
    public static bool JsonEquivalent(JsonNode? a, JsonNode? b)
        => Canonicalize(a) == Canonicalize(b);

    public static string Canonicalize(JsonNode? node)
    {
        var sorted = Sort(node);
        return sorted?.ToJsonString() ?? "null";
    }

    private static JsonNode? Sort(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
            {
                var result = new JsonObject();
                foreach (var key in obj.Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal))
                    result[key] = Sort(obj[key]?.DeepClone());
                return result;
            }
            case JsonArray arr:
            {
                var result = new JsonArray();
                foreach (var element in arr)
                    result.Add(Sort(element?.DeepClone()));
                return result;
            }
            default:
                return node?.DeepClone();
        }
    }

    /// <summary>Parse a fixture JSON element into a <see cref="JsonObject"/> for comparison.</summary>
    public static JsonObject ToJsonObject(JsonElement element)
        => (JsonObject)JsonNode.Parse(element.GetRawText())!;

    /// <summary>
    /// Independently recompute a Disclosure's digest from the fixture's base64url string via the
    /// library's <see cref="Disclosure"/> API, under the fixture's stated hash algorithm.
    /// </summary>
    public static string RecomputeDigest(string disclosureB64, string sdAlg)
        => Disclosure.Parse(disclosureB64).ComputeDigest(sdAlg);
}
