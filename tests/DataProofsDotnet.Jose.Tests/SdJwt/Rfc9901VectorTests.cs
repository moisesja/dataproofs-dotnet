using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// AC-3 step 1 (SD-JWT parts) — RFC 9901 worked-example vectors (fixtures:
/// <c>fixtures/ietf/rfc9901/</c>). For each worked example this asserts three independent facts
/// the RFC publishes as ground truth:
/// <list type="number">
/// <item>every Disclosure's digest, recomputed via the library's <see cref="Disclosure"/> API,
///   equals the fixture's stated <c>sha256_digest_b64url</c>;</item>
/// <item>the verifier/reconstructor produces the fixture's stated processed (disclosed)
///   payload;</item>
/// <item>each Key Binding JWT <c>sd_hash</c> equals the fixture's stated value, recomputed over
///   the presented SD-JWT.</item>
/// </list>
/// Nested/structured/recursive/array-element/decoy cases are all exercised by the fixtures below.
/// </summary>
public sealed class Rfc9901VectorTests
{
    private static readonly Jwk _issuerKey = SdJwtFixtureSupport.Rfc9901IssuerKey();
    private static Func<string, Jwk?> Resolver => SdJwtFixtureSupport.SingleKeyResolver(_issuerKey);

    // ---- (1) Disclosure digests recomputed via the library and compared to the RFC's stated values ----

    public static IEnumerable<object[]> DisclosureFixtures()
    {
        // (file, json-pointer to a "disclosures" array of {disclosure_b64, sha256_digest_b64url})
        yield return ["example1-disclosures.json"];
        yield return ["section6-flat.json"];
        yield return ["section6-structured.json"];
        yield return ["section6-recursive.json"];
        yield return ["appendix-a1-simple-structured.json"];
        yield return ["appendix-a2-complex-structured.json"];
    }

    [Theory]
    [MemberData(nameof(DisclosureFixtures))]
    public void Every_disclosure_digest_recomputes_to_the_stated_value(string file)
    {
        using var doc = SdJwtFixtureSupport.Load("rfc9901", file);
        var disclosures = doc.RootElement.GetProperty("disclosures");
        disclosures.GetArrayLength().Should().BeGreaterThan(0, "the fixture must carry Disclosures to check");

        foreach (var d in disclosures.EnumerateArray())
        {
            var encoded = d.GetProperty("disclosure_b64").GetString()!;
            var stated = d.GetProperty("sha256_digest_b64url").GetString()!;

            // Recompute via the library's Disclosure parse + digest API (not a local SHA-256).
            var recomputed = SdJwtFixtureSupport.RecomputeDigest(encoded, SdHashAlgorithm.Sha256);

            recomputed.Should().Be(stated,
                because: $"RFC 9901 states base64url(SHA-256(ASCII(disclosure))) = {stated} for {file}");
        }
    }

    [Fact]
    public void Disclosure_format_object_and_array_examples_recompute_to_stated_digests()
    {
        // RFC 9901 §4.2.1–4.2.4.2: the family_name "Möbius" object-property Disclosure and the
        // "FR" array-element Disclosure each publish a stated digest.
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "disclosure-format.json");
        var root = doc.RootElement;

        var op = root.GetProperty("object_property_disclosure");
        SdJwtFixtureSupport.RecomputeDigest(op.GetProperty("disclosure_b64").GetString()!, SdHashAlgorithm.Sha256)
            .Should().Be(op.GetProperty("sha256_digest_b64url").GetString());

        var ae = root.GetProperty("array_element_disclosure");
        SdJwtFixtureSupport.RecomputeDigest(ae.GetProperty("disclosure_b64").GetString()!, SdHashAlgorithm.Sha256)
            .Should().Be(ae.GetProperty("sha256_digest_b64url").GetString());

        // The three alternative encodings of the same Disclosure (whitespace/escaping variants)
        // each parse, but their digests differ from the canonical one — RFC 9901 §4.2.5 hashes the
        // received string verbatim, so a re-encoded form is a *different* digest. This is exactly
        // why the library preserves Encoded byte-for-byte.
        foreach (var alt in op.GetProperty("equivalent_alternative_encodings").EnumerateArray())
        {
            var altEncoded = alt.GetString()!;
            // It must still parse to the same logical claim (family_name).
            var parsed = Disclosure.Parse(altEncoded);
            parsed.ClaimName.Should().Be("family_name");
        }
    }

    // ---- (2) Reconstruction of the processed (disclosed) payload ----

    [Fact]
    public void Main_example_full_issuance_reconstructs_to_a_superset_of_disclosed_claims()
    {
        // The full issuance reveals all 10 Disclosures; verifying it yields a payload carrying
        // every disclosed claim plus the always-visible iss/iat/exp/sub/cnf (control claims stripped).
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "example1-sd-jwt.json");
        var sdJwt = doc.RootElement.GetProperty("sd_jwt").GetString()!;

        var result = SdJwtVerifier.Verify(sdJwt, Resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.SignatureAlgorithm.Should().Be("ES256");
        var payload = result.DisclosedPayload!;
        payload.Should().NotContainKey("_sd");
        payload.Should().NotContainKey("_sd_alg");
        // All 8 object-property disclosures plus the always-clear claims are present.
        payload["given_name"]!.GetValue<string>().Should().Be("John");
        payload["family_name"]!.GetValue<string>().Should().Be("Doe");
        payload["email"]!.GetValue<string>().Should().Be("johndoe@example.com");
        payload["iss"]!.GetValue<string>().Should().Be("https://issuer.example.com");
        // Both nationalities array elements resolve.
        var nats = payload["nationalities"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
        nats.Should().Equal("US", "DE");
    }

    [Fact]
    public void Main_example_kb_presentation_reconstructs_to_the_stated_processed_payload()
    {
        // RFC 9901 §5.2: a presentation disclosing family_name, address, given_name, nationality
        // US, with a KB-JWT. The processed payload is published verbatim.
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "kb-jwt.json");
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;
        var expected = SdJwtFixtureSupport.ToJsonObject(doc.RootElement.GetProperty("processed_sd_jwt_payload"));

        var options = new SdJwtVerificationOptions
        {
            ExpectedAudience = "https://verifier.example.org",
            ExpectedNonce = "1234567890",
        };
        var result = SdJwtVerifier.Verify(presentation, Resolver, options);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue("the presentation carries a verifiable KB-JWT (RFC 9901 §7.3)");
        AssertProcessedPayloadMatches(result.DisclosedPayload!, expected);
    }

    [Theory]
    [InlineData("appendix-a1-simple-structured.json")] // structured address, 6 decoy digests, non-ASCII
    [InlineData("appendix-a2-complex-structured.json")] // OIDC-IDA recursive array-element evidence
    public void Appendix_presentation_reconstructs_to_the_stated_processed_payload(string file)
    {
        using var doc = SdJwtFixtureSupport.Load("rfc9901", file);
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;
        var expected = SdJwtFixtureSupport.ToJsonObject(doc.RootElement.GetProperty("processed_sd_jwt_payload"));

        var result = SdJwtVerifier.Verify(presentation, Resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        AssertProcessedPayloadMatches(result.DisclosedPayload!, expected);
    }

    // ---- (3) KB-JWT sd_hash recomputation ----

    [Theory]
    [InlineData("rfc9901", "kb-jwt.json")]
    public void Kb_jwt_sd_hash_recomputes_to_the_stated_value(string source, string file)
    {
        using var doc = SdJwtFixtureSupport.Load(source, file);
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;
        var statedSdHash = doc.RootElement.GetProperty("kb_jwt").GetProperty("sd_hash").GetString()!;

        // Split off the SD-JWT (up to and including the final '~') the way the library does, then
        // recompute sd_hash over exactly those bytes under the SD-JWT's _sd_alg.
        var components = SdJwtComponents.Parse(presentation);
        components.HasKeyBinding.Should().BeTrue();
        var recomputed = SdHashAlgorithm.ComputeSdHash(SdHashAlgorithm.Sha256, components.SdJwtWithoutKeyBinding);

        recomputed.Should().Be(statedSdHash,
            because: "RFC 9901 §7.3 sd_hash = base64url(SHA-256(ASCII(SD-JWT up to and including final '~')))");
    }

    // ---- Structural / nested / recursive coverage against the published payloads ----

    [Fact]
    public void Flat_disclosure_payload_carries_the_whole_address_digest()
    {
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "section6-flat.json");
        var payload = doc.RootElement.GetProperty("sd_jwt_payload");
        var sd = payload.GetProperty("_sd").EnumerateArray().Select(e => e.GetString()).ToArray();

        var addressDigest = doc.RootElement.GetProperty("disclosures")[0].GetProperty("sha256_digest_b64url").GetString();
        sd.Should().ContainSingle().Which.Should().Be(addressDigest,
            because: "the flat (§6.1) SD-JWT carries exactly the whole-address Disclosure digest");
    }

    [Fact]
    public void Structured_disclosure_digests_recompute_into_the_nested_sd_array()
    {
        // §6.2: the four address sub-claim Disclosures' digests appear in the address._sd array.
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "section6-structured.json");
        var nestedSd = doc.RootElement.GetProperty("sd_jwt_payload")
            .GetProperty("address").GetProperty("_sd")
            .EnumerateArray().Select(e => e.GetString()!).ToHashSet();

        foreach (var d in doc.RootElement.GetProperty("disclosures").EnumerateArray())
        {
            var digest = SdJwtFixtureSupport.RecomputeDigest(d.GetProperty("disclosure_b64").GetString()!, SdHashAlgorithm.Sha256);
            nestedSd.Should().Contain(digest,
                because: $"the structured §6.2 payload embeds each sub-claim digest in address._sd");
        }
    }

    [Fact]
    public void Recursive_address_disclosure_contains_its_sub_claim_digests()
    {
        // §6.3: the address Disclosure's *value* is itself an object carrying an _sd array of the
        // four sub-claim digests; the parent payload _sd carries the address Disclosure's digest.
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "section6-recursive.json");
        var disclosures = doc.RootElement.GetProperty("disclosures");

        var addressEntry = disclosures.EnumerateArray().Single(e =>
            e.TryGetProperty("claim_name", out var n) && n.ValueKind == JsonValueKind.String && n.GetString() == "address");

        var parsed = Disclosure.Parse(addressEntry.GetProperty("disclosure_b64").GetString()!);
        parsed.ClaimName.Should().Be("address");
        var nestedSd = parsed.ClaimValue!.AsObject()["_sd"]!.AsArray().Select(n => n!.GetValue<string>()).ToHashSet();

        // Each of the four sub-claim Disclosures' digests must be referenced inside the address value.
        foreach (var sub in new[] { "street_address", "locality", "region", "country" })
        {
            var subEntry = disclosures.EnumerateArray().Single(e =>
                e.TryGetProperty("claim_name", out var n) && n.ValueKind == JsonValueKind.String && n.GetString() == sub);
            var subDigest = SdJwtFixtureSupport.RecomputeDigest(subEntry.GetProperty("disclosure_b64").GetString()!, SdHashAlgorithm.Sha256);
            nestedSd.Should().Contain(subDigest);
        }

        // And the parent payload's _sd carries the address Disclosure's digest.
        var addressDigest = SdJwtFixtureSupport.RecomputeDigest(addressEntry.GetProperty("disclosure_b64").GetString()!, SdHashAlgorithm.Sha256);
        doc.RootElement.GetProperty("sd_jwt_payload").GetProperty("_sd")[0].GetString().Should().Be(addressDigest);
    }

    [Fact]
    public void Decoy_digests_are_silently_dropped_during_reconstruction()
    {
        // Appendix A.1 carries 6 decoy digests in its _sd arrays. Reconstructing the full
        // presentation must succeed and the processed payload must NOT surface any decoy as a claim
        // (RFC 9901 §4.2.7 / §7.1: a digest with no matching Disclosure is ignored).
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "appendix-a1-simple-structured.json");
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;
        var decoys = doc.RootElement.GetProperty("decoy_digests").EnumerateArray().Select(e => e.GetString()!).ToArray();
        decoys.Should().NotBeEmpty("Appendix A.1 publishes decoy digests");

        var result = SdJwtVerifier.Verify(presentation, Resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        // The processed payload's serialized form must contain none of the decoy digest strings.
        var serialized = result.DisclosedPayload!.ToJsonString();
        foreach (var decoy in decoys)
            serialized.Should().NotContain(decoy, "a decoy digest must never surface in the processed payload");
    }

    private static void AssertProcessedPayloadMatches(JsonObject actual, JsonObject expected)
    {
        SdJwtFixtureSupport.JsonEquivalent(actual, expected).Should().BeTrue(
            because: "the reconstructed processed payload must equal RFC 9901's published value\n" +
                     $"expected: {SdJwtFixtureSupport.Canonicalize(expected)}\n" +
                     $"actual:   {SdJwtFixtureSupport.Canonicalize(actual)}");
    }
}
