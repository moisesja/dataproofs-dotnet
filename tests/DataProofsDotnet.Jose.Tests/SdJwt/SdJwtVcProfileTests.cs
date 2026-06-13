using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// AC-3 step 5 — SD-JWT VC profile (FR-17, draft-ietf-oauth-sd-jwt-vc-16) beyond generic SD-JWT.
/// Fixtures: <c>fixtures/ietf/sd-jwt-vc-16/</c>. Asserts the profile-specific behavior the generic
/// SD-JWT suite does not: <c>vct</c> presence and validation, the <c>dc+sd-jwt</c> media type with
/// the transitional <c>vc+sd-jwt</c> accepted on input, the registered must-not-disclose claim
/// rules, issuer/holder/verifier processing, and Type Metadata retrieval through the offline
/// <see cref="LocalCacheTypeMetadataResolver"/> (never the network, FR-17 posture).
///
/// SD-JWT VC pin check (2026-06-12): <see cref="SdJwtVcConstants"/> pins draft-16; re-verified
/// against the IETF datatracker — -16 remains the latest, no -17 exists (PRD §12.2 / FR-17).
/// </summary>
public sealed class SdJwtVcProfileTests
{
    private static readonly Jwk _issuerKey = SdJwtFixtureSupport.Rfc9901IssuerKey();
    private static Func<string, Jwk?> Resolver => SdJwtFixtureSupport.SingleKeyResolver(_issuerKey);

    private static JsonObject SampleVcClaims(string vct = "https://credentials.example.com/identity_credential") => new()
    {
        ["iss"] = "https://example.com/issuer",
        ["vct"] = vct,
        ["given_name"] = "John",
        ["family_name"] = "Doe",
        ["address"] = new JsonObject { ["country"] = "US" },
    };

    // ---- Fixture-driven verification (draft-16 worked examples) ----

    [Fact]
    public async Task Fixture_presentation_without_kb_verifies_and_carries_vct()
    {
        // sd-jwt-vc-16 §2.3.2 Figure 9/10: a presentation (typ dc+sd-jwt, no cnf/KB) disclosing
        // is_over_65 and address; the verifier yields the processed payload and the resolved vct.
        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "example-presentation-no-kb.json");
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;
        var expected = SdJwtFixtureSupport.ToJsonObject(doc.RootElement.GetProperty("processed_sd_jwt_payload"));

        var result = await SdJwtVcVerifier.VerifyAsync(presentation, Resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.Vct.Should().Be("https://credentials.example.com/identity_credential");
        SdJwtFixtureSupport.JsonEquivalent(result.DisclosedPayload, expected).Should().BeTrue(
            $"expected {SdJwtFixtureSupport.Canonicalize(expected)} got {SdJwtFixtureSupport.Canonicalize(result.DisclosedPayload)}");
    }

    [Fact]
    public async Task Fixture_presentation_with_kb_verifies_audience_nonce_and_sd_hash()
    {
        // sd-jwt-vc-16 §2.3.2 Figure 7/8: SD-JWT+KB disclosing address and is_over_65.
        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "example-presentation-kb-jwt.json");
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;
        var expected = SdJwtFixtureSupport.ToJsonObject(doc.RootElement.GetProperty("processed_sd_jwt_payload"));
        var statedSdHash = doc.RootElement.GetProperty("kb_jwt").GetProperty("sd_hash").GetString()!;

        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = "https://example.com/verifier",
            ExpectedNonce = "1234567890",
        };
        var result = await SdJwtVcVerifier.VerifyAsync(presentation, Resolver, options);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue();
        SdJwtFixtureSupport.JsonEquivalent(result.DisclosedPayload, expected).Should().BeTrue(
            $"expected {SdJwtFixtureSupport.Canonicalize(expected)} got {SdJwtFixtureSupport.Canonicalize(result.DisclosedPayload)}");

        // Independently confirm the stated sd_hash recomputes over the presented SD-JWT.
        var components = SdJwtComponents.Parse(presentation);
        SdHashAlgorithm.ComputeSdHash(SdHashAlgorithm.Sha256, components.SdJwtWithoutKeyBinding).Should().Be(statedSdHash);
    }

    [Fact]
    public async Task Full_issued_vc_fixture_verifies_with_dc_sd_jwt_media_type()
    {
        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "example-sd-jwt-vc.json");
        var issued = doc.RootElement.GetProperty("sd_jwt_vc").GetString()!;
        doc.RootElement.GetProperty("issuer_signed_jwt_header").GetProperty("typ").GetString()
            .Should().Be(SdJwtVcConstants.MediaType, "the issuer-JWT typ is the dc+sd-jwt media type");

        var result = await SdJwtVcVerifier.VerifyAsync(issued, Resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.Vct.Should().Be("https://credentials.example.com/identity_credential");
    }

    // ---- vct presence + validation ----

    [Fact]
    public async Task Issuer_rejects_claims_set_missing_vct()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var claims = SampleVcClaims();
        claims.Remove("vct");
        var frame = new DisclosureFrame().Disclose("given_name");

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, frame, issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*vct*");
    }

    [Fact]
    public async Task Issuer_rejects_blank_vct()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var claims = SampleVcClaims(vct: "");
        var frame = new DisclosureFrame().Disclose("given_name");

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, frame, issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*vct*");
    }

    [Fact]
    public async Task Verifier_rejects_a_non_vc_sd_jwt_with_a_profile_media_type_failure()
    {
        // A generic SD-JWT (typ example+sd-jwt, no vct) must be rejected by the VC verifier with a
        // media-type failure, BEFORE the generic verification, distinguishing it from a valid VC.
        using var doc = SdJwtFixtureSupport.Load("rfc9901", "example1-sd-jwt.json");
        var genericSdJwt = doc.RootElement.GetProperty("sd_jwt").GetString()!;

        var result = await SdJwtVcVerifier.VerifyAsync(genericSdJwt, Resolver);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_MEDIA_TYPE_INVALID");
    }

    [Fact]
    public async Task Verifier_accepts_the_transitional_vc_sd_jwt_media_type_on_input()
    {
        // draft-16 §3.5: the deprecated vc+sd-jwt typ is accepted on INPUT (older issuers). We
        // issue a generic SD-JWT with that typ and a vct claim, then verify through the VC verifier.
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var frame = new DisclosureFrame().Disclose("given_name");
        var issued = await SdJwtIssuer.IssueAsync(SampleVcClaims(), frame, issuer.Signer,
            typ: SdJwtVcConstants.TransitionalMediaType);

        var result = await SdJwtVcVerifier.VerifyAsync(issued.Issuance, _ => issuer.PublicJwk);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.Vct.Should().Be("https://credentials.example.com/identity_credential");
    }

    // ---- registered must-not-disclose claim rules (§3.2.2.2) ----

    public static IEnumerable<object[]> RegisteredClaimsFromFixture()
    {
        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "registered-claims.json");
        foreach (var prop in doc.RootElement.GetProperty("must_not_be_selectively_disclosed").EnumerateObject())
        {
            // 'iss'/'nbf'/'exp'/'cnf' need claim values to exist before the frame is checked; we
            // only test the vct/status/vct#integrity et al. that the issuer rejects at the frame.
            yield return [prop.Name];
        }
    }

    [Fact]
    public void Library_constants_match_the_fixtures_registered_must_not_disclose_set()
    {
        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "registered-claims.json");
        var fixtureSet = doc.RootElement.GetProperty("must_not_be_selectively_disclosed")
            .EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

        SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Should().BeEquivalentTo(fixtureSet,
            because: "draft-16 §2.2.2.2 lists exactly iss/nbf/exp/cnf/vct/vct#integrity/status");
    }

    [Theory]
    [MemberData(nameof(RegisteredClaimsFromFixture))]
    public async Task Issuer_rejects_disclosing_a_registered_must_not_disclose_claim(string reserved)
    {
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        // Build a claims set that carries the reserved claim so the only failure is the frame rule.
        var claims = SampleVcClaims();
        claims[reserved] = reserved switch
        {
            "exp" or "nbf" => 1883000000,
            "cnf" => new JsonObject { ["jwk"] = new JsonObject { ["kty"] = "EC" } },
            _ => "x",
        };
        var frame = new DisclosureFrame().Disclose(reserved);

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, frame, issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage($"*{reserved}*",
            because: $"draft-16 §2.2.2.2 forbids selectively disclosing '{reserved}'");
    }

    [Fact]
    public async Task Verifier_rejects_a_presentation_that_discloses_a_registered_claim()
    {
        // Adversarial: a (generic) issuer that DID place a reserved claim (iss) in a Disclosure.
        // The VC verifier must reject it even though the generic SD-JWT reconstructs fine.
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var claims = SampleVcClaims();
        // Issue via the generic issuer (bypassing the VC issuer's frame guard) with iss disclosable.
        var frame = new DisclosureFrame().Disclose("iss");
        var issued = await SdJwtIssuer.IssueAsync(claims, frame, issuer.Signer, typ: SdJwtVcConstants.MediaType);

        var result = await SdJwtVcVerifier.VerifyAsync(issued.Issuance, _ => issuer.PublicJwk);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.StartsWith("VC_DISALLOWED_DISCLOSURE"));
    }

    // ---- issuer/holder/verifier round trip with Key Binding ----

    [Fact]
    public async Task Vc_issuer_holder_verifier_round_trip_with_key_binding()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");

        var options = new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk };
        var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name").Disclose("address");
        var issued = await SdJwtVcIssuer.IssueAsync(SampleVcClaims(), frame, issuer.Signer, options);

        // Issuer fixed the typ to dc+sd-jwt.
        var header = SdJwtComponents.Parse(issued.Issuance).IssuerJwt;
        global::DataProofsDotnet.Jose.Base64Url.DecodeUtf8(header.Split('.')[0])
            .Should().Contain(SdJwtVcConstants.MediaType);

        const string audience = "https://example.com/verifier";
        const string nonce = "abc-123";
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance,
            issued.Disclosures.Where(d => d.ClaimName == "given_name").Select(d => d.Encoded),
            holder.Signer, audience, nonce);

        var verifyOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = audience,
            ExpectedNonce = nonce,
        };
        var result = await SdJwtVcVerifier.VerifyAsync(presentation, _ => issuer.PublicJwk, verifyOptions);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue();
        result.DisclosedPayload!["given_name"]!.GetValue<string>().Should().Be("John");
        result.DisclosedPayload!.Should().NotContainKey("family_name", "the holder withheld it");
    }

    // ---- Type Metadata retrieval via the offline LocalCacheTypeMetadataResolver (FR-17) ----

    [Fact]
    public async Task Type_metadata_is_resolved_from_the_local_cache_resolver()
    {
        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "type-metadata-example.json");
        var typeMetadataDoc = SdJwtFixtureSupport.ToJsonObject(doc.RootElement.GetProperty("type_metadata_document"));
        const string vct = "https://credentials.example.com/identity_credential";

        // Seed the offline resolver with the vct → Type Metadata mapping (local-cache, no network).
        var resolver = new LocalCacheTypeMetadataResolver(new Dictionary<string, JsonObject>
        {
            [vct] = typeMetadataDoc,
        });

        using var presentationDoc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "example-presentation-no-kb.json");
        var presentation = presentationDoc.RootElement.GetProperty("presentation").GetString()!;

        var result = await SdJwtVcVerifier.VerifyAsync(presentation, Resolver, typeMetadataResolver: resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.TypeMetadata.Should().NotBeNull("the resolver knows this vct");
        result.TypeMetadata!["vct"]!.GetValue<string>().Should().Be(typeMetadataDoc["vct"]!.GetValue<string>());
    }

    [Fact]
    public async Task Type_metadata_for_an_unknown_vct_returns_null_without_network()
    {
        // Fail-closed offline default: an empty resolver returns null for any vct (FR-10/FR-17).
        var resolver = new LocalCacheTypeMetadataResolver();

        using var doc = SdJwtFixtureSupport.Load("sd-jwt-vc-16", "example-presentation-no-kb.json");
        var presentation = doc.RootElement.GetProperty("presentation").GetString()!;

        var result = await SdJwtVcVerifier.VerifyAsync(presentation, Resolver, typeMetadataResolver: resolver);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.TypeMetadata.Should().BeNull("the offline resolver does not know this vct and never reaches the network");
    }

    [Fact]
    public async Task Local_cache_resolver_returns_null_for_unseeded_vct()
    {
        var resolver = new LocalCacheTypeMetadataResolver(new Dictionary<string, JsonObject>
        {
            ["https://known.example/type"] = new JsonObject { ["vct"] = "https://known.example/type" },
        });

        (await resolver.ResolveAsync("https://unknown.example/type")).Should().BeNull();
        (await resolver.ResolveAsync("https://known.example/type")).Should().NotBeNull();
    }
}
