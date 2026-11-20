using System.Text;
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
/// RFC 9901 §4.1.1: <c>_sd_alg</c> "MUST appear at the top level of the SD-JWT payload. It MUST NOT be used in any
/// object nested within the payload." Releases up to 2.0.0 dropped a nested <c>_sd_alg</c> during reconstruction and
/// verified the SD-JWT; this PR first kept it as ordinary data, which the PR #54 review refused. A nested
/// <c>_sd_alg</c>, in the clear, inside a disclosed value, or introduced by a Disclosure's name, is now refused on
/// verification, and <see cref="SdJwtIssuer"/> no longer signs one. The top-level and default-algorithm cases are the
/// controls. Only public API is used, so this file also compiles against earlier heads.
/// </summary>
public sealed class SdJwtSdAlgPlacementTests
{
    private static readonly TestKeyMaterial Issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

    /// <summary>Signs <paramref name="payloadJson"/> as given as a <c>dc+sd-jwt</c> issuer JWT and appends the Disclosures.</summary>
    private static async Task<string> SignAsGiven(string payloadJson, params Disclosure[] disclosures)
    {
        var jwt = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(payloadJson), Issuer.Signer, typ: "dc+sd-jwt");
        return jwt + "~" + string.Concat(disclosures.Select(d => d.Encoded + "~"));
    }

    private static Task<string> SignAsGiven(JsonObject payload, params Disclosure[] disclosures)
        => SignAsGiven(payload.ToJsonString(), disclosures);

    private static string Digest(Disclosure disclosure, string sdAlg = "sha-256") => disclosure.ComputeDigest(sdAlg);

    private static JsonArray Sd(Disclosure disclosure, string sdAlg = "sha-256") => new((JsonNode)Digest(disclosure, sdAlg));

    private static JsonObject Placeholder(Disclosure disclosure, string sdAlg = "sha-256") => new() { ["..."] = Digest(disclosure, sdAlg) };

    private static async Task ShouldBeRefusedOnBothVerifiers(string presentation)
    {
        var generic = SdJwtVerifier.Verify(presentation, _ => Issuer.PublicJwk);
        var vc = await SdJwtVcVerifier.VerifyAsync(presentation, _ => Issuer.PublicJwk);

        generic.IsValid.Should().BeFalse();
        generic.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("§4.1.1");
        vc.IsValid.Should().BeFalse();
        vc.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("§4.1.1");
    }

    // ---- Verification: a nested _sd_alg is refused ----

    [Fact]
    public async Task The_reviewers_reproduction_in_the_clear_is_refused()
    {
        await ShouldBeRefusedOnBothVerifiers(await SignAsGiven(
            """{"vct":"urn:example:credential","_sd_alg":"sha-256","address":{"_sd_alg":"sha-512","country":"DE"}}"""));
    }

    [Fact]
    public async Task The_reviewers_reproduction_inside_a_presented_disclosure_is_refused()
    {
        var address = Disclosure.ForObjectProperty(
            "salt-address", "address", new JsonObject { ["_sd_alg"] = "sha-512", ["country"] = "DE" });

        await ShouldBeRefusedOnBothVerifiers(await SignAsGiven(
            new JsonObject { ["vct"] = "urn:example:credential", ["_sd_alg"] = "sha-256", ["_sd"] = Sd(address) }, address));
    }

    [Fact]
    public async Task A_nested_sd_alg_inside_an_array_is_refused_in_the_clear_and_in_an_element_disclosure()
    {
        var element = Disclosure.ForArrayElement("salt-element", new JsonObject { ["_sd_alg"] = "sha-512" });

        await ShouldBeRefusedOnBothVerifiers(await SignAsGiven(
            """{"vct":"urn:example:credential","items":[{"_sd_alg":"sha-512"}]}"""));
        await ShouldBeRefusedOnBothVerifiers(await SignAsGiven(
            new JsonObject { ["vct"] = "urn:example:credential", ["items"] = new JsonArray(Placeholder(element)) }, element));
    }

    [Fact]
    public async Task A_disclosure_that_introduces_sd_alg_into_a_nested_object_is_refused()
    {
        var named = Disclosure.ForObjectProperty("salt-named", "_sd_alg", JsonValue.Create("sha-512"));

        await ShouldBeRefusedOnBothVerifiers(await SignAsGiven(
            new JsonObject
            {
                ["vct"] = "urn:example:credential",
                ["address"] = new JsonObject { ["country"] = "DE", ["_sd"] = Sd(named) },
            },
            named));
    }

    [Fact]
    public async Task A_disclosure_named_sd_alg_beside_the_top_level_sd_alg_is_refused()
    {
        // RFC 9901 §7.1 step 3.c.ii.3: "If the claim name already exists at the level of the _sd key, the SD-JWT MUST
        // be rejected." It used to replace _sd_alg in the processed payload.
        var shadow = Disclosure.ForObjectProperty("salt-alg", "_sd_alg", JsonValue.Create("sha-512"));
        var presentation = await SignAsGiven(new JsonObject { ["_sd_alg"] = "sha-256", ["_sd"] = Sd(shadow) }, shadow);

        var result = SdJwtVerifier.Verify(presentation, _ => Issuer.PublicJwk);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("collides");
    }

    // ---- Verification controls: the top-level and default algorithm ----

    [Theory]
    [InlineData("sha-256")]
    [InlineData("sha-512")]
    [InlineData(null)]
    public async Task A_top_level_or_default_sd_alg_with_nested_disclosures_verifies(string? sdAlg)
    {
        var inner = Disclosure.ForObjectProperty("salt-inner", "locality", JsonValue.Create("Anytown"));
        var element = Disclosure.ForArrayElement("salt-el", JsonValue.Create("DE"));
        var algorithm = sdAlg ?? "sha-256";
        var payload = new JsonObject
        {
            ["vct"] = "urn:example:credential",
            ["address"] = new JsonObject { ["country"] = "DE", ["_sd"] = Sd(inner, algorithm) },
            ["nationalities"] = new JsonArray(Placeholder(element, algorithm)),
        };
        if (sdAlg is not null)
            payload["_sd_alg"] = sdAlg;
        var presentation = await SignAsGiven(payload, inner, element);

        var generic = SdJwtVerifier.Verify(presentation, _ => Issuer.PublicJwk);
        var vc = await SdJwtVcVerifier.VerifyAsync(presentation, _ => Issuer.PublicJwk);

        generic.IsValid.Should().BeTrue(string.Join("; ", generic.Errors));
        vc.IsValid.Should().BeTrue(string.Join("; ", vc.Errors));
        generic.DisclosedPayload!.Should().NotContainKey("_sd_alg");
        generic.DisclosedPayload!["address"]!.ToJsonString().Should().Be("""{"country":"DE","locality":"Anytown"}""");
        generic.DisclosedPayload!["nationalities"]!.ToJsonString().Should().Be("""["DE"]""");
    }

    // ---- Issuance: SdJwtIssuer does not sign a nested _sd_alg ----

    public static TheoryData<string> NestedSdAlgClaims => new()
    {
        "in the clear",
        "inside a disclosed value",
        "framed as a nested disclosure",
        "inside an array element",
        "inside a .NET object",
    };

    [Theory]
    [MemberData(nameof(NestedSdAlgClaims))]
    public async Task The_issuer_refuses_a_claims_set_with_a_nested_sd_alg(string shape)
    {
        var address = new JsonObject { ["_sd_alg"] = "sha-512", ["country"] = "DE" };
        var claims = new JsonObject { ["vct"] = "urn:example:credential", ["given_name"] = "Erika" };
        DisclosureFrame frame;
        switch (shape)
        {
            case "in the clear":
                claims["address"] = address;
                frame = new DisclosureFrame().Disclose("given_name");
                break;
            case "inside a disclosed value":
                claims["address"] = address;
                frame = new DisclosureFrame().Disclose("address");
                break;
            case "framed as a nested disclosure":
                claims["address"] = address;
                frame = new DisclosureFrame().DiscloseObjectProperties("address", "_sd_alg");
                break;
            case "inside an array element":
                claims["items"] = new JsonArray(address);
                frame = new DisclosureFrame().DiscloseArrayElements("items", 0);
                break;
            default:
                claims["address"] = JsonValue.Create(new Dictionary<string, string> { ["_sd_alg"] = "sha-512" });
                frame = new DisclosureFrame().Disclose("given_name");
                break;
        }

        Func<Task> generic = () => SdJwtIssuer.IssueAsync(claims, frame, Issuer.Signer, typ: "dc+sd-jwt");
        Func<Task> vc = () => SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer);

        await generic.Should().ThrowAsync<MalformedJoseException>().WithMessage("*_sd_alg*§4.1.1*");
        await vc.Should().ThrowAsync<MalformedJoseException>().WithMessage("*_sd_alg*§4.1.1*");
    }

    [Fact]
    public async Task The_issuer_refuses_a_frame_that_discloses_the_top_level_sd_alg()
    {
        // The issuer writes the clear _sd_alg itself, so a Disclosure of the caller's _sd_alg would clash with it.
        var claims = new JsonObject { ["_sd_alg"] = "sha-256", ["given_name"] = "Erika" };

        Func<Task> act = () => SdJwtIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("_sd_alg"), Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*'_sd_alg' collides*");
    }

    [Theory]
    [InlineData("sha-256")]
    [InlineData("sha-512")]
    public async Task The_issuer_still_signs_nested_disclosures_under_the_top_level_sd_alg(string hashAlgorithm)
    {
        // Controls: the issuer's own top-level _sd_alg, a caller's top-level _sd_alg it overwrites, and every frame kind.
        var claims = new JsonObject
        {
            ["vct"] = "urn:example:credential",
            ["_sd_alg"] = "sha-384",
            ["address"] = new JsonObject { ["country"] = "DE", ["locality"] = "Anytown" },
            ["employment"] = new JsonObject { ["employer"] = "Example", ["since"] = 2020 },
            ["nationalities"] = new JsonArray("DE", "FR"),
        };
        var frame = new DisclosureFrame()
            .DiscloseObjectProperties("address", "locality")
            .DiscloseRecursively("employment", "since")
            .DiscloseArrayElements("nationalities", 1);
        var options = new SdJwtIssuerOptions { HashAlgorithm = hashAlgorithm, DecoyDigestCount = 2 };

        var issued = await SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer, options);
        var result = await SdJwtVcVerifier.VerifyAsync(issued.Issuance, _ => Issuer.PublicJwk);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        Base64Url.DecodeUtf8(issued.IssuerJwt.Split('.')[1]).Should().Contain($"\"_sd_alg\":\"{hashAlgorithm}\"");
    }
}
