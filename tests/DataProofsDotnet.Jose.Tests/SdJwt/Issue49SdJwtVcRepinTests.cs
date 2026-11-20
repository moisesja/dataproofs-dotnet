using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// Issue #49: the SD-JWT VC profile moves from draft-ietf-oauth-sd-jwt-vc-16 to -27.
/// <list type="bullet">
/// <item>-19 removed the transitional <c>vc+sd-jwt</c> <c>typ</c>; -27 §2.2.1 requires <c>dc+sd-jwt</c>,
/// so <see cref="SdJwtVcVerifier"/> refuses <c>vc+sd-jwt</c> however it is spelled or dressed.</item>
/// <item>-18 added <c>aka_vcts</c>; -27 §2.2.2.3 puts it on the must-not-disclose list and §2.2.2.2
/// fixes its format: a non-empty array of strings that does not contain the <c>vct</c> value.</item>
/// </list>
/// Claim names are literals rather than the new constants, so this file also compiles against the
/// 2.0.0 sources and shows each regression failing there.
/// </summary>
public sealed class Issue49SdJwtVcRepinTests
{
    private const string Vct = "https://credentials.example.com/identity_credential";
    private const string AkaVcts = "aka_vcts";

    private static readonly TestKeyMaterial Issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

    private static JsonObject Claims(JsonNode? akaVcts = null, bool withAkaVcts = false)
    {
        var claims = new JsonObject
        {
            ["iss"] = "https://example.com/issuer",
            ["vct"] = Vct,
            ["given_name"] = "John",
            ["family_name"] = "Doe",
        };
        if (withAkaVcts)
            claims[AkaVcts] = akaVcts;
        return claims;
    }

    private static Task<SdJwtVcVerificationResult> VerifyVc(string presentation)
        => SdJwtVcVerifier.VerifyAsync(presentation, _ => Issuer.PublicJwk);

    /// <summary>
    /// Replaces the issuer JWT's protected header with <paramref name="headerJson"/> exactly as given and
    /// signs again with the issuer's Ed25519 key, keeping the payload and every Disclosure. The result
    /// carries a valid signature, so the only thing a verifier can refuse is the header.
    /// </summary>
    private static async Task<string> ResignWithHeader(string issuance, string headerJson)
    {
        var tilde = issuance.IndexOf('~', StringComparison.Ordinal);
        var issuerJwt = issuance[..tilde];
        var payloadSegment = issuerJwt.Split('.')[1];
        var signingInput = $"{Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson))}.{payloadSegment}";
        var signature = await Issuer.Signer.Signer.SignAsync(Encoding.ASCII.GetBytes(signingInput), CancellationToken.None);
        return $"{signingInput}.{Base64Url.Encode(signature)}{issuance[tilde..]}";
    }

    private static async Task<string> IssueGeneric(JsonObject claims, DisclosureFrame frame, string? typ)
        => (await SdJwtIssuer.IssueAsync(claims, frame, Issuer.Signer, typ: typ)).Issuance;

    // ---- vc+sd-jwt is no longer an SD-JWT VC media type (-27 §2.2.1) ----

    [Fact]
    public async Task Verifier_rejects_the_former_vc_sd_jwt_typ()
    {
        // The exact token 2.0.0 accepted as "transitional": a valid signature, a vct, typ vc+sd-jwt.
        var issued = await IssueGeneric(Claims(), new DisclosureFrame().Disclose("given_name"), "vc+sd-jwt");

        var result = await VerifyVc(issued);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_MEDIA_TYPE_INVALID")
            .And.Contain("draft-ietf-oauth-sd-jwt-vc-27 §2.2.1");
    }

    [Theory]
    [InlineData("""{"alg":"EdDSA","typ":"vc+sd-jwt"}""")]
    [InlineData("""{"alg":"EdDSA","typ":"VC+SD-JWT"}""")]
    [InlineData("""{"alg":"EdDSA","typ":"Vc+Sd-Jwt"}""")]
    [InlineData("""{"alg":"EdDSA","typ":"application/vc+sd-jwt"}""")]
    [InlineData("""{"alg":"EdDSA","typ":"APPLICATION/VC+SD-JWT"}""")]
    [InlineData("""{"alg":"EdDSA","typ":" vc+sd-jwt"}""")]
    [InlineData("""{"alg":"EdDSA","typ":"vc+sd-jwt "}""")]
    [InlineData("""{"alg":"EdDSA","typ":"vc+sd-jwt","cty":"dc+sd-jwt"}""")]
    [InlineData("""{"alg":"EdDSA","cty":"dc+sd-jwt"}""")]
    [InlineData("""{"alg":"EdDSA","typ":["dc+sd-jwt"]}""")]
    [InlineData("""{"alg":"EdDSA","typ":{"value":"dc+sd-jwt"}}""")]
    [InlineData("""{"alg":"EdDSA","typ":null}""")]
    [InlineData("""{"alg":"EdDSA","typ":"vc+sd-jwt","typ":"dc+sd-jwt"}""")]
    [InlineData("""{"alg":"EdDSA","typ":"dc+sd-jwt","typ":"vc+sd-jwt"}""")]
    public async Task Verifier_rejects_every_header_that_is_not_typ_dc_sd_jwt(string headerJson)
    {
        var issued = await IssueGeneric(Claims(), new DisclosureFrame().Disclose("given_name"), "dc+sd-jwt");
        var presentation = await ResignWithHeader(issued, headerJson);

        var result = await VerifyVc(presentation);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Match(e => e.StartsWith("VC_MEDIA_TYPE_INVALID") || e.StartsWith("MALFORMED"));
    }

    [Fact]
    public async Task Resigned_header_control_dc_sd_jwt_still_verifies()
    {
        // Positive control for the theory above: the same re-signing with typ dc+sd-jwt verifies, so
        // each rejection there is the header's doing.
        var issued = await IssueGeneric(Claims(), new DisclosureFrame().Disclose("given_name"), "dc+sd-jwt");
        var presentation = await ResignWithHeader(issued, """{"alg":"EdDSA","typ":"dc+sd-jwt"}""");

        var result = await VerifyVc(presentation);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.Vct.Should().Be(Vct);
    }

    [Fact]
    public async Task Generic_SdJwtVerifier_still_does_not_gate_typ()
    {
        // RFC 9901 §9.11 leaves explicit typing to the profile; the generic layer stays typ-agnostic, which is
        // how a consumer builds W3C VC-JOSE-COSE's own vc+sd-jwt form on it.
        var issued = await IssueGeneric(Claims(), new DisclosureFrame().Disclose("given_name"), "vc+sd-jwt");

        var result = SdJwtVerifier.Verify(issued, _ => Issuer.PublicJwk);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public void TransitionalMediaType_keeps_its_value_and_is_obsolete()
    {
        // Minor release: the public constant stays, unchanged, and says why it should not be used.
        var field = typeof(SdJwtVcConstants).GetField("TransitionalMediaType", BindingFlags.Public | BindingFlags.Static)!;

        field.IsLiteral.Should().BeTrue();
        field.GetRawConstantValue().Should().Be("vc+sd-jwt");
        field.GetCustomAttribute<ObsoleteAttribute>().Should().NotBeNull()
            .And.Match<ObsoleteAttribute>(a => !a.IsError && a.Message!.Contains("dc+sd-jwt"));
    }

    [Fact]
    public async Task Vc_issuer_output_is_dc_sd_jwt_and_still_verifies()
    {
        // What this library has always issued is unaffected by the narrowing.
        var issued = await SdJwtVcIssuer.IssueAsync(Claims(), new DisclosureFrame().Disclose("given_name"), Issuer.Signer);
        var header = Base64Url.DecodeUtf8(issued.Issuance.Split('~')[0].Split('.')[0]);

        header.Should().Contain("\"typ\":\"dc+sd-jwt\"");
        (await VerifyVc(issued.Issuance)).IsValid.Should().BeTrue();
    }

    // ---- aka_vcts must not be selectively disclosed (-27 §2.2.2.3) ----

    [Fact]
    public void Must_not_disclose_list_names_aka_vcts()
    {
        SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Should().Contain(AkaVcts);
    }

    [Fact]
    public async Task Issuer_refuses_to_make_aka_vcts_disclosable()
    {
        var claims = Claims(new JsonArray("urn:example:general"), withAkaVcts: true);

        Func<Task> whole = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose(AkaVcts), Issuer.Signer);
        Func<Task> element = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().DiscloseArrayElements(AkaVcts, 0), Issuer.Signer);

        await whole.Should().ThrowAsync<MalformedJoseException>().WithMessage("*'aka_vcts' MUST NOT be selectively disclosed*");
        await element.Should().ThrowAsync<MalformedJoseException>().WithMessage("*'aka_vcts' MUST NOT be selectively disclosed*");
    }

    [Fact]
    public async Task Verifier_rejects_a_presentation_that_discloses_aka_vcts()
    {
        // A generic issuer (bypassing the VC issuer's frame guard) put aka_vcts in a Disclosure.
        var claims = Claims(new JsonArray("urn:example:general"), withAkaVcts: true);
        var issued = await IssueGeneric(claims, new DisclosureFrame().Disclose(AkaVcts), "dc+sd-jwt");

        var result = await VerifyVc(issued);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE")
            .And.Contain("'aka_vcts'").And.Contain("§2.2.2.3");
    }

    [Fact]
    public async Task Aka_vcts_in_the_clear_round_trips()
    {
        var claims = Claims(new JsonArray("urn:example:general", "urn:example:other"), withAkaVcts: true);
        var issued = await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        var result = await VerifyVc(issued.Issuance);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload![AkaVcts]!.AsArray().Select(n => n!.GetValue<string>())
            .Should().Equal("urn:example:general", "urn:example:other");
    }

    // ---- aka_vcts format (-27 §2.2.2.2) ----

    public static TheoryData<string> MalformedAkaVcts() => new()
    {
        "\"urn:example:general\"",        // a string, not an array
        "[]",                              // empty
        "[1]",                             // not a string
        "[\"\"]",                          // empty string
        "[null]",
        "[[\"urn:example:general\"]]",
        "[{\"vct\":\"urn:example:general\"}]",
        "[\"urn:example:general\", 2]",
        $"[\"{Vct}\"]",                    // contains the vct value
        $"[\"urn:example:general\", \"{Vct}\"]",
        "null",
        "{}",
        "true",
    };

    [Theory]
    [MemberData(nameof(MalformedAkaVcts))]
    public async Task Issuer_rejects_a_malformed_aka_vcts(string akaVctsJson)
    {
        var claims = Claims(JsonNode.Parse(akaVctsJson), withAkaVcts: true);

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*'aka_vcts'*§2.2.2.2*");
    }

    [Theory]
    [MemberData(nameof(MalformedAkaVcts))]
    public async Task Verifier_rejects_a_malformed_aka_vcts(string akaVctsJson)
    {
        // Signed in the clear by a generic issuer, so only the format rule can refuse it.
        var claims = Claims(JsonNode.Parse(akaVctsJson), withAkaVcts: true);
        var issued = await IssueGeneric(claims, new DisclosureFrame().Disclose("given_name"), "dc+sd-jwt");

        var result = await VerifyVc(issued);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_AKA_VCTS_INVALID").And.Contain("§2.2.2.2");
    }

    /// <summary>
    /// (vct, aka_vcts value) pairs with lone surrogates, built from code units at run time. They are looked up
    /// by index inside the test, because xUnit serializes theory arguments and would hand the test U+FFFD in
    /// place of each lone surrogate, which is exactly the substitution under test.
    /// </summary>
    private static (string Vct, string AkaVctsValue) IllFormedCase(int index)
    {
        var high = ((char)0xD800).ToString();
        var low = ((char)0xDC00).ToString();
        return index switch
        {
            // The adversarial pass's case: vct and the aka_vcts value differ as .NET strings, but the JSON
            // writer turns each lone surrogate into U+FFFD, so the signed aka_vcts would contain the vct value.
            0 => ("urn:t:" + high, "urn:t:" + low),
            1 => (Vct, "urn:t:" + high),
            2 => ("urn:t:" + low, "urn:example:general"),
            3 => (Vct, "urn:t:" + low + high),
            _ => throw new ArgumentOutOfRangeException(nameof(index)),
        };
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Issuer_rejects_a_type_string_that_is_not_well_formed_utf16(int caseIndex)
    {
        // What the issuer signs must be what it checked. A lone surrogate is not text; JSON serialization would
        // replace it, so the type claims are refused before signing instead.
        var (vct, akaVctsValue) = IllFormedCase(caseIndex);
        (vct + akaVctsValue).Should().Contain(((char)(caseIndex == 2 ? 0xDC00 : 0xD800)).ToString(), "the case carries a lone surrogate");
        var claims = Claims(new JsonArray(akaVctsValue), withAkaVcts: true);
        claims["vct"] = vct;

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*well-formed*");
    }

    [Fact]
    public async Task Issuer_rejects_a_parsed_lone_surrogate_escape_in_the_type_claims_through_the_contract()
    {
        // A JsonNode parsed from text that escapes a lone surrogate throws InvalidOperationException when its
        // string is read; the issuer reports it as MalformedJoseException instead.
        var escape = @"\u" + 0xD800.ToString("X4");
        var inAka = JsonNode.Parse("{\"vct\":\"" + Vct + "\",\"given_name\":\"x\",\"aka_vcts\":[\"" + escape + "\"]}")!.AsObject();
        var inVct = JsonNode.Parse("{\"vct\":\"urn:t:" + escape + "\",\"given_name\":\"x\"}")!.AsObject();

        Func<Task> aka = () => SdJwtVcIssuer.IssueAsync(inAka, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);
        Func<Task> vct = () => SdJwtVcIssuer.IssueAsync(inVct, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        await aka.Should().ThrowAsync<MalformedJoseException>();
        await vct.Should().ThrowAsync<MalformedJoseException>();
    }

    [Theory]
    [InlineData("[\"urn:example:general\"]")]
    [InlineData("[\"urn:example:general\", \"https://credentials.example.com/general\"]")]
    [InlineData("[\"urn:example:general\", \"urn:example:general\"]")] // duplicates: not forbidden by §2.2.2.2
    public async Task Well_formed_aka_vcts_is_accepted_on_both_sides(string akaVctsJson)
    {
        var claims = Claims(JsonNode.Parse(akaVctsJson), withAkaVcts: true);

        var issued = await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);
        var result = await VerifyVc(issued.Issuance);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
    }
}
