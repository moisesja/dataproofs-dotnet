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
/// Issue #45: SD-JWT and SD-JWT VC verification enforce the validity window. RFC 9901 §7.1 step 6: "Check that the
/// SD-JWT is valid using claims such as nbf, exp, and aud in the processed payload, if present";
/// draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3: <c>nbf</c> is "The time before which the Verifiable Digital Credential MUST
/// NOT be accepted", <c>exp</c> "The expiry time [...] after which the Verifiable Digital Credential is no longer valid".
/// Both are RFC 7519 NumericDates (§2, §4.1.4, §4.1.5), optional, judged at <see cref="SdJwtVerificationOptions.CurrentTime"/>
/// with <see cref="SdJwtVerificationOptions.ClockSkew"/>. Only public API is used, so this file also compiles against
/// <c>origin/main</c> and shows each regression failing there. The entry points added by #46 and #47 are in
/// <see cref="Issue45ValidityWindowEntryPointTests"/>.
/// </summary>
public sealed class Issue45ValidityWindowTests
{
    private const string Vct = "https://credentials.example.com/identity_credential";
    private const string SdAlg = "sha-256";
    private const string Audience = "https://verifier.example.org";
    private const string Nonce = "n-45";

    /// <summary>The fixed reference instant every judged test uses, so none depends on the wall clock.</summary>
    private static readonly DateTimeOffset Now = new(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);

    private static readonly long NowSeconds = Now.ToUnixTimeSeconds();

    private static readonly TestKeyMaterial Issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

    private static SdJwtVerificationOptions At(DateTimeOffset now, TimeSpan? skew = null)
        => new() { CurrentTime = now, ClockSkew = skew ?? TimeSpan.FromMinutes(2) };

    /// <summary>Signs <paramref name="payload"/> as an issuer JWT of type <paramref name="typ"/> and appends the Disclosures.</summary>
    private static async Task<string> Sign(JsonObject payload, string typ = "dc+sd-jwt", params Disclosure[] disclosures)
    {
        payload["_sd_alg"] = SdAlg;
        return await SignRaw(payload.ToJsonString(), typ, disclosures);
    }

    /// <summary>Signs the payload text as given, so a member can repeat or a number keep its spelling.</summary>
    private static async Task<string> SignRaw(string payloadJson, string typ = "dc+sd-jwt", params Disclosure[] disclosures)
    {
        var jwt = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(payloadJson), Issuer.Signer, typ: typ);
        return jwt + "~" + string.Concat(disclosures.Select(d => d.Encoded + "~"));
    }

    private static JsonObject VcPayload(params (string Name, JsonNode? Value)[] claims)
    {
        var payload = new JsonObject { ["vct"] = Vct, ["given_name"] = "Erika" };
        foreach (var (name, value) in claims)
            payload[name] = value;
        return payload;
    }

    /// <summary>A JSON number with this exact spelling, kept through serialization.</summary>
    private static JsonNode Number(string text) => JsonNode.Parse(text)!;

    private static Task<SdJwtVcVerificationResult> VerifyVc(string presentation, SdJwtVerificationOptions? options = null)
        => SdJwtVcVerifier.VerifyAsync(presentation, _ => Issuer.PublicJwk, options);

    private static SdJwtVerificationResult VerifyGeneric(string presentation, SdJwtVerificationOptions? options = null)
        => SdJwtVerifier.Verify(presentation, _ => Issuer.PublicJwk, options);

    private static void ShouldFailWith(IReadOnlyList<string> errors, bool isValid, params string[] codes)
    {
        isValid.Should().BeFalse();
        errors.Select(e => e.Split(':')[0]).Should().BeEquivalentTo(codes);
    }

    private static void ShouldFail(SdJwtVerificationResult result, params string[] codes)
        => ShouldFailWith(result.Errors, result.IsValid, codes);

    /// <summary>Runs the same presentation through both verifiers and expects the same codes from each.</summary>
    private static async Task ShouldFailOnBoth(string presentation, SdJwtVerificationOptions? options, params string[] codes)
    {
        var generic = VerifyGeneric(presentation, options);
        ShouldFailWith(generic.Errors, generic.IsValid, codes);
        generic.DisclosedPayload.Should().BeNull();

        var vc = await VerifyVc(presentation, options);
        ShouldFailWith(vc.Errors, vc.IsValid, codes);
        vc.DisclosedPayload.Should().BeNull();
    }

    private static async Task ShouldPassOnBoth(string presentation, SdJwtVerificationOptions? options)
    {
        var generic = VerifyGeneric(presentation, options);
        generic.IsValid.Should().BeTrue(string.Join("; ", generic.Errors));

        var vc = await VerifyVc(presentation, options);
        vc.IsValid.Should().BeTrue(string.Join("; ", vc.Errors));
    }

    // ------------------------------------------------------------------ the issue's reproduction

    [Fact]
    public async Task An_SD_JWT_VC_whose_exp_is_in_2001_fails_with_SD_JWT_EXPIRED()
    {
        // The issue's observation, with the wall clock: exp 1000000000 is 2001-09-09.
        var issued = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("exp", 1000000000)), new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        var vc = await VerifyVc(issued.Issuance);
        ShouldFailWith(vc.Errors, vc.IsValid, "SD_JWT_EXPIRED");
        vc.Errors.Single().Should().Contain("2001-09-09T01:46:40");

        var generic = VerifyGeneric(issued.Issuance);
        ShouldFailWith(generic.Errors, generic.IsValid, "SD_JWT_EXPIRED");
    }

    [Fact]
    public async Task An_SD_JWT_VC_whose_nbf_is_in_2100_fails_with_SD_JWT_NOT_YET_VALID()
    {
        var issued = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("nbf", 4102444800)), new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        var vc = await VerifyVc(issued.Issuance);
        ShouldFailWith(vc.Errors, vc.IsValid, "SD_JWT_NOT_YET_VALID");
        vc.Errors.Single().Should().Contain("2100-01-01T00:00:00");

        var generic = VerifyGeneric(issued.Issuance);
        ShouldFailWith(generic.Errors, generic.IsValid, "SD_JWT_NOT_YET_VALID");
    }

    [Fact]
    public async Task A_generic_SD_JWT_of_another_type_is_held_to_the_same_window()
    {
        // RFC 9901 §7.1 step 6 is generic: the window is not an SD-JWT VC rule.
        var expired = await Sign(new JsonObject { ["sub"] = "user", ["exp"] = NowSeconds - 3600 }, typ: "example+sd-jwt");
        ShouldFail(VerifyGeneric(expired, At(Now)), "SD_JWT_EXPIRED");

        var valid = await Sign(new JsonObject { ["sub"] = "user", ["exp"] = NowSeconds + 3600 }, typ: "example+sd-jwt");
        VerifyGeneric(valid, At(Now)).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Inside_the_window_and_without_either_claim_a_credential_verifies()
    {
        await ShouldPassOnBoth(await Sign(VcPayload(("nbf", NowSeconds - 60), ("exp", NowSeconds + 60))), At(Now, TimeSpan.Zero));
        await ShouldPassOnBoth(await Sign(VcPayload(("exp", NowSeconds + 60))), At(Now, TimeSpan.Zero));
        await ShouldPassOnBoth(await Sign(VcPayload(("nbf", NowSeconds))), At(Now, TimeSpan.Zero));
        await ShouldPassOnBoth(await Sign(VcPayload()), At(Now, TimeSpan.Zero));

        // Without either claim nothing is judged, at any instant and with any skew.
        await ShouldPassOnBoth(await Sign(VcPayload()), At(DateTimeOffset.MaxValue, TimeSpan.MinValue));
    }

    [Fact]
    public async Task Both_claims_are_judged_so_an_inverted_window_can_report_both()
    {
        // nbf later than exp: with no skew there is no instant at which the credential is valid.
        var inverted = await Sign(VcPayload(("nbf", NowSeconds + 10), ("exp", NowSeconds)));

        await ShouldFailOnBoth(inverted, At(Now.AddSeconds(-1), TimeSpan.Zero), "SD_JWT_NOT_YET_VALID");
        await ShouldFailOnBoth(inverted, At(Now.AddSeconds(5), TimeSpan.Zero), "SD_JWT_NOT_YET_VALID", "SD_JWT_EXPIRED");
        await ShouldFailOnBoth(inverted, At(Now.AddSeconds(20), TimeSpan.Zero), "SD_JWT_EXPIRED");
    }

    // ------------------------------------------------------------------ the boundary: exp exclusive, nbf inclusive

    public static TheoryData<int> Skews => new() { 0, 120 };

    [Theory]
    [MemberData(nameof(Skews))]
    public async Task Exp_is_refused_from_exactly_exp_plus_skew(int skewSeconds)
    {
        // RFC 7519 §4.1.4: "the current date/time MUST be before the expiration date/time"; the leeway adds exactly skew.
        var skew = TimeSpan.FromSeconds(skewSeconds);
        var presentation = await Sign(VcPayload(("exp", NowSeconds)));

        await ShouldPassOnBoth(presentation, At(Now + skew - TimeSpan.FromTicks(1), skew));
        await ShouldFailOnBoth(presentation, At(Now + skew, skew), "SD_JWT_EXPIRED");
        await ShouldFailOnBoth(presentation, At(Now + skew + TimeSpan.FromDays(1), skew), "SD_JWT_EXPIRED");
    }

    [Theory]
    [MemberData(nameof(Skews))]
    public async Task Nbf_is_accepted_from_exactly_nbf_minus_skew(int skewSeconds)
    {
        // RFC 7519 §4.1.5: "the current date/time MUST be after or equal to the not-before date/time", and the same
        // comparison as the Key Binding JWT iat check (iat - now > skew fails).
        var skew = TimeSpan.FromSeconds(skewSeconds);
        var presentation = await Sign(VcPayload(("nbf", NowSeconds)));

        await ShouldPassOnBoth(presentation, At(Now - skew, skew));
        await ShouldPassOnBoth(presentation, At(Now + TimeSpan.FromDays(1), skew));
        await ShouldFailOnBoth(presentation, At(Now - skew - TimeSpan.FromTicks(1), skew), "SD_JWT_NOT_YET_VALID");
    }

    [Fact]
    public async Task The_default_skew_is_two_minutes_and_current_time_defaults_to_the_wall_clock()
    {
        var justExpired = await Sign(VcPayload(("exp", DateTimeOffset.UtcNow.AddSeconds(-60).ToUnixTimeSeconds())));
        await ShouldPassOnBoth(justExpired, new SdJwtVerificationOptions());

        var longExpired = await Sign(VcPayload(("exp", DateTimeOffset.UtcNow.AddMinutes(-3).ToUnixTimeSeconds())));
        await ShouldFailOnBoth(longExpired, null, "SD_JWT_EXPIRED");
    }

    [Fact]
    public async Task Current_time_is_compared_as_an_instant_whatever_its_offset()
    {
        var presentation = await Sign(VcPayload(("exp", NowSeconds)));
        var sameInstantElsewhere = Now.ToOffset(TimeSpan.FromHours(14));

        await ShouldFailOnBoth(presentation, At(sameInstantElsewhere, TimeSpan.Zero), "SD_JWT_EXPIRED");
        await ShouldPassOnBoth(presentation, At(sameInstantElsewhere.AddTicks(-1), TimeSpan.Zero));
    }

    // ------------------------------------------------------------------ NumericDate values (RFC 7519 §2)

    [Fact]
    public async Task Fractional_seconds_are_kept_to_the_tick()
    {
        // Truncating to whole seconds would accept this nbf half a second early.
        var nbf = await Sign(VcPayload(("nbf", Number($"{NowSeconds}.5"))));
        await ShouldFailOnBoth(nbf, At(Now.AddMilliseconds(500).AddTicks(-1), TimeSpan.Zero), "SD_JWT_NOT_YET_VALID");
        await ShouldPassOnBoth(nbf, At(Now.AddMilliseconds(500), TimeSpan.Zero));

        var exp = await Sign(VcPayload(("exp", Number($"{NowSeconds}.5"))));
        await ShouldPassOnBoth(exp, At(Now.AddMilliseconds(500).AddTicks(-1), TimeSpan.Zero));
        await ShouldFailOnBoth(exp, At(Now.AddMilliseconds(500), TimeSpan.Zero), "SD_JWT_EXPIRED");
    }

    [Fact]
    public async Task A_remainder_below_one_tick_is_rounded_toward_refusal()
    {
        // Half a tick past Now: exp rounds down to Now, nbf up to Now plus one tick.
        var exp = await Sign(VcPayload(("exp", Number($"{NowSeconds}.00000005"))));
        await ShouldFailOnBoth(exp, At(Now, TimeSpan.Zero), "SD_JWT_EXPIRED");
        await ShouldPassOnBoth(exp, At(Now.AddTicks(-1), TimeSpan.Zero));

        var nbf = await Sign(VcPayload(("nbf", Number($"{NowSeconds}.00000005"))));
        await ShouldFailOnBoth(nbf, At(Now, TimeSpan.Zero), "SD_JWT_NOT_YET_VALID");
        await ShouldPassOnBoth(nbf, At(Now.AddTicks(1), TimeSpan.Zero));
    }

    public static TheoryData<string> ValidSpellings => new()
    {
        "1.7951112E9",   // exponent notation, upper case
        "1.7951112e+9",  // with a sign
        "17951112e2",
        "1795111200.000",
        "1795111200",
    };

    [Theory]
    [MemberData(nameof(ValidSpellings))]
    public async Task Any_JSON_spelling_of_a_number_is_a_NumericDate(string spelling)
    {
        // Every spelling is 1795111200, Now + 6 hours.
        var presentation = await Sign(VcPayload(("exp", Number(spelling))));
        await ShouldPassOnBoth(presentation, At(Now, TimeSpan.Zero));
        await ShouldFailOnBoth(presentation, At(Now.AddHours(6), TimeSpan.Zero), "SD_JWT_EXPIRED");
    }

    [Fact]
    public async Task The_representable_extremes_are_NumericDates()
    {
        // 9999-12-31T23:59:59Z and 0001-01-01T00:00:00Z, the bounds JwtClaims and the KB-JWT iat use.
        var far = await Sign(VcPayload(("nbf", Number("-62135596800")), ("exp", Number("253402300799"))));
        await ShouldPassOnBoth(far, At(Now));
        await ShouldPassOnBoth(far, At(DateTimeOffset.MinValue));
        await ShouldFailOnBoth(far, At(DateTimeOffset.MaxValue, TimeSpan.Zero), "SD_JWT_EXPIRED");

        var zero = await Sign(VcPayload(("exp", Number("-0"))));
        await ShouldFailOnBoth(zero, At(Now), "SD_JWT_EXPIRED");
        await ShouldPassOnBoth(zero, At(DateTimeOffset.UnixEpoch.AddTicks(-1), TimeSpan.Zero));
    }

    /// <summary>Present values that are not NumericDates: every non-number JSON type, and numbers out of range.</summary>
    public static TheoryData<string> NotNumericDates => new()
    {
        "\"1000000000\"", "\"2030-01-01T00:00:00Z\"", "\"\"", "true", "false", "null", "[]", "[4102444800]", "{}",
        "{\"exp\":4102444800}", "1e400", "-1e400", "1e20", "-1e20", "253402300800", "-62135596801",
        "253402300799.5", "-62135596800.5", "123456789012345678901234567890", "79228162514264337593543950336",
    };

    [Theory]
    [MemberData(nameof(NotNumericDates))]
    public async Task An_exp_that_is_not_a_NumericDate_fails_with_SD_JWT_EXP_INVALID(string json)
    {
        var presentation = await Sign(VcPayload(("exp", JsonNode.Parse(json))));

        // Refused at every instant and with every skew, the widest included.
        await ShouldFailOnBoth(presentation, At(Now), "SD_JWT_EXP_INVALID");
        await ShouldFailOnBoth(presentation, At(DateTimeOffset.MinValue, TimeSpan.MaxValue), "SD_JWT_EXP_INVALID");
    }

    [Theory]
    [MemberData(nameof(NotNumericDates))]
    public async Task An_nbf_that_is_not_a_NumericDate_fails_with_SD_JWT_NBF_INVALID(string json)
    {
        var presentation = await Sign(VcPayload(("nbf", JsonNode.Parse(json))));

        await ShouldFailOnBoth(presentation, At(Now), "SD_JWT_NBF_INVALID");
        await ShouldFailOnBoth(presentation, At(DateTimeOffset.MaxValue, TimeSpan.MaxValue), "SD_JWT_NBF_INVALID");
    }

    [Fact]
    public async Task Both_malformed_claims_are_reported()
    {
        var presentation = await Sign(VcPayload(("nbf", "yesterday"), ("exp", "tomorrow")));
        await ShouldFailOnBoth(presentation, At(Now), "SD_JWT_NBF_INVALID", "SD_JWT_EXP_INVALID");
    }

    // ------------------------------------------------------------------ the clock skew and the current time at their extremes

    [Fact]
    public async Task A_negative_skew_narrows_the_window_on_both_sides()
    {
        var skew = TimeSpan.FromMinutes(-1);
        var presentation = await Sign(VcPayload(("nbf", NowSeconds), ("exp", NowSeconds + 600)));

        await ShouldFailOnBoth(presentation, At(Now.AddSeconds(30), skew), "SD_JWT_NOT_YET_VALID");
        await ShouldPassOnBoth(presentation, At(Now.AddSeconds(60), skew));
        await ShouldPassOnBoth(presentation, At(Now.AddSeconds(539), skew));
        await ShouldFailOnBoth(presentation, At(Now.AddSeconds(540), skew), "SD_JWT_EXPIRED");
    }

    public static TheoryData<long, long, long> Extremes => new()
    {
        // CurrentTime (ticks), ClockSkew (ticks), exp and nbf (seconds): every combination that could overflow a sum.
        { DateTimeOffset.MaxValue.UtcTicks, TimeSpan.MaxValue.Ticks, -62135596800 },
        { DateTimeOffset.MaxValue.UtcTicks, TimeSpan.MinValue.Ticks, -62135596800 },
        { DateTimeOffset.MinValue.UtcTicks, TimeSpan.MaxValue.Ticks, 253402300799 },
        { DateTimeOffset.MinValue.UtcTicks, TimeSpan.MinValue.Ticks, 253402300799 },
        { DateTimeOffset.MaxValue.UtcTicks, TimeSpan.MaxValue.Ticks, 253402300799 },
        { DateTimeOffset.MinValue.UtcTicks, TimeSpan.MinValue.Ticks, -62135596800 },
    };

    [Theory]
    [MemberData(nameof(Extremes))]
    public async Task No_current_time_or_skew_overflows(long nowTicks, long skewTicks, long seconds)
    {
        var options = At(new DateTimeOffset(nowTicks, TimeSpan.Zero), TimeSpan.FromTicks(skewTicks));
        var presentation = await Sign(VcPayload(("nbf", seconds), ("exp", seconds)));

        var generic = VerifyGeneric(presentation, options);
        var vc = await VerifyVc(presentation, options);

        // A maximal skew accepts the whole representable range; a minimal one refuses every present claim.
        var expected = skewTicks > 0 ? Array.Empty<string>() : ["SD_JWT_NOT_YET_VALID", "SD_JWT_EXPIRED"];
        generic.Errors.Select(e => e.Split(':')[0]).Should().BeEquivalentTo(expected);
        vc.Errors.Select(e => e.Split(':')[0]).Should().BeEquivalentTo(expected);
    }

    [Fact]
    public async Task The_Key_Binding_age_bound_does_not_overflow_on_a_maximal_skew()
    {
        // maxAge + ClockSkew threw OverflowException out of both verifiers before.
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var issued = await SdJwtVcIssuer.IssueAsync(
            VcPayload(), new DisclosureFrame().Disclose("given_name"), Issuer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holder.Signer, Audience, Nonce, Now);
        var options = new SdJwtVerificationOptions
        {
            CurrentTime = Now, ClockSkew = TimeSpan.MaxValue, MaxKeyBindingAge = TimeSpan.FromMinutes(5),
            ExpectedAudience = Audience, ExpectedNonce = Nonce,
        };

        VerifyGeneric(presentation, options).IsValid.Should().BeTrue();
        (await VerifyVc(presentation, options)).IsValid.Should().BeTrue();
        VerifyGeneric(presentation, options with { MaxKeyBindingAge = TimeSpan.MaxValue }).IsValid.Should().BeTrue();
    }

    // ------------------------------------------------------------------ what is read: the top level, as signed

    [Fact]
    public async Task A_nested_exp_or_nbf_is_an_ordinary_claim_in_the_clear_or_disclosed()
    {
        var subject = new JsonObject { ["id"] = "did:example:subject", ["exp"] = 1000000000, ["nbf"] = 4102444800 };
        var issued = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("credentialSubject", subject)),
            new DisclosureFrame().DiscloseObjectProperties("credentialSubject", "exp"),
            Issuer.Signer);
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));

        await ShouldPassOnBoth(presentation, At(Now));
        (await VerifyVc(presentation, At(Now))).DisclosedPayload!["credentialSubject"]!["exp"]!.GetValue<long>().Should().Be(1000000000);

        // A nested member that is not even a number is not a NumericDate the verifier reads.
        await ShouldPassOnBoth(await Sign(VcPayload(("credentialSubject", new JsonObject { ["exp"] = "tomorrow" }))), At(Now));
    }

    [Fact]
    public async Task An_SD_JWT_VC_whose_top_level_exp_a_Disclosure_supplies_is_refused_whatever_its_value()
    {
        // -27 §2.2.2.3 forbids the Disclosure; the positional rule (issue #48) refuses it. A past value is refused by
        // the window first, which reads the processed payload as RFC 9901 §7.1 step 6 says; either way it fails.
        var past = Disclosure.ForObjectProperty("salt-past", "exp", JsonValue.Create(NowSeconds - 3600));
        var pastPresentation = await Sign(VcPayload(("_sd", new JsonArray((JsonNode)past.ComputeDigest(SdAlg)))), disclosures: [past]);
        var pastResult = await VerifyVc(pastPresentation, At(Now));
        ShouldFailWith(pastResult.Errors, pastResult.IsValid, "SD_JWT_EXPIRED");

        var future = Disclosure.ForObjectProperty("salt-future", "exp", JsonValue.Create(NowSeconds + 3600));
        var futurePresentation = await Sign(VcPayload(("_sd", new JsonArray((JsonNode)future.ComputeDigest(SdAlg)))), disclosures: [future]);
        var futureResult = await VerifyVc(futurePresentation, At(Now));
        ShouldFailWith(futureResult.Errors, futureResult.IsValid, "VC_DISALLOWED_DISCLOSURE");

        // A disclosed nbf that has passed cannot make anything valid either.
        var nbf = Disclosure.ForObjectProperty("salt-nbf", "nbf", JsonValue.Create(NowSeconds - 3600));
        var nbfPresentation = await Sign(VcPayload(("_sd", new JsonArray((JsonNode)nbf.ComputeDigest(SdAlg)))), disclosures: [nbf]);
        var nbfResult = await VerifyVc(nbfPresentation, At(Now));
        ShouldFailWith(nbfResult.Errors, nbfResult.IsValid, "VC_DISALLOWED_DISCLOSURE");
    }

    [Fact]
    public async Task A_Disclosure_cannot_replace_a_clear_exp()
    {
        // The signed exp has passed; a Disclosure offering a later one is a name clash (RFC 9901 §7.1 step 3.c.ii.3).
        var later = Disclosure.ForObjectProperty("salt-later", "exp", JsonValue.Create(NowSeconds + 3600));
        var presentation = await Sign(
            VcPayload(("exp", NowSeconds - 3600), ("_sd", new JsonArray((JsonNode)later.ComputeDigest(SdAlg)))), disclosures: [later]);

        await ShouldFailOnBoth(presentation, At(Now), "DISCLOSURE_INVALID");

        // Withheld, the decoy-looking digest leaves the signed exp in charge.
        var withheld = presentation[..(presentation.IndexOf('~') + 1)];
        await ShouldFailOnBoth(withheld, At(Now), "SD_JWT_EXPIRED");
    }

    [Fact]
    public async Task A_generic_SD_JWT_checks_an_exp_the_Issuer_made_disclosable_when_it_is_disclosed()
    {
        // RFC 9901 §7.1 step 6 reads the processed payload; §9.7 says an Issuer must not do this, and a Verifier cannot
        // rely on it. Disclosed, the past exp fails; withheld, it is absent (a Verifier that needs it checks presence).
        var issued = await SdJwtIssuer.IssueAsync(
            new JsonObject { ["sub"] = "user", ["exp"] = NowSeconds - 3600 }, new DisclosureFrame().Disclose("exp"), Issuer.Signer,
            typ: "example+sd-jwt");

        var disclosed = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));
        ShouldFail(VerifyGeneric(disclosed, At(Now)), "SD_JWT_EXPIRED");

        var withheld = SdJwtHolder.CreatePresentation(issued.Issuance, []);
        var result = VerifyGeneric(withheld, At(Now));
        result.IsValid.Should().BeTrue();
        result.DisclosedPayload!.ContainsKey("exp").Should().BeFalse();
    }

    [Fact]
    public async Task Duplicate_exp_members_in_the_issuer_JWT_are_malformed()
    {
        // A parser that kept the last (or the first) member would read a different exp than another one.
        var later = NowSeconds + 3600;
        var earlier = NowSeconds - 3600;
        foreach (var payload in new[]
        {
            $$"""{"vct":"{{Vct}}","exp":{{later}},"exp":{{earlier}},"_sd_alg":"sha-256"}""",
            $$"""{"vct":"{{Vct}}","exp":{{earlier}},"exp":{{later}},"_sd_alg":"sha-256"}""",
            // The second name is "exp" spelled with an escape, built here so no tool rewrites it.
            "{\"vct\":\"" + Vct + "\",\"exp\":" + later + ",\"" + @"\u" + 0x65.ToString("X4") + "xp\":" + earlier + ",\"_sd_alg\":\"sha-256\"}",
        })
        {
            await ShouldFailOnBoth(await SignRaw(payload), At(Now), "MALFORMED");
        }

        // A single escaped name is just exp.
        var escaped = "{\"vct\":\"" + Vct + "\",\"" + @"\u" + 0x65.ToString("X4") + "xp\":" + earlier + ",\"_sd_alg\":\"sha-256\"}";
        await ShouldFailOnBoth(await SignRaw(escaped), At(Now), "SD_JWT_EXPIRED");
    }

    // ------------------------------------------------------------------ the Key Binding JWT has its own claims

    private static async Task<string> PresentWithKeyBindingPayload(string issuance, TestKeyMaterial holder, JsonObject kbPayload)
    {
        kbPayload["sd_hash"] = SdHashAlgorithm.ComputeSdHash(SdAlg, issuance);
        var kbJwt = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(kbPayload.ToJsonString()), holder.Signer, typ: "kb+jwt");
        return issuance + kbJwt;
    }

    [Fact]
    public async Task A_Key_Binding_JWT_exp_or_nbf_is_not_the_Issuers()
    {
        // The issuer JWT has expired; a Key Binding JWT that carries a later exp and an earlier nbf cannot revive it.
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var issued = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("exp", NowSeconds - 3600)), new DisclosureFrame().Disclose("given_name"), Issuer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });
        var presentation = await PresentWithKeyBindingPayload(issued.Issuance, holder, new JsonObject
        {
            ["nonce"] = Nonce, ["aud"] = Audience, ["iat"] = NowSeconds, ["exp"] = NowSeconds + 3600, ["nbf"] = NowSeconds - 60,
        });
        var options = At(Now) with { ExpectedAudience = Audience, ExpectedNonce = Nonce, RequireKeyBinding = true };

        await ShouldFailOnBoth(presentation, options, "SD_JWT_EXPIRED");

        // And a stale KB-JWT iat is the KB-JWT's own code, not the Issuer's, with the issuer JWT inside its window.
        var fresh = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("exp", NowSeconds + 3600)), new DisclosureFrame().Disclose("given_name"), Issuer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });
        var stale = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            fresh.Issuance, fresh.Disclosures.Select(d => d.Encoded), holder.Signer, Audience, Nonce, Now.AddHours(-1));
        await ShouldFailOnBoth(stale, options with { MaxKeyBindingAge = TimeSpan.FromMinutes(5) }, "KB_JWT_EXPIRED");
    }

    public static TheoryData<string, string, string?> KeyBindingWindows => new()
    {
        // KB-JWT claims (JSON members, Now = 1795089600), the code it fails with, or null when it verifies.
        { "exp", "1795086000", "KB_JWT_EXPIRED" },            // an hour ago
        { "exp", "1795089600", "KB_JWT_EXPIRED" },            // exactly now, no skew: RFC 7519 §4.1.4
        { "exp", "1795089601", null },
        { "nbf", "1795093200", "KB_JWT_NOT_YET_VALID" },      // in an hour
        { "nbf", "1795089600", null },                        // exactly now: §4.1.5 "after or equal"
        { "exp", "\"1795093200\"", "KB_JWT_EXP_INVALID" },
        { "nbf", "null", "KB_JWT_NBF_INVALID" },
        { "nbf", "1e400", "KB_JWT_NBF_INVALID" },
    };

    [Theory]
    [MemberData(nameof(KeyBindingWindows))]
    public async Task A_Key_Binding_JWTs_own_nbf_and_exp_are_judged_with_KB_JWT_codes(string claim, string json, string? code)
    {
        // RFC 9901 §7.3 step 5.h: "Check that the Key Binding JWT is a valid JWT in all other respects, per [RFC7519]".
        // The issuer JWT is inside its window, so only the KB-JWT's claim can fail.
        NowSeconds.Should().Be(1795089600);
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var issued = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("exp", NowSeconds + 3600)), new DisclosureFrame().Disclose("given_name"), Issuer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });
        var presentation = await PresentWithKeyBindingPayload(issued.Issuance, holder, new JsonObject
        {
            ["nonce"] = Nonce, ["aud"] = Audience, ["iat"] = NowSeconds, [claim] = JsonNode.Parse(json),
        });
        var options = At(Now, TimeSpan.Zero) with { ExpectedAudience = Audience, ExpectedNonce = Nonce, RequireKeyBinding = true };

        if (code is null)
            await ShouldPassOnBoth(presentation, options);
        else
            await ShouldFailOnBoth(presentation, options, code);
    }

    [Fact]
    public async Task The_window_is_checked_before_the_Key_Binding_JWT()
    {
        // RFC 9901 §7.3 step 4 processes the SD-JWT (§7.1, step 6 included) before the KB-JWT; a missing KB-JWT is not
        // what an expired credential reports.
        var presentation = await Sign(VcPayload(("exp", NowSeconds - 3600)));
        await ShouldFailOnBoth(presentation, At(Now) with { RequireKeyBinding = true }, "SD_JWT_EXPIRED");
    }

    // ------------------------------------------------------------------ issuance: the shape, not the time

    [Theory]
    [InlineData("exp", "\"2030-01-01T00:00:00Z\"")]
    [InlineData("nbf", "null")]
    [InlineData("exp", "1e400")]
    [InlineData("nbf", "[1700000000]")]
    [InlineData("exp", "253402300800")]
    public async Task The_issuers_refuse_an_nbf_or_exp_that_is_not_a_NumericDate(string claim, string json)
    {
        var code = claim == "exp" ? "SD_JWT_EXP_INVALID" : "SD_JWT_NBF_INVALID";

        var vc = async () => await SdJwtVcIssuer.IssueAsync(
            VcPayload((claim, JsonNode.Parse(json))), new DisclosureFrame().Disclose("given_name"), Issuer.Signer);
        (await vc.Should().ThrowAsync<MalformedJoseException>()).Which.Message.Should().Contain(code);

        var generic = async () => await SdJwtIssuer.IssueAsync(
            new JsonObject { ["sub"] = "user", [claim] = JsonNode.Parse(json) }, new DisclosureFrame(), Issuer.Signer);
        (await generic.Should().ThrowAsync<MalformedJoseException>()).Which.Message.Should().Contain(code);
    }

    [Fact]
    public async Task The_generic_issuer_refuses_a_disclosable_exp_that_is_not_a_NumericDate()
    {
        // Read in the processed payload, as the verifier reads it.
        var issue = async () => await SdJwtIssuer.IssueAsync(
            new JsonObject { ["sub"] = "user", ["exp"] = "2030-01-01" }, new DisclosureFrame().Disclose("exp"), Issuer.Signer);
        (await issue.Should().ThrowAsync<MalformedJoseException>()).Which.Message.Should().Contain("SD_JWT_EXP_INVALID");
    }

    [Fact]
    public async Task A_DateTimeOffset_in_the_claims_set_is_refused_because_it_serializes_as_a_string()
    {
        var claims = VcPayload(("exp", JsonValue.Create(Now.AddYears(1))));
        var issue = async () => await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame(), Issuer.Signer);
        (await issue.Should().ThrowAsync<MalformedJoseException>()).Which.Message.Should().Contain("SD_JWT_EXP_INVALID");
    }

    [Fact]
    public async Task The_issuers_sign_a_credential_valid_later_or_already_expired_and_the_verifier_judges_it()
    {
        // The time is not judged at issuance: an Issuer may sign a credential that becomes valid tomorrow.
        var later = await SdJwtVcIssuer.IssueAsync(
            VcPayload(("nbf", NowSeconds + 86400), ("exp", NowSeconds + 2 * 86400)), new DisclosureFrame(), Issuer.Signer);
        await ShouldFailOnBoth(later.Issuance, At(Now), "SD_JWT_NOT_YET_VALID");
        await ShouldPassOnBoth(later.Issuance, At(Now.AddDays(1.5)));
        await ShouldFailOnBoth(later.Issuance, At(Now.AddDays(3)), "SD_JWT_EXPIRED");

        var expired = await SdJwtIssuer.IssueAsync(
            new JsonObject { ["sub"] = "user", ["exp"] = 1000000000 }, new DisclosureFrame(), Issuer.Signer);
        ShouldFail(VerifyGeneric(expired.Issuance, At(Now)), "SD_JWT_EXPIRED");
    }
}
