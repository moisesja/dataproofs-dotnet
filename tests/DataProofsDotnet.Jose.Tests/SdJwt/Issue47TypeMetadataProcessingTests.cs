using System.Diagnostics;
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
/// Issue #47: SD-JWT VC Type Metadata is processed, not only retrieved (draft-ietf-oauth-sd-jwt-vc-27 §5, §6, §7.4).
/// With processing enabled (<see cref="SdJwtVcVerifier.VerifyWithTypeMetadataAsync"/>,
/// <see cref="SdJwtVcIssuer.IssueWithTypeMetadataAsync"/>): integrity, <c>vct</c> identity, <c>extends</c> cycles and
/// depth, and <c>mandatory</c> / <c>sd</c> fail with stable codes; issuance is checked by the same code; the processed
/// metadata is on the result; a resolver fault is told apart from a verdict. With it off,
/// <see cref="SdJwtVcVerifier.VerifyAsync"/> behaves as before, which is what each "processing off" test pins: on
/// 2.0.0 every credential below that processing refuses verifies.
/// </summary>
public sealed class Issue47TypeMetadataProcessingTests
{
    private const string SdAlg = "sha-256";
    private const string Vct = "https://example.com/vc/simple";
    private const string EducationVct = "https://betelgeuse.example.com/education_credential/v42";

    private static readonly TestKeyMaterial Issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

    // ------------------------------------------------------------------ helpers

    private static byte[] Bytes(JsonObject document) => Encoding.UTF8.GetBytes(document.ToJsonString());

    private static TypeMetadataProcessingOptions Options(params (string Reference, byte[] Octets)[] documents)
        => new(new LocalCacheTypeMetadataDocumentResolver(documents.ToDictionary(d => d.Reference, d => d.Octets)));

    private static Task<SdJwtVcVerificationResult> Verify(string presentation, TypeMetadataProcessingOptions options)
        => SdJwtVcVerifier.VerifyWithTypeMetadataAsync(presentation, _ => Issuer.PublicJwk, options);

    private static Task<SdJwtVcVerificationResult> VerifyUnprocessed(string presentation)
        => SdJwtVcVerifier.VerifyAsync(presentation, _ => Issuer.PublicJwk);

    /// <summary>Signs <paramref name="payload"/> as a <c>dc+sd-jwt</c> issuer JWT and appends <paramref name="disclosures"/>.</summary>
    private static async Task<string> Sign(JsonObject payload, params Disclosure[] disclosures)
    {
        payload["_sd_alg"] = SdAlg;
        var jwt = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(payload.ToJsonString()), Issuer.Signer, typ: "dc+sd-jwt");
        return jwt + "~" + string.Concat(disclosures.Select(d => d.Encoded + "~"));
    }

    private static JsonArray Sd(params Disclosure[] disclosures)
    {
        var sd = new JsonArray();
        foreach (var disclosure in disclosures)
            sd.Add((JsonNode)disclosure.ComputeDigest(SdAlg));
        return sd;
    }

    private static JsonObject Placeholder(Disclosure disclosure) => new() { ["..."] = disclosure.ComputeDigest(SdAlg) };

    private static Disclosure Member(string name, JsonNode? value) => Disclosure.ForObjectProperty("salt-" + name, name, value);

    private static JsonObject SimpleDocument(JsonArray? claims = null, string vct = Vct, string? extends = null)
    {
        var document = new JsonObject { ["vct"] = vct, ["name"] = "Simple" };
        if (extends is not null)
            document["extends"] = extends;
        if (claims is not null)
            document["claims"] = claims;
        return document;
    }

    private static JsonObject ClaimEntry(JsonArray path, string? sd = null, bool? mandatory = null)
    {
        var entry = new JsonObject { ["path"] = path };
        if (sd is not null)
            entry["sd"] = sd;
        if (mandatory is not null)
            entry["mandatory"] = mandatory.Value;
        return entry;
    }

    private static JsonArray Path(params object?[] components)
    {
        var path = new JsonArray();
        foreach (var component in components)
            path.Add(component switch { string s => (JsonNode)s, int i => (JsonNode)i, _ => null });
        return path;
    }

    private static void ShouldFail(SdJwtVcVerificationResult result, string code)
    {
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith(code + ":");
        result.TypeMetadataResolverFault.Should().BeNull("a verdict is not a resolver fault");
        result.ProcessedTypeMetadata.Should().BeNull();
    }

    private static void ShouldPass(SdJwtVcVerificationResult result)
    {
        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.ProcessedTypeMetadata.Should().NotBeNull();
    }

    // ------------------------------------------------------------------ integrity (§6)

    /// <summary>Figure 17 as printed, indent removed, LF line ends, trailing LF: Figure 16's vct#integrity hashes these octets.</summary>
    private static byte[] Figure17() => Encoding.UTF8.GetBytes(
        "{\n"
        + "  \"vct\":\"https://betelgeuse.example.com/education_credential/v42\",\n"
        + "  \"name\":\"Betelgeuse Education Credential - Version 42\",\n"
        + "  \"description\":\"This is our education credential. Don't panic.\",\n"
        + "  \"extends\":\"https://galaxy.example.com/galactic-education-credential/v2\",\n"
        + "  \"extends#integrity\":\n"
        + "    \"sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=\"\n"
        + "}\n");

    private static string Figure16Integrity()
    {
        using var fixture = SdJwtFixtureSupport.Load("sd-jwt-vc-27", "type-metadata-example.json");
        return fixture.RootElement.GetProperty("sd_jwt_vc_payload_excerpt").GetProperty("vct#integrity").GetString()!;
    }

    [Fact]
    public void Figure_16_integrity_matches_the_Figure_17_octets_and_nothing_else()
    {
        var octets = Figure17();
        TypeMetadataIntegrity.Matches(Figure16Integrity(), octets).Should().BeTrue();
        TypeMetadataIntegrity.Compute(octets).Should().Be(Figure16Integrity());

        octets[^2] = (byte)' '; // the same JSON, different octets
        TypeMetadataIntegrity.Matches(Figure16Integrity(), octets).Should().BeFalse();
    }

    private static readonly byte[] Document = Encoding.UTF8.GetBytes("{\"vct\":\"x\"}");

    private static string Expression(string algorithm, byte[] document) => TypeMetadataIntegrity.Compute(document, algorithm);

    private static string Wrong(string algorithm) => Expression(algorithm, Encoding.UTF8.GetBytes("other"));

    [Fact]
    public void Only_the_strongest_supported_algorithm_counts_and_any_of_its_expressions_may_match()
    {
        TypeMetadataIntegrity.Matches($"{Expression("sha256", Document)} {Wrong("sha512")}", Document).Should().BeFalse();
        TypeMetadataIntegrity.Matches($"{Wrong("sha256")} {Expression("sha512", Document)}", Document).Should().BeTrue();
        TypeMetadataIntegrity.Matches($"{Wrong("sha384")} {Expression("sha384", Document)}", Document).Should().BeTrue();
        TypeMetadataIntegrity.Matches($"{Expression("sha256", Document)}\t{Wrong("sha384")}", Document).Should().BeFalse();
        TypeMetadataIntegrity.Matches($" {Expression("sha384", Document)}\n", Document).Should().BeTrue();
    }

    public static TheoryData<string> Unsupported => new()
    {
        "md5-1B2M2Y8AsgTpgAmY7PhCfg==",
        "sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
        "sha3-256-p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=",
    };

    [Theory]
    [MemberData(nameof(Unsupported))]
    public void An_unsupported_algorithm_alone_fails_and_beside_a_supported_one_is_ignored(string unsupported)
    {
        TypeMetadataIntegrity.Matches(unsupported, Document).Should().BeFalse();
        TypeMetadataIntegrity.Matches($"{unsupported} {Expression("sha256", Document)}", Document).Should().BeTrue();
    }

    public static TheoryData<string> Malformed => new()
    {
        "",
        "   ",
        "sha256",
        "sha256-",
        "-abc",
        "sha256-not_base64url-",
        "sha256-AAAA", // a supported algorithm with a digest of the wrong length
        "sha256-" + new string('A', 43) + "===",
        "sha256-" + Convert.ToBase64String(new byte[32]) + " garbage",
        "sha 256-" + Convert.ToBase64String(new byte[32]),
    };

    [Theory]
    [MemberData(nameof(Malformed))]
    public void A_malformed_value_fails(string value)
        => TypeMetadataIntegrity.Matches(value, Document).Should().BeFalse();

    [Fact]
    public void Options_are_ignored_algorithm_names_are_case_insensitive_and_padding_is_optional()
    {
        var good = Expression("sha256", Document);
        TypeMetadataIntegrity.Matches(good + "?ct=application/json", Document).Should().BeTrue();
        TypeMetadataIntegrity.Matches("SHA256" + good["sha256".Length..], Document).Should().BeTrue();
        TypeMetadataIntegrity.Matches(good.TrimEnd('='), Document).Should().BeTrue();
    }

    [Fact]
    public void Compute_names_one_of_the_three_algorithms_exactly()
    {
        TypeMetadataIntegrity.Compute(Document, TypeMetadataIntegrity.Sha384).Should().StartWith("sha384-");
        TypeMetadataIntegrity.Compute(Document, TypeMetadataIntegrity.Sha512).Should().StartWith("sha512-");
        var act = () => TypeMetadataIntegrity.Compute(Document, "md5");
        act.Should().Throw<ArgumentException>();
        var upper = () => TypeMetadataIntegrity.Compute(Document, "SHA256");
        upper.Should().Throw<ArgumentException>();
    }

    // ------------------------------------------------------------------ the A.2 document end to end

    /// <summary>Figure 30 without its <c>extends</c> (the draft does not print the parent, so its integrity cannot match).</summary>
    private static JsonObject EducationDocument()
    {
        using var fixture = SdJwtFixtureSupport.Load("sd-jwt-vc-27", "appendix-a2-type-metadata.json");
        var document = SdJwtFixtureSupport.ToJsonObject(fixture.RootElement.GetProperty("type_metadata_document"));
        document.Remove("extends");
        document.Remove("extends#integrity");
        return document;
    }

    private sealed record Credential(JsonObject Payload, Disclosure Name, Disclosure Address, Disclosure Street, Disclosure[] Degrees, Disclosure[] Dates)
    {
        public Disclosure[] All => [Name, Street, Address, .. Dates, .. Degrees];
    }

    /// <summary>
    /// The Figure 29 credential issued as Figure 30's claim metadata asks: <c>name</c>, <c>address</c> and
    /// <c>address.street_address</c> disclosable; <c>degrees</c> in the clear with every element disclosable; in each
    /// element <c>field_of_study</c> in the clear and <c>date_awarded</c> disclosable.
    /// </summary>
    private static Credential Education(byte[] metadata)
    {
        var name = Member("name", "Zaphod Beeblebrox");
        var street = Member("street_address", "42 Galaxy Way");
        var address = Member("address", new JsonObject
        {
            ["city"] = "Betelgeuse City",
            ["postal_code"] = "12345",
            ["country"] = "Betelgeuse",
            ["_sd"] = Sd(street),
        });

        (string Field, string Date)[] rows = [("Intergalactic Politics", "2020-05-15"), ("Space Navigation", "2018-06-20"), ("Quantum Mechanics", "2016-07-25")];
        var dates = rows.Select((r, i) => Disclosure.ForObjectProperty("salt-date-" + i, "date_awarded", r.Date)).ToArray();
        var degrees = rows.Select((r, i) => Disclosure.ForArrayElement(
            "salt-degree-" + i, new JsonObject { ["field_of_study"] = r.Field, ["_sd"] = Sd(dates[i]) })).ToArray();
        var degreeArray = new JsonArray();
        foreach (var degree in degrees)
            degreeArray.Add((JsonNode)Placeholder(degree));

        var payload = new JsonObject
        {
            ["vct"] = EducationVct,
            ["vct#integrity"] = TypeMetadataIntegrity.Compute(metadata),
            ["_sd"] = Sd(name, address),
            ["degrees"] = degreeArray,
        };
        return new Credential(payload, name, address, street, degrees, dates);
    }

    [Fact]
    public async Task The_A2_credential_verifies_and_the_processed_metadata_is_typed()
    {
        var metadata = Bytes(EducationDocument());
        var credential = Education(metadata);
        var presentation = await Sign(credential.Payload, credential.All);

        var result = await Verify(presentation, Options((EducationVct, metadata)));

        ShouldPass(result);
        var processed = result.ProcessedTypeMetadata!;
        processed.Vct.Should().Be(EducationVct);
        processed.Name.Should().Be("Betelgeuse Education Credential - Version 42");
        processed.Description.Should().Be("This is our education credential. Don't panic.");
        processed.Documents.Should().ContainSingle();
        SdJwtFixtureSupport.JsonEquivalent(result.TypeMetadata, EducationDocument()).Should().BeTrue("the raw member keeps the vct's document");

        processed.Display.Select(d => d.Locale).Should().Equal("en-US", "de-DE");
        var english = processed.Display[0];
        english.Name.Should().Be("Betelgeuse Education Credential");
        english.Description.Should().Be("Education credential for all carbon-based life forms on Betelgeuse.");
        english.Dir.Should().BeNull();
        var simple = english.Rendering!.Simple!;
        simple.Logo!.Uri.Should().Be("https://betelgeuse.example.com/public/education-logo.png");
        simple.Logo.UriIntegrity.Should().Be("sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=");
        simple.Logo.AltText.Should().Be("Betelgeuse Ministry of Education logo");
        simple.BackgroundImage!.Uri.Should().Be("https://betelgeuse.example.com/public/cred-background.png");
        simple.BackgroundImage.AltText.Should().BeNull();
        simple.BackgroundColor.Should().Be("#12107c");
        simple.TextColor.Should().Be("#FFFFFF");
        var svg = english.Rendering.SvgTemplates.Should().ContainSingle().Subject;
        svg.Uri.Should().Be("https://betelgeuse.example.com/public/credential-english.svg");
        svg.UriIntegrity.Should().StartWith("sha256-");
        (svg.Orientation, svg.ColorScheme, svg.Contrast).Should().Be(("landscape", "light", "high"));

        processed.Claims.Should().HaveCount(7);
        var nameClaim = processed.Claims[0];
        nameClaim.Path.Should().ContainSingle().Which.Key.Should().Be("name");
        (nameClaim.Mandatory, nameClaim.SelectiveDisclosure).Should().Be((true, ClaimSelectiveDisclosure.Always));
        nameClaim.Display.Select(d => (d.Locale, d.Label)).Should().Equal(("de-DE", "Vor- und Nachname"), ("en-US", "Name"));
        nameClaim.Display[1].Description.Should().Be("The name of the student");
        nameClaim.Display[1].Dir.Should().BeNull();
        processed.Claims[2].SvgId.Should().Be("address_street_address");
        var allDegrees = processed.Claims[4];
        allDegrees.Path[1].IsAllElements.Should().BeTrue();
        allDegrees.Path[1].Key.Should().BeNull();
        allDegrees.Path[1].Index.Should().BeNull();
        allDegrees.SelectiveDisclosure.Should().Be(ClaimSelectiveDisclosure.Always);
        processed.Claims[3].SelectiveDisclosure.Should().Be(ClaimSelectiveDisclosure.Never);
        processed.Claims[3].Mandatory.Should().BeFalse();
    }

    [Fact]
    public async Task Withholding_a_mandatory_disclosable_claim_or_a_disclosable_element_still_verifies()
    {
        var metadata = Bytes(EducationDocument());
        var credential = Education(metadata);

        // name is mandatory and sd: always; withheld, it may well have been issued (§5.6 MUST NOT treat it as missing).
        var withheld = await Sign(credential.Payload, [credential.Street, credential.Address, .. credential.Dates, .. credential.Degrees]);
        ShouldPass(await Verify(withheld, Options((EducationVct, metadata))));

        // An undisclosed degrees element is included and selectively disclosable, as sd: always asks.
        var someDegrees = await Sign(credential.Payload, credential.Name, credential.Degrees[0], credential.Dates[0]);
        ShouldPass(await Verify(someDegrees, Options((EducationVct, metadata))));
    }

    [Fact]
    public async Task An_sd_always_claim_in_the_clear_fails_whether_other_Disclosures_are_attached_or_withheld()
    {
        var metadata = Bytes(EducationDocument());
        var credential = Education(metadata);
        credential.Payload["_sd"] = Sd(credential.Address);
        credential.Payload["name"] = "Zaphod Beeblebrox";

        var attached = await Sign(credential.Payload, [credential.Street, credential.Address, .. credential.Dates, .. credential.Degrees]);
        ShouldFail(await Verify(attached, Options((EducationVct, metadata))), "VC_CLAIM_SD_VIOLATION");
        var withheld = await Sign(credential.Payload);
        ShouldFail(await Verify(withheld, Options((EducationVct, metadata))), "VC_CLAIM_SD_VIOLATION");

        (await VerifyUnprocessed(withheld)).IsValid.Should().BeTrue("processing off: unchanged");
    }

    [Fact]
    public async Task An_sd_never_claim_presented_as_a_Disclosure_fails()
    {
        // degrees[*].field_of_study is sd: never; make it a Disclosure inside the first element.
        var metadata = Bytes(EducationDocument());
        var credential = Education(metadata);
        var field = Member("field_of_study", "Intergalactic Politics");
        var degree = Disclosure.ForArrayElement("salt-degree-x", new JsonObject { ["_sd"] = Sd(field, credential.Dates[0]) });
        credential.Payload["degrees"] = new JsonArray(Placeholder(degree));

        var presentation = await Sign(credential.Payload, credential.Name, credential.Street, credential.Address, degree, field, credential.Dates[0]);
        ShouldFail(await Verify(presentation, Options((EducationVct, metadata))), "VC_CLAIM_SD_VIOLATION");
        (await VerifyUnprocessed(presentation)).IsValid.Should().BeTrue("processing off: unchanged");
    }

    [Fact]
    public async Task An_sd_never_array_element_fails_whether_its_Disclosure_is_attached_or_withheld()
    {
        var document = SimpleDocument(new JsonArray(ClaimEntry(Path("nationalities", null), sd: "never")));
        var element = Disclosure.ForArrayElement("salt-n", "Betelgeusian");
        var payload = new JsonObject { ["vct"] = Vct, ["nationalities"] = new JsonArray("British", Placeholder(element)) };

        ShouldFail(await Verify(await Sign(payload.DeepClone().AsObject(), element), Options((Vct, Bytes(document)))), "VC_CLAIM_SD_VIOLATION");
        ShouldFail(await Verify(await Sign(payload.DeepClone().AsObject()), Options((Vct, Bytes(document)))), "VC_CLAIM_SD_VIOLATION");
    }

    [Fact]
    public async Task A_withheld_sd_never_member_cannot_be_told_from_a_decoy_unless_it_is_mandatory()
    {
        var hidden = Member("given_name", "Arthur");
        var payload = new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(hidden) };

        var optional = SimpleDocument(new JsonArray(ClaimEntry(Path("given_name"), sd: "never")));
        ShouldPass(await Verify(await Sign(payload.DeepClone().AsObject()), Options((Vct, Bytes(optional)))));
        ShouldFail(await Verify(await Sign(payload.DeepClone().AsObject(), hidden), Options((Vct, Bytes(optional)))), "VC_CLAIM_SD_VIOLATION");

        // Mandatory and never: absent from the clear is a violation either way (not issued, or issued as a Disclosure).
        var mandatory = SimpleDocument(new JsonArray(ClaimEntry(Path("given_name"), sd: "never", mandatory: true)));
        ShouldFail(await Verify(await Sign(payload.DeepClone().AsObject()), Options((Vct, Bytes(mandatory)))), "VC_CLAIM_MANDATORY_MISSING");
    }

    // ------------------------------------------------------------------ mandatory (§5.6, §5.6.3)

    [Fact]
    public async Task A_mandatory_claim_never_set_fails_and_one_withheld_verifies()
    {
        var document = SimpleDocument(new JsonArray(ClaimEntry(Path("given_name"), mandatory: true)));
        var options = Options((Vct, Bytes(document)));

        var neverSet = await Sign(new JsonObject { ["vct"] = Vct, ["family_name"] = "Dent" });
        ShouldFail(await Verify(neverSet, options), "VC_CLAIM_MANDATORY_MISSING");
        (await VerifyUnprocessed(neverSet)).IsValid.Should().BeTrue("processing off: unchanged");

        var given = Member("given_name", "Arthur");
        var withheld = await Sign(new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(given) });
        ShouldPass(await Verify(withheld, options));

        // An empty _sd array hides nothing (RFC 9901 §4.2.4.1).
        var emptySd = await Sign(new JsonObject { ["vct"] = Vct, ["_sd"] = new JsonArray() });
        ShouldFail(await Verify(emptySd, options), "VC_CLAIM_MANDATORY_MISSING");
    }

    [Fact]
    public async Task A_mandatory_nested_claim_is_judged_where_it_would_be()
    {
        var document = SimpleDocument(new JsonArray(ClaimEntry(Path("address", "city"), mandatory: true)));
        var options = Options((Vct, Bytes(document)));

        ShouldFail(await Verify(await Sign(new JsonObject { ["vct"] = Vct, ["address"] = new JsonObject { ["street"] = "x" } }), options),
            "VC_CLAIM_MANDATORY_MISSING");
        ShouldFail(await Verify(await Sign(new JsonObject { ["vct"] = Vct }), options), "VC_CLAIM_MANDATORY_MISSING");

        // The whole address withheld: its contents are unknown, so nothing is determined.
        var address = Member("address", new JsonObject { ["city"] = "Milliways" });
        ShouldPass(await Verify(await Sign(new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(address) }), options));
        ShouldPass(await Verify(await Sign(new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(address) }, address), options));
    }

    [Fact]
    public async Task Array_indices_count_undisclosed_elements()
    {
        var hidden = Disclosure.ForArrayElement("salt-h", "Betelgeusian");
        var payload = new JsonObject { ["vct"] = Vct, ["nationalities"] = new JsonArray("British", Placeholder(hidden)) };

        // Index 1 is the undisclosed element: included, and selectively disclosable.
        var second = SimpleDocument(new JsonArray(ClaimEntry(Path("nationalities", 1), sd: "always", mandatory: true)));
        ShouldPass(await Verify(await Sign(payload.DeepClone().AsObject()), Options((Vct, Bytes(second)))));

        var third = SimpleDocument(new JsonArray(ClaimEntry(Path("nationalities", 2), mandatory: true)));
        ShouldFail(await Verify(await Sign(payload.DeepClone().AsObject(), hidden), Options((Vct, Bytes(third)))), "VC_CLAIM_MANDATORY_MISSING");

        // A null over an empty array selects nothing and is no violation (§5.6.1.2).
        var all = SimpleDocument(new JsonArray(ClaimEntry(Path("tags", null), sd: "always", mandatory: true)));
        ShouldPass(await Verify(await Sign(new JsonObject { ["vct"] = Vct, ["tags"] = new JsonArray() }), Options((Vct, Bytes(all)))));
    }

    [Fact]
    public async Task Paths_through_the_wrong_type_fail()
    {
        var payload = new JsonObject { ["vct"] = Vct, ["name"] = "Arthur", ["list"] = new JsonArray(1), ["nothing"] = null };
        foreach (var path in new[] { Path("name", "first"), Path("name", null), Path("name", 0), Path("list", "x"), Path("nothing", "x") })
        {
            var document = SimpleDocument(new JsonArray(ClaimEntry(path)));
            ShouldFail(await Verify(await Sign(payload.DeepClone().AsObject()), Options((Vct, Bytes(document)))), "VC_CLAIM_PATH_INVALID");
        }

        // A path that selects nothing is no error.
        var absent = SimpleDocument(new JsonArray(ClaimEntry(Path("missing", "x"))));
        ShouldPass(await Verify(await Sign(payload.DeepClone().AsObject()), Options((Vct, Bytes(absent)))));
    }

    // ------------------------------------------------------------------ vct identity, integrity, chain

    private static async Task<string> SimpleCredential(string? vctIntegrity = null, string vct = Vct)
    {
        var payload = new JsonObject { ["vct"] = vct, ["given_name"] = "Arthur" };
        if (vctIntegrity is not null)
            payload["vct#integrity"] = vctIntegrity;
        return await Sign(payload);
    }

    public static TheoryData<string> VctVariants => new()
    {
        "HTTPS://example.com/vc/simple",
        "https://EXAMPLE.com/vc/simple",
        "https://example.com/vc/simple/",
        "https://example.com/vc/%73imple",
        "https://example.com/vc/other",
    };

    [Theory]
    [MemberData(nameof(VctVariants))]
    public async Task A_document_for_another_vct_fails_with_no_normalization(string documentVct)
    {
        var presentation = await SimpleCredential();
        ShouldFail(await Verify(presentation, Options((Vct, Bytes(SimpleDocument(vct: documentVct))))), "VC_TYPE_METADATA_VCT_MISMATCH");
        (await VerifyUnprocessed(presentation)).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task The_vct_integrity_is_checked_against_the_octets_retrieved()
    {
        var octets = Bytes(SimpleDocument());
        ShouldPass(await Verify(await SimpleCredential(TypeMetadataIntegrity.Compute(octets)), Options((Vct, octets))));

        var reformatted = Encoding.UTF8.GetBytes(SimpleDocument().ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        var mismatch = await SimpleCredential(TypeMetadataIntegrity.Compute(octets));
        ShouldFail(await Verify(mismatch, Options((Vct, reformatted))), "VC_TYPE_METADATA_INTEGRITY_MISMATCH");
        (await VerifyUnprocessed(mismatch)).IsValid.Should().BeTrue("processing off: unchanged");

        ShouldFail(await Verify(await SimpleCredential("md5-1B2M2Y8AsgTpgAmY7PhCfg=="), Options((Vct, octets))), "VC_TYPE_METADATA_INTEGRITY_INVALID");
        ShouldFail(await Verify(await SimpleCredential("not integrity"), Options((Vct, octets))), "VC_TYPE_METADATA_INTEGRITY_INVALID");
        ShouldFail(await Verify(await SimpleCredential($"{TypeMetadataIntegrity.Compute(octets)} {Wrong("sha512")}"), Options((Vct, octets))),
            "VC_TYPE_METADATA_INTEGRITY_MISMATCH");

        var numeric = new JsonObject { ["vct"] = Vct, ["vct#integrity"] = 5 };
        ShouldFail(await Verify(await Sign(numeric), Options((Vct, octets))), "VC_TYPE_METADATA_INTEGRITY_INVALID");
    }

    [Fact]
    public async Task Figure_17_verifies_against_Figure_16_and_then_its_parent_must_match_extends_integrity()
    {
        const string parent = "https://galaxy.example.com/galactic-education-credential/v2";
        var presentation = await SimpleCredential(Figure16Integrity(), EducationVct);
        var parentDocument = Bytes(SimpleDocument(vct: parent));

        // The leaf's integrity holds (a real -27 vector); the parent's cannot, and must not be skipped.
        ShouldFail(await Verify(presentation, Options((EducationVct, Figure17()), (parent, parentDocument))), "VC_TYPE_METADATA_INTEGRITY_MISMATCH");
        ShouldFail(await Verify(presentation, Options((EducationVct, Figure17()))), "VC_TYPE_METADATA_UNAVAILABLE");
    }

    [Fact]
    public async Task Extends_integrity_is_checked_on_every_parent()
    {
        var root = Bytes(SimpleDocument(vct: "urn:root"));
        var middle = SimpleDocument(vct: "urn:middle", extends: "urn:root");
        middle["extends#integrity"] = TypeMetadataIntegrity.Compute(root);
        var leaf = SimpleDocument(extends: "urn:middle");
        leaf["extends#integrity"] = TypeMetadataIntegrity.Compute(Bytes(middle));
        var presentation = await SimpleCredential();

        ShouldPass(await Verify(presentation, Options((Vct, Bytes(leaf)), ("urn:middle", Bytes(middle)), ("urn:root", root))));
        ShouldFail(await Verify(presentation, Options((Vct, Bytes(leaf)), ("urn:middle", Bytes(middle)), ("urn:root", Bytes(SimpleDocument(vct: "urn:root", claims: new JsonArray()))))),
            "VC_TYPE_METADATA_INTEGRITY_MISMATCH");

        middle["extends#integrity"] = 7;
        leaf["extends#integrity"] = TypeMetadataIntegrity.Compute(Bytes(middle));
        ShouldFail(await Verify(presentation, Options((Vct, Bytes(leaf)), ("urn:middle", Bytes(middle)), ("urn:root", root))),
            "VC_TYPE_METADATA_INTEGRITY_INVALID");
    }

    [Fact]
    public async Task Extends_cycles_fail()
    {
        var presentation = await SimpleCredential();

        ShouldFail(await Verify(presentation, Options((Vct, Bytes(SimpleDocument(extends: Vct))))), "VC_TYPE_METADATA_EXTENDS_CYCLE");
        ShouldFail(await Verify(presentation, Options(
            (Vct, Bytes(SimpleDocument(extends: "urn:b"))),
            ("urn:b", Bytes(SimpleDocument(vct: "urn:b", extends: Vct))))), "VC_TYPE_METADATA_EXTENDS_CYCLE");

        var chain = new List<(string, byte[])> { (Vct, Bytes(SimpleDocument(extends: "urn:t1"))) };
        for (var i = 1; i <= 5; i++)
            chain.Add(($"urn:t{i}", Bytes(SimpleDocument(vct: $"urn:t{i}", extends: i == 5 ? "urn:t2" : $"urn:t{i + 1}"))));
        ShouldFail(await Verify(presentation, Options([.. chain])), "VC_TYPE_METADATA_EXTENDS_CYCLE");
    }

    private static TypeMetadataProcessingOptions Chain(int hops, int? maxDepth = null)
    {
        var documents = new Dictionary<string, byte[]> { [Vct] = Bytes(SimpleDocument(extends: hops > 0 ? "urn:p1" : null)) };
        for (var i = 1; i <= hops; i++)
            documents[$"urn:p{i}"] = Bytes(SimpleDocument(vct: $"urn:p{i}", extends: i < hops ? $"urn:p{i + 1}" : null));
        var options = new TypeMetadataProcessingOptions(new LocalCacheTypeMetadataDocumentResolver(documents));
        return maxDepth is { } depth ? new TypeMetadataProcessingOptions(options.Resolver) { MaxExtendsDepth = depth } : options;
    }

    [Fact]
    public async Task An_over_deep_chain_fails()
    {
        var presentation = await SimpleCredential();
        ShouldPass(await Verify(presentation, Chain(TypeMetadataProcessingOptions.DefaultMaxExtendsDepth)));
        ShouldFail(await Verify(presentation, Chain(TypeMetadataProcessingOptions.DefaultMaxExtendsDepth + 1)), "VC_TYPE_METADATA_EXTENDS_DEPTH");
        ShouldPass(await Verify(presentation, Chain(0, maxDepth: 0)));
        ShouldFail(await Verify(presentation, Chain(1, maxDepth: 0)), "VC_TYPE_METADATA_EXTENDS_DEPTH");
        ShouldPass(await Verify(presentation, Chain(20, maxDepth: 20)));

        var negative = () => new TypeMetadataProcessingOptions(new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]>())) { MaxExtendsDepth = -1 };
        negative.Should().Throw<ArgumentOutOfRangeException>();
    }

    // ------------------------------------------------------------------ merging (§5.5.2, §5.6.5)

    [Fact]
    public async Task Figures_20_to_22_merge_claim_metadata_by_path_and_the_child_display_replaces_the_parent()
    {
        static JsonArray Display(string label) => new(new JsonObject { ["label"] = label, ["locale"] = "en" });
        var baseType = new JsonObject
        {
            ["vct"] = "https://example.com/base-type-metadata",
            ["display"] = new JsonArray(new JsonObject { ["locale"] = "en", ["name"] = "Base" }, new JsonObject { ["locale"] = "de", ["name"] = "Basis" }),
            ["claims"] = new JsonArray(
                new JsonObject { ["path"] = Path("name"), ["display"] = Display("Full Name") },
                new JsonObject { ["path"] = Path("address", "city"), ["display"] = Display("City"), ["mandatory"] = true }),
        };
        var custom = new JsonObject
        {
            ["vct"] = Vct,
            ["extends"] = "https://example.com/base-type-metadata",
            ["claims"] = new JsonArray(
                new JsonObject { ["path"] = Path("address", "city"), ["display"] = Display("Town") },
                new JsonObject { ["path"] = Path("nationalities"), ["display"] = Display("Nationalities") }),
        };
        var options = Options((Vct, Bytes(custom)), ("https://example.com/base-type-metadata", Bytes(baseType)));
        var presentation = await Sign(new JsonObject { ["vct"] = Vct, ["address"] = new JsonObject { ["city"] = "Milliways" } });

        var result = await Verify(presentation, options);

        ShouldPass(result);
        var claims = result.ProcessedTypeMetadata!.Claims;
        claims.Select(c => (ClaimPathKeys(c), c.Display.Single().Label)).Should().Equal(
            ("name", "Full Name"), ("address.city", "Town"), ("nationalities", "Nationalities"));
        claims[1].Mandatory.Should().BeTrue("the child's entry is combined with the parent's, not replacing it");
        result.ProcessedTypeMetadata.Display.Select(d => d.Name).Should().Equal("Base", "Basis");
        result.ProcessedTypeMetadata.Documents.Select(d => d["vct"]!.GetValue<string>()).Should().Equal(Vct, "https://example.com/base-type-metadata");

        custom["display"] = new JsonArray(new JsonObject { ["locale"] = "en", ["name"] = "Custom" });
        var replaced = await Verify(presentation, Options((Vct, Bytes(custom)), ("https://example.com/base-type-metadata", Bytes(baseType))));
        replaced.ProcessedTypeMetadata!.Display.Select(d => d.Name).Should().Equal("Custom");

        // The merged mandatory still binds: a credential without address.city fails.
        var withoutCity = await Sign(new JsonObject { ["vct"] = Vct, ["address"] = new JsonObject() });
        ShouldFail(await Verify(withoutCity, Options((Vct, Bytes(custom)), ("https://example.com/base-type-metadata", Bytes(baseType)))),
            "VC_CLAIM_MANDATORY_MISSING");
    }

    private static string ClaimPathKeys(ClaimMetadata claim) => string.Join(".", claim.Path.Select(c => c.Key));

    public static TheoryData<string?, bool?, string?, bool?, bool> Overrides => new()
    {
        // parent sd, parent mandatory, child sd, child mandatory, allowed
        { "always", null, "never", null, false },
        { "always", null, "allowed", null, false },
        { "never", null, "always", null, false },
        { "never", null, "allowed", null, false },
        { "always", null, "always", null, true },
        { "allowed", null, "always", null, true },
        { null, null, "never", null, true },
        { "always", null, null, null, true },
        { null, true, null, false, false },
        { null, true, null, true, true },
        { null, false, null, true, true },
        { null, null, null, true, true },
    };

    [Theory]
    [MemberData(nameof(Overrides))]
    public async Task An_extending_type_may_only_tighten_sd_and_mandatory(string? parentSd, bool? parentMandatory, string? childSd, bool? childMandatory, bool allowed)
    {
        var parent = SimpleDocument(new JsonArray(ClaimEntry(Path("given_name"), parentSd, parentMandatory)), vct: "urn:parent");
        var child = SimpleDocument(new JsonArray(ClaimEntry(Path("given_name"), childSd, childMandatory)), extends: "urn:parent");
        var given = Member("given_name", "Arthur");
        var presentation = await Sign(new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(given) }, given);

        var result = await Verify(presentation, Options((Vct, Bytes(child)), ("urn:parent", Bytes(parent))));

        if (!allowed)
        {
            ShouldFail(result, "VC_CLAIM_METADATA_OVERRIDE_INVALID");
            return;
        }

        var effectiveSd = childSd ?? parentSd;
        if (effectiveSd == "never")
        {
            ShouldFail(result, "VC_CLAIM_SD_VIOLATION"); // the tightened rule is enforced on the merged metadata
            return;
        }
        ShouldPass(result);
        var claim = result.ProcessedTypeMetadata!.Claims.Single();
        claim.Mandatory.Should().Be(childMandatory ?? parentMandatory ?? false);
        claim.SelectiveDisclosure.Should().Be(effectiveSd switch
        {
            "always" => ClaimSelectiveDisclosure.Always,
            "never" => ClaimSelectiveDisclosure.Never,
            _ => ClaimSelectiveDisclosure.Allowed,
        });
    }

    // ------------------------------------------------------------------ malformed metadata

    public static TheoryData<string> InvalidClaims => new()
    {
        "\"claims\": {}",
        "\"claims\": [1]",
        "\"claims\": [{}]",
        "\"claims\": [{\"path\": []}]",
        "\"claims\": [{\"path\": \"name\"}]",
        "\"claims\": [{\"path\": [true]}]",
        "\"claims\": [{\"path\": [-1]}]",
        "\"claims\": [{\"path\": [1.0]}]",
        "\"claims\": [{\"path\": [1e0]}]",
        "\"claims\": [{\"path\": [{}]}]",
        "\"claims\": [{\"path\": [3000000000]}]",
        "\"claims\": [{\"path\": [\"a\"], \"mandatory\": \"true\"}]",
        "\"claims\": [{\"path\": [\"a\"], \"mandatory\": null}]",
        "\"claims\": [{\"path\": [\"a\"], \"sd\": \"ALWAYS\"}]",
        "\"claims\": [{\"path\": [\"a\"], \"sd\": true}]",
        "\"claims\": [{\"path\": [\"a\"]}, {\"path\": [\"a\"], \"sd\": \"never\"}]",
        "\"claims\": null",
    };

    [Theory]
    [MemberData(nameof(InvalidClaims))]
    public async Task Malformed_claim_metadata_fails(string member)
    {
        var document = Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", {member}}}");
        ShouldFail(await Verify(await SimpleCredential(), Options((Vct, document))), "VC_CLAIM_METADATA_INVALID");
    }

    [Fact]
    public async Task Malformed_display_and_svg_id_are_ignored_not_rejected()
    {
        var document = Encoding.UTF8.GetBytes($$$$"""
            {"vct": "{{{{Vct}}}}",
             "display": [{"locale": "en", "name": "Ok", "dir": "sideways", "rendering": {"simple": {"logo": {"uri#integrity": "x"}}, "svg_templates": [{"uri": 5}, {"uri": "https://example.com/t.svg", "properties": {"orientation": "upside-down"}}]}}, {"name": "no locale"}, 3],
             "claims": [
               {"path": ["given_name"], "display": "not an array", "svg_id": 5},
               {"path": ["a"], "svg_id": "1starts_with_digit"},
               {"path": ["b", null], "svg_id": "on_a_null_path"},
               {"path": ["c"], "svg_id": "twice"}, {"path": ["d"], "svg_id": "twice"},
               {"path": ["e"], "svg_id": "fine_1", "display": [{"locale": "en"}, {"locale": "en", "label": "E", "dir": "rtl"}]}
             ]}
            """);

        var result = await Verify(await SimpleCredential(), Options((Vct, document)));

        ShouldPass(result);
        var display = result.ProcessedTypeMetadata!.Display.Should().ContainSingle().Subject;
        display.Dir.Should().BeNull();
        display.Rendering!.Simple!.Logo.Should().BeNull();
        display.Rendering.SvgTemplates.Should().ContainSingle().Which.Orientation.Should().BeNull();
        var claims = result.ProcessedTypeMetadata.Claims;
        claims.Take(5).Should().OnlyContain(c => c.SvgId == null);
        claims[0].Display.Should().BeEmpty();
        claims[5].SvgId.Should().Be("fine_1");
        claims[5].Display.Should().ContainSingle().Which.Dir.Should().Be("rtl");
    }

    public static TheoryData<string, byte[]> InvalidDocuments()
    {
        var data = new TheoryData<string, byte[]>
        {
            { "not JSON", Encoding.UTF8.GetBytes("{\"vct\": ") },
            { "an array", Encoding.UTF8.GetBytes($"[\"{Vct}\"]") },
            { "a duplicate member", Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", \"vct\": \"{Vct}\"}}") },
            { "no vct", Encoding.UTF8.GetBytes("{\"name\": \"x\"}") },
            { "a numeric vct", Encoding.UTF8.GetBytes("{\"vct\": 1}") },
            { "a numeric extends", Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", \"extends\": 1}}") },
            { "an empty extends", Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", \"extends\": \"\"}}") },
            { "a byte order mark", [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\"}}")] },
            { "invalid UTF-8", [.. Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", \"name\": \""), 0xC3, 0x28, .. "\"}"u8.ToArray()] },
            { "nested 65 deep", Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", \"x\": {new string('[', 64)}{new string(']', 64)}}}") },
            { "empty", [] },
        };
        // An unpaired surrogate escape, built from its code unit so no tool rewrites it (lesson 2026-10-27).
        data.Add("an unpaired surrogate escape", Encoding.UTF8.GetBytes($"{{\"vct\": \"{Vct}\", \"name\": \"\\u" + 0xD800.ToString("X4") + "\"}"));
        return data;
    }

    [Theory]
    [MemberData(nameof(InvalidDocuments))]
    public async Task A_document_that_is_not_a_JSON_object_with_a_vct_fails(string what, byte[] document)
    {
        _ = what;
        ShouldFail(await Verify(await SimpleCredential(), Options((Vct, document))), "VC_TYPE_METADATA_INVALID");
    }

    [Fact]
    public async Task A_document_above_the_size_limit_fails()
    {
        var document = SimpleDocument();
        document["padding"] = new string('x', 2000);
        var octets = Bytes(document);
        var resolver = new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = octets });
        var presentation = await SimpleCredential();

        ShouldFail(await Verify(presentation, new TypeMetadataProcessingOptions(resolver) { MaxDocumentSize = octets.Length - 1 }), "VC_TYPE_METADATA_INVALID");
        ShouldPass(await Verify(presentation, new TypeMetadataProcessingOptions(resolver) { MaxDocumentSize = octets.Length }));
        new TypeMetadataProcessingOptions(resolver).MaxDocumentSize.Should().Be(TypeMetadataProcessingOptions.DefaultMaxDocumentSize);
        var zero = () => new TypeMetadataProcessingOptions(resolver) { MaxDocumentSize = 0 };
        zero.Should().Throw<ArgumentOutOfRangeException>();
    }

    // ------------------------------------------------------------------ resolver faults versus verdicts

    private sealed class ThrowingResolver(Exception exception) : ITypeMetadataDocumentResolver
    {
        public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default) => throw exception;
    }

    private sealed class CountingResolver(ITypeMetadataDocumentResolver inner) : ITypeMetadataDocumentResolver
    {
        public List<string> Calls { get; } = [];

        public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
        {
            Calls.Add(reference);
            return inner.ResolveDocumentAsync(reference, cancellationToken);
        }
    }

    public static TheoryData<Exception> Faults => new()
    {
        new HttpRequestException("internal-host.example unreachable"),
        new TaskCanceledException("timeout"),
        new MalformedJoseException("thrown by the resolver"),
        new InvalidOperationException(),
    };

    [Theory]
    [MemberData(nameof(Faults))]
    public async Task A_resolver_that_throws_is_a_fault_not_a_verdict(Exception fault)
    {
        var result = await Verify(await SimpleCredential(), new TypeMetadataProcessingOptions(new ThrowingResolver(fault)));

        result.IsValid.Should().BeFalse();
        result.TypeMetadataResolverFault.Should().BeSameAs(fault);
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_TYPE_METADATA_RESOLVER_FAULT:")
            .And.NotContain("internal-host", "only the exception type is reported");
    }

    [Fact]
    public async Task A_parent_resolver_fault_is_a_fault_too_and_a_null_is_a_verdict()
    {
        var documents = new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = Bytes(SimpleDocument(extends: "urn:parent")) });
        var presentation = await SimpleCredential();

        ShouldFail(await Verify(presentation, new TypeMetadataProcessingOptions(documents)), "VC_TYPE_METADATA_UNAVAILABLE");
        ShouldFail(await Verify(presentation, Options()), "VC_TYPE_METADATA_UNAVAILABLE");

        var fault = new HttpRequestException();
        var parentFaults = new TypeMetadataProcessingOptions(new SelectiveResolver(documents, "urn:parent", fault));
        (await Verify(presentation, parentFaults)).TypeMetadataResolverFault.Should().BeSameAs(fault);
    }

    private sealed class SelectiveResolver(ITypeMetadataDocumentResolver inner, string failing, Exception fault) : ITypeMetadataDocumentResolver
    {
        public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
            => reference == failing ? throw fault : inner.ResolveDocumentAsync(reference, cancellationToken);
    }

    [Fact]
    public async Task Cancelling_the_callers_token_propagates()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var options = Options((Vct, Bytes(SimpleDocument())));
        var presentation = await SimpleCredential();

        var act = () => SdJwtVcVerifier.VerifyWithTypeMetadataAsync(presentation, _ => Issuer.PublicJwk, options, cancellationToken: cancelled.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Nothing_is_retrieved_for_a_presentation_whose_signature_fails()
    {
        var resolver = new CountingResolver(new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = Bytes(SimpleDocument()) }));
        var presentation = await SimpleCredential();
        var parts = presentation.Split('.');
        var tampered = parts[0] + "." + parts[1] + "." + (parts[2][0] == 'A' ? 'B' : 'A') + parts[2][1..];

        var result = await Verify(tampered, new TypeMetadataProcessingOptions(resolver));

        result.IsValid.Should().BeFalse();
        resolver.Calls.Should().BeEmpty();
        ShouldPass(await Verify(presentation, new TypeMetadataProcessingOptions(resolver)));
        resolver.Calls.Should().Equal(Vct);
    }

    [Fact]
    public async Task Processing_off_keeps_the_raw_resolver_behaviour()
    {
        var raw = new LocalCacheTypeMetadataResolver(new Dictionary<string, JsonObject> { [Vct] = SimpleDocument(extends: Vct) });
        var result = await SdJwtVcVerifier.VerifyAsync(await SimpleCredential(), _ => Issuer.PublicJwk, typeMetadataResolver: raw);

        result.IsValid.Should().BeTrue("VerifyAsync does not process: a self-extending document is returned, not refused");
        result.TypeMetadata!["extends"]!.GetValue<string>().Should().Be(Vct);
        result.ProcessedTypeMetadata.Should().BeNull();
        result.TypeMetadataResolverFault.Should().BeNull();
    }

    // ------------------------------------------------------------------ issuance (parity with verification)

    private static readonly JsonObject IssuanceDocument = SimpleDocument(new JsonArray(
        ClaimEntry(Path("given_name"), sd: "always", mandatory: true),
        ClaimEntry(Path("address"), sd: "never"),
        ClaimEntry(Path("address", "city"), sd: "always")));

    private static JsonObject IssuanceClaims(byte[] metadata) => new()
    {
        ["vct"] = Vct,
        ["vct#integrity"] = TypeMetadataIntegrity.Compute(metadata),
        ["given_name"] = "Arthur",
        ["address"] = new JsonObject { ["city"] = "Milliways", ["country"] = "Betelgeuse" },
    };

    private static readonly DisclosureFrame Conforming = new DisclosureFrame().Disclose("given_name").DiscloseObjectProperties("address", "city");

    [Fact]
    public async Task Issuance_is_checked_against_the_metadata_and_a_conforming_credential_verifies()
    {
        var metadata = Bytes(IssuanceDocument);
        var options = Options((Vct, metadata));

        var issued = await SdJwtVcIssuer.IssueWithTypeMetadataAsync(IssuanceClaims(metadata), Conforming, Issuer.Signer, options);

        ShouldPass(await Verify(issued.Issuance, options));
    }

    public static TheoryData<string, string> NonConforming => new()
    {
        { "given_name in the clear", "VC_CLAIM_SD_VIOLATION" },
        { "address disclosable", "VC_CLAIM_SD_VIOLATION" },
        { "given_name missing", "VC_CLAIM_MANDATORY_MISSING" },
        { "wrong vct#integrity", "VC_TYPE_METADATA_INTEGRITY_MISMATCH" },
    };

    [Theory]
    [MemberData(nameof(NonConforming))]
    public async Task Issuance_refuses_what_verification_would_refuse(string variant, string code)
    {
        var metadata = Bytes(IssuanceDocument);
        var claims = IssuanceClaims(metadata);
        var frame = Conforming;
        switch (variant)
        {
            case "given_name in the clear":
                frame = new DisclosureFrame().DiscloseObjectProperties("address", "city");
                break;
            case "address disclosable":
                frame = new DisclosureFrame().Disclose("given_name").DiscloseRecursively("address", "city");
                break;
            case "given_name missing":
                claims.Remove("given_name");
                frame = new DisclosureFrame().DiscloseObjectProperties("address", "city");
                break;
            case "wrong vct#integrity":
                claims["vct#integrity"] = TypeMetadataIntegrity.Compute("{}"u8);
                break;
        }

        // Verification of the same credential, every Disclosure presented, refuses it with the same code.
        var plain = await SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer);
        ShouldFail(await Verify(plain.Issuance, Options((Vct, metadata))), code);

        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, frame, Issuer.Signer, Options((Vct, metadata)));
        (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith(code + ":");
    }

    [Fact]
    public async Task At_issuance_decoys_do_not_hide_a_missing_mandatory_claim()
    {
        var metadata = Bytes(IssuanceDocument);
        var claims = IssuanceClaims(metadata);
        claims.Remove("given_name");
        claims["family_name"] = "Dent";
        var frame = new DisclosureFrame().Disclose("family_name").DiscloseObjectProperties("address", "city");
        var withDecoys = new SdJwtIssuerOptions { DecoyDigestCount = 3 };

        // A verifier cannot tell a decoy from a withheld claim, so it accepts; the issuer knows, so it refuses.
        var plain = await SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer, withDecoys);
        ShouldPass(await Verify(plain.Issuance, Options((Vct, metadata))));
        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, frame, Issuer.Signer, Options((Vct, metadata)), withDecoys);
        (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_CLAIM_MANDATORY_MISSING:");
    }

    [Fact]
    public async Task At_issuance_a_resolver_fault_is_a_JoseException_not_a_verdict()
    {
        var fault = new MalformedJoseException("thrown by the resolver");
        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(
            IssuanceClaims(Bytes(IssuanceDocument)), Conforming, Issuer.Signer, new TypeMetadataProcessingOptions(new ThrowingResolver(fault)));

        var thrown = (await act.Should().ThrowExactlyAsync<JoseException>()).Which;
        thrown.Message.Should().StartWith("VC_TYPE_METADATA_RESOLVER_FAULT:");
        thrown.InnerException.Should().BeSameAs(fault);

        var unavailable = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(IssuanceClaims(Bytes(IssuanceDocument)), Conforming, Issuer.Signer, Options());
        (await unavailable.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_TYPE_METADATA_UNAVAILABLE:");
    }

    // ------------------------------------------------------------------ adversarial pass (findings fixed in this PR)

    [Fact]
    public void A_non_canonical_base64_digest_does_not_match()
    {
        // The last character of a 32-octet digest carries two unused bits; flipping one spells the same octets differently.
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var good = Expression("sha256", Document);
        var body = good["sha256-".Length..].TrimEnd('=');
        var tweaked = "sha256-" + body[..^1] + alphabet[alphabet.IndexOf(body[^1]) ^ 1] + "=";

        TypeMetadataIntegrity.Matches(good, Document).Should().BeTrue();
        TypeMetadataIntegrity.Matches(tweaked, Document).Should().BeFalse();
    }

    [Fact]
    public async Task A_large_claims_array_is_processed_within_the_entry_bound_and_refused_past_it()
    {
        // Adversarial pass 1: the duplicate-path check and the merge compared every pair of paths (53,000 claims, 1 MiB:
        // 113 s). Paths are keyed since, and pass 3 bounded the entries a chain may hold. Two documents, so the merge runs
        // over every entry: 4,900 claims of one component each, 9,800 entries in all, are processed; one more claim is refused.
        static byte[] Claims(string vct, string? extends, int offset, int count)
            => Encoding.UTF8.GetBytes(
                $"{{\"vct\":\"{vct}\"" + (extends is null ? "" : $",\"extends\":\"{extends}\"") + ",\"claims\":["
                + string.Join(",", Enumerable.Range(offset, count).Select(i => $"{{\"path\":[\"k{i}\"]}}")) + "]}");
        var presentation = await SimpleCredential();

        var result = await Verify(presentation, Options((Vct, Claims(Vct, "urn:parent", 1_000, 2_450)), ("urn:parent", Claims("urn:parent", null, 0, 2_450))));
        ShouldPass(result);
        result.ProcessedTypeMetadata!.Claims.Should().HaveCount(3_450, "1,000 of the child's paths are new and 1,450 combine with the parent's");

        var over = await Verify(presentation, Options((Vct, Claims(Vct, "urn:parent", 1_000, 2_450)), ("urn:parent", Claims("urn:parent", null, 0, 2_551))));
        ShouldFail(over, "VC_TYPE_METADATA_INVALID");
        over.Errors.Single().Should().Contain($"more than {TypeMetadataProcessor.EntryBudget} claim, path, display and template entries");
    }

    private sealed class FlippingResolver(byte[] a, byte[] b) : ITypeMetadataDocumentResolver, IDisposable
    {
        private readonly byte[] _shared = (byte[])a.Clone();
        private readonly CancellationTokenSource _stop = new();
        private Task? _flipper;

        public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
        {
            _flipper ??= Task.Run(() =>
            {
                var toggle = false;
                while (!_stop.IsCancellationRequested)
                {
                    (toggle ? a : b).AsSpan().CopyTo(_shared);
                    toggle = !toggle;
                }
            });
            return Task.FromResult<byte[]?>(_shared);
        }

        public void Dispose()
        {
            _stop.Cancel();
            _flipper?.Wait();
            _stop.Dispose();
        }
    }

    [Fact]
    public async Task The_octets_hashed_are_the_octets_parsed_even_when_the_resolver_keeps_writing()
    {
        var a = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\",\"name\":\"AAAA\"}");
        var b = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\",\"name\":\"BBBB\"}");
        var presentation = await SimpleCredential(TypeMetadataIntegrity.Compute(a));
        using var resolver = new FlippingResolver(a, b);

        for (var i = 0; i < 500; i++)
        {
            var result = await Verify(presentation, new TypeMetadataProcessingOptions(resolver));
            if (result.IsValid)
                result.ProcessedTypeMetadata!.Name.Should().Be("AAAA", "only the document whose octets matched vct#integrity is processed");
        }
    }

    [Fact]
    public async Task A_resolver_that_keeps_writing_cannot_make_an_exception_escape()
    {
        // Equal lengths; b carries unpaired surrogate escapes, built from their code unit (lesson 2026-10-27).
        var escape = "\\u" + 0xD800.ToString("X4");
        var a = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\",\"abcdef\":1,\"x\":\"abcdef\"}");
        var b = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\",\"" + escape + "\":1,\"x\":\"" + escape + "\"}");
        a.Length.Should().Be(b.Length);
        var presentation = await SimpleCredential();
        using var resolver = new FlippingResolver(a, b);

        for (var i = 0; i < 500; i++)
        {
            var result = await Verify(presentation, new TypeMetadataProcessingOptions(resolver));
            if (!result.IsValid)
                result.Errors.Single().Should().StartWith("VC_TYPE_METADATA_INVALID:");
        }
    }

    [Fact]
    public async Task At_issuance_an_array_decoy_does_not_stand_in_for_a_mandatory_element()
    {
        // A placeholder no Disclosure resolves is, at issuance, a decoy (RFC 9901 §4.2.5 allows them in arrays): the
        // complete Unsecured Payload's deg has one element, so the mandatory deg[1] was not included.
        var metadata = Bytes(SimpleDocument(new JsonArray(ClaimEntry(Path("deg", 1), mandatory: true))));
        var decoy = Disclosure.ForArrayElement("salt-decoy", "never disclosed");
        var claims = new JsonObject { ["vct"] = Vct, ["deg"] = new JsonArray("a", Placeholder(decoy)) };

        // A Verifier cannot tell the decoy from a withheld element, so it accepts the credential.
        var plain = await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame(), Issuer.Signer);
        ShouldPass(await Verify(plain.Issuance, Options((Vct, metadata))));

        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, new DisclosureFrame(), Issuer.Signer, Options((Vct, metadata)));
        (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_CLAIM_MANDATORY_MISSING:");

        // And issuance still refuses what that Verifier refuses: sd: never on the elements, the decoy counted as one.
        var never = Bytes(SimpleDocument(new JsonArray(ClaimEntry(Path("deg", null), sd: "never"))));
        ShouldFail(await Verify(plain.Issuance, Options((Vct, never))), "VC_CLAIM_SD_VIOLATION");
        var refused = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, new DisclosureFrame(), Issuer.Signer, Options((Vct, never)));
        (await refused.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_CLAIM_SD_VIOLATION:");
    }

    private static JsonObject Decoy() => Placeholder(Disclosure.ForArrayElement("salt-decoy", "never disclosed"));

    public static TheoryData<string, string, int?, string?, bool?, string?> ShiftedIndexes => new()
    {
        // claims arr, disclosed index, metadata path tail, sd, mandatory, issuer's expected code (null: issued)
        { "decoy,a,b", "arr", 2, "never", null, null },
        { "decoy,a,b", "arr", 1, "always", null, null },
        { "decoy,{t},s", "arr.t", null, null, null, null },
        { "decoy,a", "arr", null, null, true, "VC_CLAIM_MANDATORY_MISSING" },
    };

    [Theory]
    [MemberData(nameof(ShiftedIndexes))]
    public async Task At_issuance_the_complete_payload_only_decides_whether_a_mandatory_claim_was_included(
        string shape, string tail, int? disclosedIndex, string? sd, bool? mandatory, string? issuerCode)
    {
        // Adversarial pass 2: the complete-payload view skips array decoys, so its index 1 is another element than the
        // as-issued index 1 the verifier judges. It must not add sd or path findings, only a missing mandatory claim.
        var array = shape switch
        {
            "decoy,a,b" => new JsonArray(Decoy(), "a", "b"),
            "decoy,{t},s" => new JsonArray(Decoy(), new JsonObject { ["t"] = 1 }, "s"),
            _ => new JsonArray(Decoy(), "a"),
        };
        var claims = new JsonObject { ["vct"] = Vct, ["arr"] = array };
        var path = tail == "arr.t" ? Path("arr", 1, "t") : Path("arr", 1);
        var metadata = Bytes(SimpleDocument(new JsonArray(ClaimEntry(path, sd, mandatory))));
        var frame = disclosedIndex is { } index ? new DisclosureFrame().DiscloseArrayElements("arr", index) : new DisclosureFrame();

        var plain = await SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer);
        ShouldPass(await Verify(plain.Issuance, Options((Vct, metadata))));

        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, frame, Issuer.Signer, Options((Vct, metadata)));
        if (issuerCode is null)
            await act.Should().NotThrowAsync();
        else
            (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith(issuerCode + ":");
    }

    [Fact]
    public async Task Claim_metadata_evaluation_is_bounded()
    {
        // Adversarial pass 2: the work is claims times the elements each path reaches; a 27,000-leaf credential against
        // 27,000 claims took 22 s. Here 5,000 elements: each claim ["a", null, "kN"] takes about 10,000 units of work (the
        // array's 5,000 elements selected, then each tried for its short key at one unit), so 90 claims pass and 300 are refused at the
        // bound. Deterministic: the refusal is asserted, not a duration.
        var elements = new JsonArray();
        for (var i = 0; i < 5_000; i++)
            elements.Add((JsonNode)new JsonObject { ["v"] = i });
        var presentation = await Sign(new JsonObject { ["vct"] = Vct, ["a"] = elements });
        static byte[] Document(int count)
        {
            var claims = new JsonArray();
            for (var i = 0; i < count; i++)
                claims.Add((JsonNode)ClaimEntry(Path("a", null, "k" + i)));
            return Bytes(SimpleDocument(claims));
        }

        ShouldPass(await Verify(presentation, Options((Vct, Document(90)))));
        var refused = await Verify(presentation, Options((Vct, Document(300))));

        ShouldFail(refused, "VC_CLAIM_METADATA_INVALID");
        refused.Errors.Single().Should().Contain("takes more than 1000000 units of work");
    }

    // ------------------------------------------------------------------ PR #55 review (comment 7030160237)

    /// <summary>The bytes the validator allocates on this thread for <paramref name="count"/> paths <c>["a", i]</c> over a <paramref name="count"/>-element array.</summary>
    private static long IndexedPathAllocations(int count, bool mandatory)
    {
        var elements = new JsonArray();
        for (var i = 0; i < count; i++)
            elements.Add((JsonNode)i);
        var trace = new ReconstructionTrace();
        var root = SdJwtReconstructor.Reconstruct(new JsonObject { ["vct"] = Vct, ["a"] = elements }, [], SdAlg, trace);
        var claims = Enumerable.Range(0, count)
            .Select(i => new ClaimMetadata([ClaimPathComponent.ForKey("a"), ClaimPathComponent.ForIndex(i)], [], mandatory, ClaimSelectiveDisclosure.Allowed, null))
            .ToList();

        ClaimMetadataValidator.Validate(root, trace, claims, allDisclosuresPresent: true).Should().BeNull();
        var before = GC.GetAllocatedBytesForCurrentThread();
        ClaimMetadataValidator.Validate(root, trace, claims, allDisclosuresPresent: true).Should().BeNull();
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Indexed_paths_cost_work_linear_in_the_claims_at_issuance(bool mandatory)
    {
        // Review finding 1: the complete-payload pass copied the whole array for every ["a", i], so 10,000 such claims
        // over a 10,000-element array allocated 2.66 GB. Four times the claims over four times the array must cost about
        // four times as much, not sixteen.
        var small = IndexedPathAllocations(1_000, mandatory);
        var large = IndexedPathAllocations(4_000, mandatory);

        large.Should().BeLessThan(small * 6, $"allocation grew from {small} to {large} bytes");
        large.Should().BeLessThan(4_000L * 2_000, "a few hundred bytes per indexed claim at most");
    }

    [Fact]
    public async Task The_reviewers_indexed_issuance_is_issued_within_the_entry_bound_and_refused_past_it()
    {
        // The review's case, 10,000 claims ["a", i] over a 10,000-element array, holds 30,000 entries and is refused by
        // the entry bound (pass 3) before anything is built; 3,000 such claims (9,000 entries) are issued and verify.
        static (JsonObject Claims, TypeMetadataProcessingOptions Options) Case(int count)
        {
            var elements = new JsonArray();
            var claims = new JsonArray();
            for (var i = 0; i < count; i++)
            {
                elements.Add((JsonNode)i);
                claims.Add((JsonNode)ClaimEntry(Path("a", i), mandatory: i % 2 == 0));
            }
            return (new JsonObject { ["vct"] = Vct, ["a"] = elements }, Options((Vct, Bytes(SimpleDocument(claims)))));
        }

        var (fits, fitsOptions) = Case(3_000);
        var issued = await SdJwtVcIssuer.IssueWithTypeMetadataAsync(fits, new DisclosureFrame(), Issuer.Signer, fitsOptions);
        ShouldPass(await Verify(issued.Issuance, fitsOptions));

        var (review, reviewOptions) = Case(10_000);
        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(review, new DisclosureFrame(), Issuer.Signer, reviewOptions);
        (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_TYPE_METADATA_INVALID:");
    }

    private static JsonObject DecoyNumbered(int n) => Placeholder(Disclosure.ForArrayElement("salt-decoy-" + n, "never disclosed " + n));

    public static TheoryData<string, bool> ShiftedShapeBesideAbsence => new()
    {
        // which row comes first, and whether the complete view's shape error is a string where an object (key x) or an
        // array (index 0) is expected
        { "missing first", false },
        { "shape error first", false },
        { "missing first", true },
        { "shape error first", true },
    };

    [Theory]
    [MemberData(nameof(ShiftedShapeBesideAbsence))]
    public async Task At_issuance_a_shifted_shape_error_does_not_discard_a_missing_mandatory_claim(string order, bool arrayStep)
    {
        // Review finding 2: in a=[[D1, X, missing], [D2, X, "s"]] the as-issued element 1 of each row is X; the complete
        // payload's element 1 is `missing` in one row and "s" in the other. "s" is a shifted shape error, which the
        // complete pass must skip without dropping the absence the other row proved (-27 §5.6.1.2, §5.6).
        JsonNode Present() => arrayStep ? new JsonArray(5) : new JsonObject { ["x"] = 1 };
        JsonNode Missing() => arrayStep ? new JsonArray() : new JsonObject();
        var withAbsence = new JsonArray(DecoyNumbered(1), Present(), Missing());
        var withShapeError = new JsonArray(DecoyNumbered(2), Present(), "s");
        var rows = order == "missing first" ? new JsonArray(withAbsence, withShapeError) : new JsonArray(withShapeError, withAbsence);
        var claims = new JsonObject { ["vct"] = Vct, ["a"] = rows };
        var path = arrayStep ? Path("a", null, 1, 0) : Path("a", null, 1, "x");
        var metadata = Bytes(SimpleDocument(new JsonArray(ClaimEntry(path, mandatory: true))));

        // As a verifier numbers the elements, every row's element 1 holds the claim.
        var plain = await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame(), Issuer.Signer);
        ShouldPass(await Verify(plain.Issuance, Options((Vct, metadata))));

        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, new DisclosureFrame(), Issuer.Signer, Options((Vct, metadata)));
        (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_CLAIM_MANDATORY_MISSING:");
    }

    [Fact]
    public async Task At_issuance_a_shifted_shape_error_alone_is_not_a_finding()
    {
        // The control: with the claim present in both complete rows' element 1 except a shifted shape error, nothing is missing.
        var rows = new JsonArray(
            new JsonArray(DecoyNumbered(1), new JsonObject { ["x"] = 1 }, new JsonObject { ["x"] = 1 }),
            new JsonArray(DecoyNumbered(2), new JsonObject { ["x"] = 1 }, "s"));
        var metadata = Bytes(SimpleDocument(new JsonArray(ClaimEntry(Path("a", null, 1, "x"), mandatory: true))));

        var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(
            new JsonObject { ["vct"] = Vct, ["a"] = rows }, new DisclosureFrame(), Issuer.Signer, Options((Vct, metadata)));

        await act.Should().NotThrowAsync();
    }

    // ------------------------------------------------------------------ PR #55 review 2 (review 5987613088)

    private static JsonObject ManyObjects(int count)
    {
        var elements = new JsonArray();
        for (var i = 0; i < count; i++)
            elements.Add((JsonNode)new JsonObject { ["x"] = 0 });
        return new JsonObject { ["vct"] = Vct, ["a"] = elements };
    }

    private static byte[] OneKeyPath(string key) => Bytes(SimpleDocument(new JsonArray(ClaimEntry(Path("a", null, key)))));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_long_path_key_over_a_wildcard_is_charged_for_its_length(bool issuance)
    {
        // Review 2: each key lookup hashes the whole key, so one optional claim ["a", null, K] with a 900,000-character K
        // over 80,000 objects took 14.2 s while 160,003 steps were charged. A lookup now costs a step per 32 characters,
        // charged before it runs: 2,000 objects with a 900,000-character key need about 56 million, refused at the
        // bound. The same claim with a short key costs about 6,000 and passes. Deterministic: a refusal, not a duration.
        var claims = ManyObjects(2_000);
        var longKey = OneKeyPath(new string('z', 900_000));
        var shortKey = OneKeyPath("zzzzzzzzzz");

        if (issuance)
        {
            await SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, new DisclosureFrame(), Issuer.Signer, Options((Vct, shortKey)));
            var act = () => SdJwtVcIssuer.IssueWithTypeMetadataAsync(claims, new DisclosureFrame(), Issuer.Signer, Options((Vct, longKey)));
            (await act.Should().ThrowExactlyAsync<MalformedJoseException>()).Which.Message.Should().StartWith("VC_CLAIM_METADATA_INVALID:");
            return;
        }

        var presentation = (await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame(), Issuer.Signer)).Issuance;
        ShouldPass(await Verify(presentation, Options((Vct, shortKey))));
        var refused = await Verify(presentation, Options((Vct, longKey)));
        ShouldFail(refused, "VC_CLAIM_METADATA_INVALID");
        refused.Errors.Single().Should().Contain("units of work");
    }

    [Fact]
    public void A_key_lookup_is_charged_before_it_runs()
    {
        // One lookup whose key alone exceeds the bound is refused without being performed.
        var trace = new ReconstructionTrace();
        var root = SdJwtReconstructor.Reconstruct(new JsonObject { ["vct"] = Vct, ["a"] = 1 }, [], SdAlg, trace);
        var key = new string('k', 32 * ClaimMetadataValidator.WorkBudget + 32);
        var claim = new ClaimMetadata([ClaimPathComponent.ForKey(key)], [], false, ClaimSelectiveDisclosure.Allowed, null);

        ClaimMetadataValidator.Validate(root, trace, [claim], allDisclosuresPresent: false).Should().StartWith("VC_CLAIM_METADATA_INVALID:");
    }

    // ------------------------------------------------------------------ adversarial pass 3 (resource exhaustion)

    [Fact]
    public async Task A_document_of_dense_path_components_is_refused_before_it_is_built()
    {
        // Pass 3: one claim with 524,000 two-octet index components (a 1 MiB document) allocated about 100 MB and the
        // result kept 55 MB alive. The entry bound refuses it from the array's parsed length, before any component is read.
        var document = Encoding.UTF8.GetBytes(
            "{\"vct\":\"" + Vct + "\",\"claims\":[{\"path\":[\"d\"" + string.Concat(Enumerable.Repeat(",0", 500_000)) + "]}]}");
        document.Length.Should().BeLessThan(TypeMetadataProcessingOptions.DefaultMaxDocumentSize);

        var result = await Verify(await SimpleCredential(), Options((Vct, document)));

        ShouldFail(result, "VC_TYPE_METADATA_INVALID");
        result.Errors.Single().Should().Contain($"more than {TypeMetadataProcessor.EntryBudget}");
    }

    public static TheoryData<string, string> HugeDisplayArrays => new()
    {
        { "type display", "\"display\":[" + string.Join(",", Enumerable.Repeat("{\"locale\":\"en\",\"name\":\"n\"}", 10_001)) + "]" },
        { "svg templates", "\"display\":[{\"locale\":\"en\",\"name\":\"n\",\"rendering\":{\"svg_templates\":["
            + string.Join(",", Enumerable.Repeat("{\"uri\":\"u\"}", 10_001)) + "]}}]" },
        { "claim display", "\"claims\":[{\"path\":[\"a\"],\"display\":[" + string.Join(",", Enumerable.Repeat("{\"locale\":\"en\",\"label\":\"l\"}", 10_001)) + "]}]" },
    };

    [Theory]
    [MemberData(nameof(HugeDisplayArrays))]
    public async Task Display_and_template_arrays_count_against_the_entry_bound(string what, string member)
    {
        _ = what;
        var document = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\"," + member + "}");
        ShouldFail(await Verify(await SimpleCredential(), Options((Vct, document))), "VC_TYPE_METADATA_INVALID");
    }

    [Fact]
    public async Task Error_messages_repeat_a_bounded_part_of_a_document_value()
    {
        // Pass 3: a path error echoed the whole path, escaped: 6,290,870 characters for a 1 MiB document.
        var longKey = new string('<', 500_000);
        var pathError = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\",\"claims\":[{\"path\":[0,\"" + longKey + "\"]}]}");
        var mismatch = Encoding.UTF8.GetBytes("{\"vct\":\"" + new string('v', 500_000) + "\"}");
        var duplicate = Encoding.UTF8.GetBytes(
            "{\"vct\":\"" + Vct + "\",\"claims\":[{\"path\":[\"" + longKey + "\"]},{\"path\":[\"" + longKey + "\"]}]}");
        var badSd = Encoding.UTF8.GetBytes("{\"vct\":\"" + Vct + "\",\"claims\":[{\"path\":[" + string.Join(",", Enumerable.Repeat("\"" + longKey[..1_000] + "\"", 100)) + "],\"sd\":1}]}");
        var presentation = await SimpleCredential();

        foreach (var (document, code) in new[]
        {
            (pathError, "VC_CLAIM_PATH_INVALID"), (mismatch, "VC_TYPE_METADATA_VCT_MISMATCH"),
            (duplicate, "VC_CLAIM_METADATA_INVALID"), (badSd, "VC_CLAIM_METADATA_INVALID"),
        })
        {
            var result = await Verify(presentation, Options((Vct, document)));
            ShouldFail(result, code);
            result.Errors.Single().Length.Should().BeLessThan(2_000, code);
        }
    }

    [Fact]
    public void An_integrity_value_with_many_expressions_is_checked_without_allocating_per_expression()
    {
        // Pass 3: splitting and decoding each expression allocated about 28 times a 1 MiB value.
        var good = Expression("sha512", Document);
        var many = string.Join(" ", Enumerable.Repeat(Wrong("sha512"), 8_000)) + " " + good;

        TypeMetadataIntegrity.Check(many, Document).Should().Be(TypeMetadataIntegrity.Outcome.Match);
        var before = GC.GetAllocatedBytesForCurrentThread();
        TypeMetadataIntegrity.Check(many, Document).Should().Be(TypeMetadataIntegrity.Outcome.Match);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        allocated.Should().BeLessThan(4_096, $"the value is {many.Length} characters");
        TypeMetadataIntegrity.Check(many.Replace(good, Wrong("sha512")), Document).Should().Be(TypeMetadataIntegrity.Outcome.Mismatch);
    }

    [Fact]
    public async Task The_result_keeps_octets_and_hands_out_documents_the_caller_owns()
    {
        var metadata = Bytes(SimpleDocument(new JsonArray(ClaimEntry(Path("given_name")))));
        var result = await Verify(await SimpleCredential(), Options((Vct, metadata)));
        ShouldPass(result);

        var first = result.ProcessedTypeMetadata!.Documents;
        first[0]["vct"] = "changed";
        result.TypeMetadata!["vct"] = "changed";

        result.ProcessedTypeMetadata.Documents[0]["vct"]!.GetValue<string>().Should().Be(Vct);
        result.TypeMetadata!["vct"]!.GetValue<string>().Should().Be(Vct);
        Encoding.UTF8.GetBytes(result.ProcessedTypeMetadata.Documents[0].ToJsonString()).Should().Equal(metadata);
    }

    [Fact]
    public void A_wildcard_over_many_claims_reuses_its_selection_lists()
    {
        // Pass 3, F3: 490 claims ["a", null, "kN"] over 1,000 objects (about 981,000 units, under the work bound)
        // allocated 20 MB, a new list per step and claim. The two lists are reused, so the memory is one selection.
        var elements = new JsonArray();
        for (var i = 0; i < 1_000; i++)
            elements.Add((JsonNode)new JsonObject { ["x"] = 0 });
        var trace = new ReconstructionTrace();
        var root = SdJwtReconstructor.Reconstruct(new JsonObject { ["vct"] = Vct, ["a"] = elements }, [], SdAlg, trace);
        var claims = Enumerable.Range(0, 490)
            .Select(i => new ClaimMetadata(
                [ClaimPathComponent.ForKey("a"), ClaimPathComponent.AllElements, ClaimPathComponent.ForKey("k" + i)], [], false, ClaimSelectiveDisclosure.Allowed, null))
            .ToList();

        ClaimMetadataValidator.Validate(root, trace, claims, allDisclosuresPresent: false).Should().BeNull();
        var before = GC.GetAllocatedBytesForCurrentThread();
        ClaimMetadataValidator.Validate(root, trace, claims, allDisclosuresPresent: false).Should().BeNull();
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        allocated.Should().BeLessThan(256 * 1024);
    }

    [Fact]
    public void A_path_description_is_bounded_and_the_canonical_key_is_not_escaped()
    {
        var key = new string('<', 10_000);
        var path = Enumerable.Repeat(ClaimPathComponent.ForKey(key), 50).Append(ClaimPathComponent.AllElements).Append(ClaimPathComponent.ForIndex(3)).ToList();

        ClaimPathComponent.Describe(path).Length.Should().BeLessThan(4 * 32 * 6 + 200);
        ClaimPathComponent.CanonicalKey(path).Length.Should().Be(50 * (key.Length + "k10000:".Length) + "*".Length + "i3;".Length);
        ClaimPathComponent.CanonicalKey([ClaimPathComponent.ForKey("0")]).Should().NotBe(ClaimPathComponent.CanonicalKey([ClaimPathComponent.ForIndex(0)]));
        ClaimPathComponent.CanonicalKey([ClaimPathComponent.ForKey("a"), ClaimPathComponent.ForKey("b")])
            .Should().NotBe(ClaimPathComponent.CanonicalKey([ClaimPathComponent.ForKey("a1:b")]));
    }

    [Fact]
    public async Task The_processed_metadata_cannot_be_changed_through_a_cast()
    {
        var metadata = Bytes(EducationDocument());
        var credential = Education(metadata);
        var result = await Verify(await Sign(credential.Payload, credential.All), Options((EducationVct, metadata)));

        var processed = result.ProcessedTypeMetadata!;
        IEnumerable<object> lists =
        [
            processed.Claims, processed.Display, processed.Documents, processed.Claims[0].Path, processed.Claims[0].Display,
            processed.Display[0].Rendering!.SvgTemplates,
        ];
        lists.Should().AllSatisfy(list => list.Should().BeAssignableTo<System.Collections.IList>().Which.IsReadOnly.Should().BeTrue());
    }

    // ------------------------------------------------------------------ local cache

    [Fact]
    public async Task The_local_cache_serves_copies_of_what_it_was_seeded_with_and_nothing_else()
    {
        var seed = Bytes(SimpleDocument());
        var cache = new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = seed });
        seed[0] = (byte)'[';

        var first = await cache.ResolveDocumentAsync(Vct);
        first![0].Should().Be((byte)'{');
        first[0] = (byte)'[';
        (await cache.ResolveDocumentAsync(Vct))![0].Should().Be((byte)'{');
        (await cache.ResolveDocumentAsync(Vct + "/")).Should().BeNull();
    }
}
