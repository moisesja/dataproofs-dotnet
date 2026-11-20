using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// Issue #48: the SD-JWT VC must-not-disclose rule is positional. draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3: "The
/// following registered JWT claims, including any of their subclaims, when used in the SD-JWT component of an SD-JWT
/// VC, MUST NOT be included in Disclosures". The listed names are JWT claims, members of the top-level claims set, so:
/// <list type="bullet">
/// <item>a Disclosure that resolves to a top-level member with a reserved name is refused;</item>
/// <item>so is one anywhere inside a reserved claim, under any name: a member of <c>status</c> or <c>cnf</c>, an
/// element of <c>aka_vcts</c>, and so on down (the -19 clarification);</item>
/// <item>a claim elsewhere that only shares a reserved name, such as <c>credentialSubject.status</c>, is ordinary.</item>
/// </list>
/// Both directions are tested on issuance (<see cref="SdJwtVcIssuer"/>) and on verification
/// (<see cref="SdJwtVcVerifier"/>). Claim names are literals and only public API is used, so this file also compiles
/// against the 2.0.0 sources and shows each regression failing there.
/// </summary>
public sealed class Issue48ReservedClaimPositionTests
{
    private const string Vct = "https://credentials.example.com/identity_credential";
    private const string SdAlg = "sha-256";

    private static readonly TestKeyMaterial Issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

    /// <summary>The registered claims of -27 §2.2.2.3, as literals.</summary>
    private static readonly string[] Reserved = ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"];

    /// <summary>
    /// The instant every presentation here is verified at, inside the window of <see cref="CredentialWithReservedClaims"/>
    /// (<c>nbf</c> 2023-11-14, <c>exp</c> 2029-09-02): the verifier judges both (issue #45), and an expired credential
    /// would report that before the rule under test.
    /// </summary>
    private static readonly DateTimeOffset VerifiedAt = new(2026, 11, 19, 0, 0, 0, TimeSpan.Zero);

    private static Task<SdJwtVcVerificationResult> VerifyVc(string presentation)
        => SdJwtVcVerifier.VerifyAsync(presentation, _ => Issuer.PublicJwk, new SdJwtVerificationOptions { CurrentTime = VerifiedAt });

    /// <summary>A credential carrying every reserved claim in the clear, with object and array shapes to reach into.</summary>
    private static JsonObject CredentialWithReservedClaims() => new()
    {
        ["iss"] = "https://example.com/issuer",
        ["nbf"] = 1700000000,
        ["exp"] = 1883000000,
        ["vct"] = Vct,
        ["vct#integrity"] = "sha256-WRhk8wbl4bodJ4VTFJXcJjvYVPFXxmJO9iU7x52xbeA",
        ["aka_vcts"] = new JsonArray("urn:example:general", "urn:example:other"),
        ["cnf"] = new JsonObject
        {
            ["jwk"] = new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
        },
        ["status"] = new JsonObject
        {
            ["status_list"] = new JsonObject { ["idx"] = 412, ["uri"] = "https://example.com/statuslists/1" },
            ["lists"] = new JsonArray(new JsonObject { ["idx"] = 7 }),
        },
        ["given_name"] = "John",
    };

    /// <summary>Issues through the generic SD-JWT issuer with the SD-JWT VC <c>typ</c>, bypassing the VC frame guard.</summary>
    private static async Task<string> IssueGeneric(DisclosureFrame frame)
        => (await SdJwtIssuer.IssueAsync(CredentialWithReservedClaims(), frame, Issuer.Signer, typ: "dc+sd-jwt")).Issuance;

    /// <summary>Signs <paramref name="payload"/> as a <c>dc+sd-jwt</c> issuer JWT and appends <paramref name="disclosures"/>.</summary>
    private static async Task<string> SignHandBuilt(JsonObject payload, params Disclosure[] disclosures)
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

    // ---- A nested claim named like a reserved claim is ordinary: issued, presented, verified ----

    /// <summary>
    /// The issue's table (rows <c>given_name</c>, <c>status</c>, <c>exp</c>, <c>iss</c>), extended to every other
    /// reserved name. <c>given_name</c> is the control row that 2.0.0 already passed.
    /// </summary>
    public static TheoryData<string> IssueTableRows => new() { "given_name", "status", "exp", "iss", "nbf", "cnf", "vct", "vct#integrity", "aka_vcts" };

    [Theory]
    [MemberData(nameof(IssueTableRows))]
    public async Task Credential_subject_claim_named_like_a_reserved_claim_is_issued_presented_and_verified(string name)
    {
        // The issue's reproduction: claims { vct, credentialSubject: { id, <name>: "value" } },
        // frame DiscloseObjectProperties("credentialSubject", <name>), verify with every disclosure attached.
        var claims = new JsonObject
        {
            ["vct"] = Vct,
            ["credentialSubject"] = new JsonObject { ["id"] = "did:example:subject", [name] = "value" },
        };
        var frame = new DisclosureFrame().DiscloseObjectProperties("credentialSubject", name);

        var issued = await SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer);
        issued.Disclosures.Should().ContainSingle().Which.ClaimName.Should().Be(name);
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));

        var result = await VerifyVc(presentation);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["credentialSubject"]![name]!.GetValue<string>().Should().Be("value");
    }

    [Fact]
    public async Task Nested_cnf_and_status_disclosures_verify_with_key_binding_on_the_top_level_cnf()
    {
        // The holder key sits in the clear at the top level; credentialSubject carries ordinary claims that share the
        // names cnf and status. Key Binding must use the top-level cnf, and the nested ones are just claims.
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var claims = new JsonObject
        {
            ["vct"] = Vct,
            ["credentialSubject"] = new JsonObject
            {
                ["cnf"] = new JsonObject { ["note"] = "not a confirmation method" },
                ["status"] = "active",
            },
        };
        var frame = new DisclosureFrame().DiscloseObjectProperties("credentialSubject", "cnf", "status");
        var issued = await SdJwtVcIssuer.IssueAsync(
            claims, frame, Issuer.Signer, new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holder.Signer, "https://verifier.example", "n-48");
        var result = await SdJwtVcVerifier.VerifyAsync(
            presentation,
            _ => Issuer.PublicJwk,
            new SdJwtVerificationOptions
            {
                CurrentTime = VerifiedAt, RequireKeyBinding = true, ExpectedAudience = "https://verifier.example", ExpectedNonce = "n-48",
            });

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue();
        result.DisclosedPayload!["credentialSubject"]!["status"]!.GetValue<string>().Should().Be("active");
    }

    /// <summary>Other places a reserved name can sit without being the registered claim, each issued by the VC issuer.</summary>
    public static TheoryData<string> NestedFrames => new() { "recursive parent", "two levels down", "recursive two levels", "inside a nested status" };

    [Theory]
    [MemberData(nameof(NestedFrames))]
    public async Task Reserved_names_deeper_in_the_payload_are_ordinary_claims(string shape)
    {
        var claims = new JsonObject
        {
            ["vct"] = Vct,
            ["credentialSubject"] = new JsonObject
            {
                ["status"] = "active",
                ["exp"] = 1883000000,
                ["employment"] = new JsonObject { ["status"] = "employed", ["iss"] = "https://employer.example" },
                ["record"] = new JsonObject { ["status"] = new JsonObject { ["state"] = "open", ["lists"] = new JsonArray(1, 2) } },
            },
        };
        var frame = shape switch
        {
            "recursive parent" => new DisclosureFrame().DiscloseRecursively("credentialSubject", "status", "exp"),
            "two levels down" => new DisclosureFrame().DiscloseObject(
                "credentialSubject", new DisclosureFrame().Disclose("status").DiscloseObjectProperties("employment", "status", "iss")),
            "recursive two levels" => new DisclosureFrame().DiscloseRecursiveObject(
                "credentialSubject", new DisclosureFrame().DiscloseRecursively("employment", "status", "iss")),
            // credentialSubject.record.status is an ordinary object, so it may carry an _sd and array placeholders.
            _ => new DisclosureFrame().DiscloseObject("credentialSubject", new DisclosureFrame().DiscloseObject(
                "record", new DisclosureFrame().DiscloseObject(
                    "status", new DisclosureFrame().Disclose("state").DiscloseArrayElements("lists", 0, 1)))),
        };

        var issued = await SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer);
        var result = await VerifyVc(issued.Issuance);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        JsonNode.DeepEquals(result.DisclosedPayload!["credentialSubject"], claims["credentialSubject"]).Should().BeTrue(
            result.DisclosedPayload!.ToJsonString());
    }

    [Fact]
    public async Task Reserved_name_inside_an_array_element_of_an_ordinary_claim_verifies()
    {
        // items[0] is an object in the clear whose _sd holds a Disclosure named status: path items[0].status.
        var status = Disclosure.ForObjectProperty("salt-status-in-items", "status", JsonValue.Create("shipped"));
        var element = Disclosure.ForArrayElement("salt-element", new JsonObject { ["exp"] = 1883000000 });
        var payload = new JsonObject
        {
            ["vct"] = Vct,
            ["items"] = new JsonArray(new JsonObject { ["_sd"] = Sd(status) }, Placeholder(element)),
        };

        var result = await VerifyVc(await SignHandBuilt(payload, status, element));

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["items"]!.ToJsonString().Should().Be("""[{"status":"shipped"},{"exp":1883000000}]""");
    }

    [Fact]
    public async Task A_parent_disclosure_whose_value_discloses_a_reserved_name_is_ordinary()
    {
        // A top-level Disclosure "evidence" whose value carries an _sd reaching a member named status: the path is
        // evidence.status, which is not the registered status claim.
        var inner = Disclosure.ForObjectProperty("salt-inner", "status", JsonValue.Create("checked"));
        var parent = Disclosure.ForObjectProperty("salt-parent", "evidence", new JsonObject { ["_sd"] = Sd(inner) });
        var payload = new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(parent) };

        var result = await VerifyVc(await SignHandBuilt(payload, parent, inner));

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["evidence"]!["status"]!.GetValue<string>().Should().Be("checked");
    }

    // ---- A reserved claim, or anything inside one, is refused on verification ----

    public static TheoryData<string> ReservedNames()
    {
        var data = new TheoryData<string>();
        foreach (var name in Reserved)
            data.Add(name);
        return data;
    }

    [Theory]
    [MemberData(nameof(ReservedNames))]
    public async Task Verifier_refuses_a_top_level_reserved_claim_presented_as_a_disclosure(string reserved)
    {
        var result = await VerifyVc(await IssueGeneric(new DisclosureFrame().Disclose(reserved)));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE")
            .And.Contain($"'{reserved}' MUST NOT be selectively disclosed");
    }

    /// <summary>Every way the frame API can place a Disclosure inside a reserved claim.</summary>
    public static TheoryData<string, string> InsideReservedClaims => new()
    {
        { "member of status", "status" },
        { "two levels inside status", "status" },
        { "array element inside status", "status" },
        { "member of cnf", "cnf" },
        { "two levels inside cnf", "cnf" },
        { "element of aka_vcts", "aka_vcts" },
        { "second element of aka_vcts", "aka_vcts" },
    };

    private static DisclosureFrame FrameFor(string shape) => shape switch
    {
        "member of status" => new DisclosureFrame().DiscloseObjectProperties("status", "status_list"),
        "two levels inside status" => new DisclosureFrame().DiscloseObject(
            "status", new DisclosureFrame().DiscloseObjectProperties("status_list", "idx")),
        "array element inside status" => new DisclosureFrame().DiscloseObject(
            "status", new DisclosureFrame().DiscloseArrayElements("lists", 0)),
        "member of cnf" => new DisclosureFrame().DiscloseObjectProperties("cnf", "jwk"),
        "two levels inside cnf" => new DisclosureFrame().DiscloseObject(
            "cnf", new DisclosureFrame().DiscloseObjectProperties("jwk", "x")),
        "element of aka_vcts" => new DisclosureFrame().DiscloseArrayElements("aka_vcts", 0),
        // Index 1 disclosed, index 0 in the clear.
        "second element of aka_vcts" => new DisclosureFrame().DiscloseArrayElements("aka_vcts", 1),
        _ => throw new ArgumentOutOfRangeException(nameof(shape)),
    };

    [Theory]
    [MemberData(nameof(InsideReservedClaims))]
    public async Task Verifier_refuses_a_disclosure_inside_a_reserved_claim(string shape, string reserved)
    {
        var result = await VerifyVc(await IssueGeneric(FrameFor(shape)));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE")
            .And.Contain($"SD-JWT VC claim '{reserved}' MUST NOT have selectively disclosable sub-claims or elements").And.Contain("§2.2.2.3");
    }

    [Fact]
    public async Task Verifier_refuses_a_reserved_claim_wrapped_in_a_recursive_disclosure()
    {
        // status is itself a Disclosure carrying the digest of its member: both are refused, the outer one first.
        var result = await VerifyVc(await IssueGeneric(new DisclosureFrame().DiscloseRecursively("status", "status_list")));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith(
            "VC_DISALLOWED_DISCLOSURE: SD-JWT VC claim 'status' MUST NOT be selectively disclosed");
    }

    [Fact]
    public async Task Verifier_refuses_a_disclosure_two_levels_inside_status_through_an_array_element_disclosure()
    {
        // status.lists[0] is an array-element Disclosure whose value carries an _sd reaching idx: status.lists[0].idx.
        var idx = Disclosure.ForObjectProperty("salt-idx", "idx", JsonValue.Create(7));
        var element = Disclosure.ForArrayElement("salt-list", new JsonObject { ["_sd"] = Sd(idx) });
        var payload = new JsonObject
        {
            ["vct"] = Vct,
            ["status"] = new JsonObject { ["lists"] = new JsonArray(Placeholder(element)) },
        };

        var result = await VerifyVc(await SignHandBuilt(payload, element, idx));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE")
            .And.Contain("'status' MUST NOT have selectively disclosable sub-claims or elements");
    }

    [Fact]
    public async Task Verifier_refuses_a_disclosure_inside_status_even_when_another_status_sibling_is_withheld()
    {
        // Two members of status are Disclosures; the holder presents only one. The presented one is still refused.
        var issued = await SdJwtIssuer.IssueAsync(
            CredentialWithReservedClaims(),
            new DisclosureFrame().DiscloseObjectProperties("status", "status_list", "lists"),
            Issuer.Signer,
            typ: "dc+sd-jwt");
        var presentation = SdJwtHolder.CreatePresentation(
            issued.Issuance, issued.Disclosures.Where(d => d.ClaimName == "lists").Select(d => d.Encoded));

        var result = await VerifyVc(presentation);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("'status' MUST NOT have selectively disclosable sub-claims or elements");
    }

    [Theory]
    [MemberData(nameof(InsideReservedClaims))]
    public async Task Verifier_refuses_a_disclosure_inside_a_reserved_claim_when_it_is_withheld(string shape, string reserved)
    {
        // Withholding the Disclosure leaves no position to judge, and changes the reserved claim under the same
        // signature. The '_sd' or '...' left in the signed claim is the evidence, so the rule is checked there too.
        var issuance = await IssueGeneric(FrameFor(shape));

        var result = await VerifyVc(SdJwtHolder.CreatePresentation(issuance, []));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE")
            .And.Contain($"SD-JWT VC claim '{reserved}' MUST NOT have selectively disclosable sub-claims or elements").And.Contain("§2.2.2.3");
    }

    [Fact]
    public async Task Withholding_an_aka_vcts_element_cannot_turn_an_invalid_signed_value_into_a_valid_one()
    {
        // The signed aka_vcts holds the vct value at index 1, which -27 §2.2.2.2 forbids. With the element's
        // Disclosure attached the array is refused; withholding it would leave ["urn:example:visible"] under the same
        // signature. Both are refused, before the aka_vcts format check runs.
        var claims = new JsonObject { ["vct"] = "urn:example:main", ["aka_vcts"] = new JsonArray("urn:example:visible", "urn:example:main") };
        var issued = await SdJwtIssuer.IssueAsync(claims, new DisclosureFrame().DiscloseArrayElements("aka_vcts", 1), Issuer.Signer, typ: "dc+sd-jwt");

        var attached = await VerifyVc(issued.Issuance);
        var withheld = await VerifyVc(SdJwtHolder.CreatePresentation(issued.Issuance, []));

        attached.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE").And.Contain("'aka_vcts' MUST NOT have selectively disclosable sub-claims or elements");
        withheld.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE").And.Contain("'aka_vcts' MUST NOT have selectively disclosable sub-claims or elements");
    }

    public static TheoryData<string> DecoyShapes => new() { "decoy in status", "decoy two levels inside cnf", "decoy placeholder in aka_vcts", "decoy placeholder in status array" };

    [Theory]
    [MemberData(nameof(DecoyShapes))]
    public async Task Verifier_refuses_decoy_structure_inside_a_reserved_claim(string shape)
    {
        // A digest with no Disclosure behind it cannot be told from a withheld one, so it fails closed too.
        const string decoy = "Ywu0YwV9r8O5eFYC0qWdC3gExgl23sDk0iIwV3PlmVc";
        var payload = CredentialWithReservedClaims();
        switch (shape)
        {
            case "decoy in status":
                payload["status"]!["_sd"] = new JsonArray(decoy);
                break;
            case "decoy two levels inside cnf":
                payload["cnf"]!["jwk"]!["_sd"] = new JsonArray(decoy);
                break;
            case "decoy placeholder in aka_vcts":
                payload["aka_vcts"]!.AsArray().Add((JsonNode)new JsonObject { ["..."] = decoy });
                break;
            default:
                payload["status"]!["lists"]!.AsArray().Add((JsonNode)new JsonObject { ["..."] = decoy });
                break;
        }

        var result = await VerifyVc(await SignHandBuilt(payload));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE").And.Contain("MUST NOT have selectively disclosable sub-claims or elements");
    }

    [Fact]
    public async Task An_empty_sd_array_inside_a_reserved_claim_is_not_a_disclosure_site()
    {
        // RFC 9901 §4.2.4.1: "The array MAY be empty in case the Issuer decided not to selectively disclose any of the
        // claims at that level." An empty _sd carries no digest, so nothing in status is disclosable or withheld.
        var payload = CredentialWithReservedClaims();
        payload["status"]!["_sd"] = new JsonArray();
        payload["cnf"]!["jwk"]!["_sd"] = new JsonArray();

        var verified = await VerifyVc(await SignHandBuilt(payload));
        var issued = await SdJwtVcIssuer.IssueAsync(payload, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        verified.IsValid.Should().BeTrue(string.Join("; ", verified.Errors));
        (await VerifyVc(issued.Issuance)).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Decoys_outside_reserved_claims_are_still_accepted()
    {
        var claims = new JsonObject
        {
            ["vct"] = Vct,
            ["status"] = new JsonObject { ["status_list"] = new JsonObject { ["idx"] = 1, ["uri"] = "https://example.com/sl" } },
            ["credentialSubject"] = new JsonObject { ["given_name"] = "John", ["status"] = "active" },
        };
        var issued = await SdJwtVcIssuer.IssueAsync(
            claims,
            new DisclosureFrame().DiscloseObjectProperties("credentialSubject", "status"),
            Issuer.Signer,
            new SdJwtIssuerOptions { DecoyDigestCount = 3 });

        var result = await VerifyVc(issued.Issuance);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
    }

    // ---- Ways around the positional rule that must still fail ----

    [Fact]
    public async Task A_top_level_reserved_claim_in_the_clear_and_as_a_disclosure_is_refused()
    {
        var shadow = Disclosure.ForObjectProperty("salt-shadow", "exp", JsonValue.Create(4102444800));
        var payload = new JsonObject { ["vct"] = Vct, ["exp"] = 1883000000, ["_sd"] = Sd(shadow) };

        var result = await VerifyVc(await SignHandBuilt(payload, shadow));

        result.IsValid.Should().BeFalse("a Disclosure may not overwrite a claim in the clear, and exp may not be disclosed");
    }

    [Fact]
    public async Task One_digest_at_two_locations_one_reserved_one_not_is_refused()
    {
        // The same Disclosure digest sits in credentialSubject._sd and in status._sd.
        var shared = Disclosure.ForObjectProperty("salt-shared", "idx", JsonValue.Create(1));
        var payload = new JsonObject
        {
            ["vct"] = Vct,
            ["credentialSubject"] = new JsonObject { ["_sd"] = Sd(shared) },
            ["status"] = new JsonObject { ["_sd"] = Sd(shared) },
        };

        var result = await VerifyVc(await SignHandBuilt(payload, shared));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID");
    }

    [Fact]
    public async Task An_unreferenced_disclosure_named_like_a_reserved_claim_is_refused()
    {
        var used = Disclosure.ForObjectProperty("salt-used", "given_name", JsonValue.Create("John"));
        var stray = Disclosure.ForObjectProperty("salt-stray", "status", new JsonObject { ["status_list"] = new JsonObject() });
        var payload = new JsonObject { ["vct"] = Vct, ["_sd"] = Sd(used) };

        var result = await VerifyVc(await SignHandBuilt(payload, used, stray));

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("not referenced");
    }

    [Fact]
    public async Task The_generic_verifier_does_not_apply_the_profile_rule_and_the_vc_verifier_does()
    {
        // The must-not-disclose list is an SD-JWT VC rule (-27 §2.2.2.3), not an RFC 9901 one: SdJwtVerifier
        // reconstructs this credential, and only SdJwtVcVerifier refuses it.
        var issuance = await IssueGeneric(new DisclosureFrame().DiscloseObjectProperties("cnf", "jwk"));

        SdJwtVerifier.Verify(issuance, _ => Issuer.PublicJwk, new SdJwtVerificationOptions { CurrentTime = VerifiedAt }).IsValid.Should().BeTrue();
        (await VerifyVc(issuance)).Errors.Should().ContainSingle().Which.Should().StartWith("VC_DISALLOWED_DISCLOSURE");
    }

    // ---- Issuance: the frame check follows the same rule ----

    public static TheoryData<string, string> ReservedFrameEntries()
    {
        var data = new TheoryData<string, string>();
        foreach (var name in Reserved)
            foreach (var kind in new[] { "flat", "structured", "nested frame", "recursive", "recursive frame", "array elements" })
                data.Add(name, kind);
        return data;
    }

    [Theory]
    [MemberData(nameof(ReservedFrameEntries))]
    public async Task Issuer_refuses_every_frame_entry_on_a_reserved_claim(string reserved, string kind)
    {
        var frame = kind switch
        {
            "flat" => new DisclosureFrame().Disclose(reserved),
            "structured" => new DisclosureFrame().DiscloseObjectProperties(reserved, "member"),
            "nested frame" => new DisclosureFrame().DiscloseObject(reserved, new DisclosureFrame().DiscloseObjectProperties("a", "b")),
            "recursive" => new DisclosureFrame().DiscloseRecursively(reserved, "member"),
            "recursive frame" => new DisclosureFrame().DiscloseRecursiveObject(reserved, new DisclosureFrame().Disclose("member")),
            _ => new DisclosureFrame().DiscloseArrayElements(reserved, 0),
        };

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(CredentialWithReservedClaims(), frame, Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage($"*'{reserved}' MUST NOT be selectively disclosed*");
    }

    [Fact]
    public async Task Issuer_refuses_a_reserved_entry_alongside_allowed_nested_ones()
    {
        var frame = new DisclosureFrame()
            .DiscloseObjectProperties("credentialSubject", "status")
            .DiscloseObjectProperties("status", "status_list");
        var claims = CredentialWithReservedClaims();
        claims["credentialSubject"] = new JsonObject { ["status"] = "active" };

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, frame, Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*'status' MUST NOT be selectively disclosed*");
    }

    public static TheoryData<string> StructuredReservedClaims => new() { "_sd in status", "_sd two levels inside cnf", "placeholder in a status array" };

    [Theory]
    [MemberData(nameof(StructuredReservedClaims))]
    public async Task Issuer_refuses_a_claims_set_whose_reserved_claim_carries_disclosure_structure(string shape)
    {
        // A caller-built '_sd' or '...' inside a reserved claim would be signed as it is; the verifier refuses it.
        var hidden = Disclosure.ForObjectProperty("salt-hidden", "idx", JsonValue.Create(1));
        var claims = CredentialWithReservedClaims();
        switch (shape)
        {
            case "_sd in status":
                claims["status"]!["_sd"] = Sd(hidden);
                break;
            case "_sd two levels inside cnf":
                claims["cnf"]!["jwk"]!["_sd"] = Sd(hidden);
                break;
            default:
                claims["status"]!["lists"]!.AsArray().Add((JsonNode)Placeholder(Disclosure.ForArrayElement("salt-el", JsonValue.Create(3))));
                break;
        }

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>()
            .WithMessage("*carries an '_sd' digest array or a '...' array placeholder*MUST NOT be selectively disclosed*");
    }

    [Fact]
    public async Task Issuer_reads_a_reserved_claim_as_it_will_be_signed()
    {
        // A JsonValue can wrap a .NET object that serializes as a JSON object: the structure check must see the '_sd'
        // it will sign, not the JsonValue node that hides it (second adversarial pass, finding A2).
        var hidden = Disclosure.ForObjectProperty("salt-hidden", "idx", JsonValue.Create(1));
        var claims = CredentialWithReservedClaims();
        claims["status"] = JsonValue.Create(new Dictionary<string, string[]> { ["_sd"] = [hidden.ComputeDigest(SdAlg)] });

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*'status' carries an '_sd' digest array*");
    }

    /// <summary>Serializes without an <c>_sd</c> member the first <c>hiddenReads</c> times, then with one.</summary>
    public sealed class FlipStatus(int hiddenReads, string digest)
    {
        private int _reads;

        [JsonPropertyName("idx")]
        public int Idx => 1;

        [JsonPropertyName("_sd")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string[]? Sd => ++_reads <= hiddenReads ? null : [digest];
    }

    [Fact]
    public async Task Issuer_signs_the_json_it_checked_not_a_second_serialization()
    {
        // Third adversarial pass, P3_06: a value that serializes differently on its second read passed the check and
        // was signed with an '_sd'. The issuer now signs the one serialization it checked.
        var hidden = Disclosure.ForObjectProperty("salt-flip", "idx", JsonValue.Create(2));
        var claims = CredentialWithReservedClaims();
        claims["status"] = JsonValue.Create(new FlipStatus(1, hidden.ComputeDigest(SdAlg)));

        var issued = await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), Issuer.Signer);

        Base64Url.DecodeUtf8(issued.IssuerJwt.Split('.')[1]).Should().Contain("\"status\":{\"idx\":1}");
        (await VerifyVc(issued.Issuance)).IsValid.Should().BeTrue();
    }

    /// <summary>Serializes with a duplicate member name through extension data.</summary>
    public sealed class DuplicatingStatus
    {
        [JsonPropertyName("idx")]
        public int Idx => 1;

        [JsonExtensionData]
        public Dictionary<string, object> Extra { get; } = new() { ["idx"] = 2 };
    }

    [Fact]
    public async Task Issuer_refuses_a_claims_set_that_serializes_with_a_duplicate_member_name()
    {
        // RFC 7519 §4: "The Claim Names within a JWT Claims Set MUST be unique." The verifier refuses such a payload.
        var claims = CredentialWithReservedClaims();
        claims["status"] = JsonValue.Create(new DuplicatingStatus());

        Func<Task> act = () => SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame(), Issuer.Signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*unique member names*");
    }

    [Fact]
    public async Task A_claims_set_the_serializer_cannot_write_still_fails_through_the_task()
    {
        // As before the claims-set check: the call returns, and the serializer's exception arrives when awaited.
        JsonNode inner = "leaf";
        for (var i = 0; i < 70; i++)
            inner = new JsonObject { ["n"] = inner };
        var claims = CredentialWithReservedClaims();
        claims["deep"] = inner;

        var task = SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame(), Issuer.Signer);

        await FluentActions.Awaiting(() => task).Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Nested_aka_vcts_array_claim_round_trips()
    {
        // The PR #52 review's reproduction: related.aka_vcts is an ordinary nested claim, not the registered one.
        var claims = JsonNode.Parse("""{"vct":"urn:example:main","related":{"aka_vcts":["urn:example:related"]}}""")!.AsObject();
        var issued = await SdJwtVcIssuer.IssueAsync(
            claims, new DisclosureFrame().DiscloseObjectProperties("related", "aka_vcts"), Issuer.Signer);

        var result = await VerifyVc(issued.Issuance);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["related"]!["aka_vcts"]!.ToJsonString().Should().Be("""["urn:example:related"]""");
    }

    [Fact]
    public async Task Issuer_accepts_every_reserved_name_nested_under_an_ordinary_claim_and_the_verifier_agrees()
    {
        var subject = new JsonObject();
        foreach (var name in Reserved)
            subject[name] = $"{name}-value";
        var claims = new JsonObject { ["vct"] = Vct, ["credentialSubject"] = subject };

        var issued = await SdJwtVcIssuer.IssueAsync(
            claims, new DisclosureFrame().DiscloseObjectProperties("credentialSubject", Reserved), Issuer.Signer);
        var result = await VerifyVc(issued.Issuance);

        issued.Disclosures.Select(d => d.ClaimName).Should().BeEquivalentTo(Reserved);
        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        JsonNode.DeepEquals(result.DisclosedPayload!["credentialSubject"], subject).Should().BeTrue(result.DisclosedPayload!.ToJsonString());
    }
}
