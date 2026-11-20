using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// RFC 9901 §7.1 step 4: "If any digest value is encountered more than once in the Issuer-signed JWT payload
/// (directly or recursively via other Disclosures), the SD-JWT MUST be rejected." Step 3.b identifies every embedded
/// digest, in <c>_sd</c> arrays and <c>{"...": digest}</c> placeholders, whether or not a Disclosure matches it. The
/// reconstructor used to refuse a repeat only within one <c>_sd</c> array or when a Disclosure resolved it twice, so a
/// decoy or withheld digest could repeat across locations (found by the issue #48 adversarial pass). The walk also
/// skipped every <c>_sd_alg</c> member at any depth, so digests under a nested one were never seen and the member
/// vanished; <c>_sd_alg</c> is a control claim only at the top level (RFC 9901 §4.1.1, §7.1 step 3.f), so a nested one
/// is now processed like any other member. A Disclosure named <c>_sd_alg</c> beside the top-level one is a name clash
/// (§7.1 step 3.c.ii.3).
/// </summary>
public sealed class SdJwtDigestUniquenessTests
{
    private const string SdAlg = "sha-256";
    private const string Decoy = "Ywu0YwV9r8O5eFYC0qWdC3gExgl23sDk0iIwV3PlmVc";

    private static readonly TestKeyMaterial Issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

    private static async Task<SdJwtVerificationResult> SignAndVerify(JsonObject payload, params Disclosure[] disclosures)
    {
        payload["_sd_alg"] = SdAlg;
        var jwt = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(payload.ToJsonString()), Issuer.Signer, typ: "example+sd-jwt");
        return SdJwtVerifier.Verify(jwt + "~" + string.Concat(disclosures.Select(d => d.Encoded + "~")), _ => Issuer.PublicJwk);
    }

    /// <summary>For repeats 2.0.0 already refused, under another message: only the refusal is pinned.</summary>
    private static void ShouldBeRefused(SdJwtVerificationResult result)
    {
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID");
    }

    private static void ShouldBeRefusedAsRepeated(SdJwtVerificationResult result)
    {
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("appears more than once");
    }

    [Fact]
    public async Task An_undisclosed_digest_in_two_sd_arrays_is_refused()
    {
        var payload = new JsonObject { ["_sd"] = new JsonArray(Decoy), ["address"] = new JsonObject { ["_sd"] = new JsonArray(Decoy) } };

        ShouldBeRefusedAsRepeated(await SignAndVerify(payload));
    }

    [Fact]
    public async Task An_undisclosed_placeholder_digest_in_two_arrays_is_refused()
    {
        var payload = new JsonObject
        {
            ["a"] = new JsonArray(new JsonObject { ["..."] = Decoy }),
            ["b"] = new JsonArray(1, new JsonObject { ["..."] = Decoy }),
        };

        ShouldBeRefusedAsRepeated(await SignAndVerify(payload));
    }

    [Fact]
    public async Task A_digest_in_an_sd_array_and_in_a_placeholder_is_refused()
    {
        var payload = new JsonObject { ["_sd"] = new JsonArray(Decoy), ["a"] = new JsonArray(new JsonObject { ["..."] = Decoy }) };

        ShouldBeRefusedAsRepeated(await SignAndVerify(payload));
    }

    [Fact]
    public async Task A_digest_repeated_through_a_presented_disclosure_is_refused()
    {
        // The repeat sits inside a Disclosure's value: "recursively via other Disclosures".
        var parent = Disclosure.ForObjectProperty("salt-parent", "address", new JsonObject { ["_sd"] = new JsonArray(Decoy) });
        var payload = new JsonObject { ["_sd"] = new JsonArray(parent.ComputeDigest(SdAlg), Decoy) };

        ShouldBeRefusedAsRepeated(await SignAndVerify(payload, parent));
    }

    [Fact]
    public async Task A_repeat_within_one_sd_array_is_still_refused()
    {
        ShouldBeRefused(await SignAndVerify(new JsonObject { ["_sd"] = new JsonArray(Decoy, Decoy) }));
    }

    [Fact]
    public async Task A_disclosed_digest_referenced_twice_is_still_refused()
    {
        var shared = Disclosure.ForObjectProperty("salt-shared", "given_name", JsonValue.Create("John"));
        var digest = shared.ComputeDigest(SdAlg);
        var payload = new JsonObject { ["_sd"] = new JsonArray(digest), ["address"] = new JsonObject { ["_sd"] = new JsonArray(digest) } };

        ShouldBeRefused(await SignAndVerify(payload, shared));
    }

    [Fact]
    public async Task A_repeat_hidden_under_a_nested_sd_alg_is_refused()
    {
        // The second adversarial pass's B07: the walk skipped the nested _sd_alg, so the repeat went unseen.
        var shared = Disclosure.ForObjectProperty("salt-b07", "given_name", JsonValue.Create("Erika"));
        var digest = shared.ComputeDigest(SdAlg);
        var payload = new JsonObject
        {
            ["credentialSubject"] = new JsonObject
            {
                ["_sd_alg"] = new JsonObject { ["_sd"] = new JsonArray(digest) },
                ["_sd"] = new JsonArray(digest),
            },
        };

        ShouldBeRefusedAsRepeated(await SignAndVerify(payload, shared));
    }

    [Fact]
    public async Task A_nested_sd_alg_is_an_ordinary_member_in_the_clear_or_in_a_disclosed_value()
    {
        var clear = await SignAndVerify(new JsonObject { ["address"] = new JsonObject { ["_sd_alg"] = "sha-256", ["country"] = "DE" } });
        var parent = Disclosure.ForObjectProperty("salt-p", "address", new JsonObject { ["_sd_alg"] = "sha-512" });
        var disclosed = await SignAndVerify(new JsonObject { ["_sd"] = new JsonArray(parent.ComputeDigest(SdAlg)) }, parent);

        clear.IsValid.Should().BeTrue(string.Join("; ", clear.Errors));
        clear.DisclosedPayload!["address"]!["_sd_alg"]!.GetValue<string>().Should().Be("sha-256");
        disclosed.IsValid.Should().BeTrue(string.Join("; ", disclosed.Errors));
        disclosed.DisclosedPayload!["address"]!["_sd_alg"]!.GetValue<string>().Should().Be("sha-512");
    }

    [Fact]
    public async Task A_claims_set_with_a_nested_sd_alg_issues_and_verifies()
    {
        // SdJwtIssuer copies a nested _sd_alg as given; its own verifier must not refuse what it signed.
        var claims = new JsonObject { ["credentialSubject"] = new JsonObject { ["_sd_alg"] = "sha-256", ["name"] = "Erika" } };
        var issued = await SdJwtIssuer.IssueAsync(
            claims, new DisclosureFrame().DiscloseObjectProperties("credentialSubject", "name"), Issuer.Signer);

        var result = SdJwtVerifier.Verify(issued.Issuance, _ => Issuer.PublicJwk);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        JsonNode.DeepEquals(result.DisclosedPayload!["credentialSubject"], claims["credentialSubject"]).Should().BeTrue();
    }

    [Fact]
    public async Task A_disclosure_named_sd_alg_beside_the_top_level_sd_alg_is_refused()
    {
        // RFC 9901 §7.1 step 3.c.ii.3: the claim name already exists at the level of the _sd key.
        var shadow = Disclosure.ForObjectProperty("salt-alg", "_sd_alg", JsonValue.Create("sha-512"));
        var result = await SignAndVerify(new JsonObject { ["_sd"] = new JsonArray(shadow.ComputeDigest(SdAlg)) }, shadow);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("collides");
    }

    [Fact]
    public async Task Distinct_decoys_and_a_withheld_disclosures_inner_digests_are_not_repeats()
    {
        // A withheld Disclosure's value is never processed, so a digest inside it is not "encountered".
        var withheld = Disclosure.ForObjectProperty("salt-withheld", "address", new JsonObject { ["_sd"] = new JsonArray(Decoy) });
        var payload = new JsonObject
        {
            ["_sd"] = new JsonArray(withheld.ComputeDigest(SdAlg), Decoy),
            ["nationalities"] = new JsonArray("DE", new JsonObject { ["..."] = "c2Vjb25kLWRpc3RpbmN0LWRlY295LWRpZ2VzdC12YWx1ZQ" }),
        };

        var result = await SignAndVerify(payload);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
    }
}
