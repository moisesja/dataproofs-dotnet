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
/// decoy or withheld digest could repeat across locations (found by the issue #48 adversarial pass). The walk skipped
/// every <c>_sd_alg</c> member at any depth, so digests under a nested one were never seen; RFC 9901 §4.1.1 says
/// <c>_sd_alg</c> "MUST NOT be used in any object nested within the payload", and a nested one is now refused.
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
        ShouldBeRefusedAsRepeated(await SignAndVerify(new JsonObject { ["_sd"] = new JsonArray(Decoy, Decoy) }));
    }

    [Fact]
    public async Task A_disclosed_digest_referenced_twice_is_still_refused()
    {
        var shared = Disclosure.ForObjectProperty("salt-shared", "given_name", JsonValue.Create("John"));
        var digest = shared.ComputeDigest(SdAlg);
        var payload = new JsonObject { ["_sd"] = new JsonArray(digest), ["address"] = new JsonObject { ["_sd"] = new JsonArray(digest) } };

        ShouldBeRefusedAsRepeated(await SignAndVerify(payload, shared));
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

        var result = await SignAndVerify(payload, shared);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("RFC 9901 §4.1.1");
    }

    [Fact]
    public async Task A_nested_sd_alg_in_the_clear_or_in_a_disclosed_value_is_refused()
    {
        var clear = await SignAndVerify(new JsonObject { ["address"] = new JsonObject { ["_sd_alg"] = "sha-256", ["country"] = "DE" } });
        var parent = Disclosure.ForObjectProperty("salt-p", "address", new JsonObject { ["_sd_alg"] = "sha-256" });
        var disclosed = await SignAndVerify(new JsonObject { ["_sd"] = new JsonArray(parent.ComputeDigest(SdAlg)) }, parent);

        clear.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("§4.1.1");
        disclosed.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID").And.Contain("§4.1.1");
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
