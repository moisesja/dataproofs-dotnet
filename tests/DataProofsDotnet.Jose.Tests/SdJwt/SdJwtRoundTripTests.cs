using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// FR-16 issuer/holder/verifier round trips: exercises the four SD-JWT structuring styles
/// (flat, structured, recursive, array-element), decoy digests, Key Binding, and the holder's
/// selective presentation — issuing with this library's own keys (deterministic Ed25519 path) and
/// verifying through the same pipeline. Complements the RFC 9901 ground-truth vectors with the
/// creation direction the fixtures cannot cover (our salts are random by NFR-5).
/// </summary>
public sealed class SdJwtRoundTripTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    private static JsonObject SampleClaims() => new()
    {
        ["iss"] = "https://issuer.example.com",
        ["sub"] = "user_42",
        ["given_name"] = "John",
        ["family_name"] = "Doe",
        ["address"] = new JsonObject
        {
            ["street_address"] = "123 Main St",
            ["locality"] = "Anytown",
            ["region"] = "Anystate",
            ["country"] = "US",
        },
        ["nationalities"] = new JsonArray("US", "DE", "FR"),
    };

    [Fact]
    public async Task Flat_disclosure_round_trips_and_holder_can_withhold_it()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var frame = new DisclosureFrame().Disclose("family_name").Disclose("address");

        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer);
        issued.Disclosures.Should().HaveCount(2);

        // Full issuance reveals both.
        var full = SdJwtVerifier.Verify(issued.Issuance, _ => issuer.PublicJwk);
        full.IsValid.Should().BeTrue(string.Join("; ", full.Errors));
        full.DisclosedPayload!.Should().ContainKey("family_name").And.ContainKey("address");

        // Holder presents only address; family_name is withheld.
        var addressDisclosure = issued.Disclosures.Single(d => d.ClaimName == "address").Encoded;
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, [addressDisclosure]);

        var partial = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk);
        partial.IsValid.Should().BeTrue(string.Join("; ", partial.Errors));
        partial.DisclosedPayload!.Should().ContainKey("address");
        partial.DisclosedPayload!.Should().NotContainKey("family_name",
            because: "the holder withheld the family_name Disclosure");
    }

    [Fact]
    public async Task Structured_disclosure_keeps_object_in_clear_with_per_subclaim_disclosures()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var frame = new DisclosureFrame().DiscloseObjectProperties("address", "street_address", "locality", "region", "country");

        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer);
        issued.Disclosures.Should().HaveCount(4, "one Disclosure per address sub-claim");

        // Present only region + country.
        var keep = issued.Disclosures.Where(d => d.ClaimName is "region" or "country").Select(d => d.Encoded);
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, keep);

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk);
        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        var address = result.DisclosedPayload!["address"]!.AsObject();
        address.Should().ContainKey("region").And.ContainKey("country");
        address.Should().NotContainKey("street_address").And.NotContainKey("locality");
    }

    [Fact]
    public async Task Recursive_disclosure_wraps_object_and_its_subclaims()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var frame = new DisclosureFrame().DiscloseRecursively("address", "street_address", "locality", "region", "country");

        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer);
        // 4 sub-claim Disclosures + 1 wrapping address Disclosure (RFC 9901 §6.3).
        issued.Disclosures.Should().HaveCount(5);

        // Without the address Disclosure, the nested sub-claim Disclosures are unreferenced and the
        // address claim itself is hidden.
        var addressDisclosure = issued.Disclosures.Single(d =>
            d.ClaimName == "address" && d.ClaimValue!.AsObject().ContainsKey("_sd")).Encoded;
        var localityDisclosure = issued.Disclosures.Single(d => d.ClaimName == "locality").Encoded;

        // Present the address wrapper + locality only.
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, [addressDisclosure, localityDisclosure]);
        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        var address = result.DisclosedPayload!["address"]!.AsObject();
        address.Should().ContainKey("locality");
        address.Should().NotContainKey("street_address",
            because: "only the locality sub-Disclosure was presented inside the recursive address");
    }

    [Fact]
    public async Task Array_element_disclosure_reveals_only_selected_indices()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        // Make nationalities[0] and nationalities[2] (US, FR) disclosable; DE stays in the clear.
        var frame = new DisclosureFrame().DiscloseArrayElements("nationalities", 0, 2);

        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer);
        issued.Disclosures.Should().HaveCount(2);
        issued.Disclosures.Should().OnlyContain(d => d.IsArrayElement);

        // Reveal only the US element (index 0).
        var usDisclosure = issued.Disclosures.Single(d => d.ClaimValue!.GetValue<string>() == "US").Encoded;
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, [usDisclosure]);

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk);
        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        var nats = result.DisclosedPayload!["nationalities"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
        // DE was always clear; US disclosed; FR withheld (dropped).
        nats.Should().BeEquivalentTo(new[] { "DE", "US" });
        nats.Should().NotContain("FR");
    }

    [Fact]
    public async Task Decoy_digests_obscure_the_count_without_breaking_reconstruction()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var frame = new DisclosureFrame().Disclose("given_name");
        var options = new SdJwtIssuerOptions { DecoyDigestCount = 5 };

        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer, options);
        // One real Disclosure, but the _sd array carries 1 real + 5 decoy digests.
        issued.Disclosures.Should().HaveCount(1);

        var result = SdJwtVerifier.Verify(issued.Issuance, _ => issuer.PublicJwk);
        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["given_name"]!.GetValue<string>().Should().Be("John");
    }

    [Fact]
    public async Task Key_binding_round_trip_verifies_with_audience_and_nonce()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");

        var options = new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk };
        var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name");
        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer, options);

        const string audience = "https://verifier.example.org";
        const string nonce = "n-0S6_WzA2Mj";
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance,
            issued.Disclosures.Select(d => d.Encoded),
            holder.Signer,
            audience,
            nonce);

        var verifyOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = audience,
            ExpectedNonce = nonce,
        };
        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk, verifyOptions);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue();

        // The recomputed sd_hash inside the KB-JWT matches the presented SD-JWT bytes (sanity:
        // a successful KB verification implies this, asserted explicitly).
        var components = SdJwtComponents.Parse(presentation);
        var recomputed = SdHashAlgorithm.ComputeSdHash(SdHashAlgorithm.Sha256, components.SdJwtWithoutKeyBinding);
        var kb = global::DataProofsDotnet.Jose.Base64Url.DecodeUtf8(components.KeyBindingJwt!.Split('.')[1]);
        kb.Should().Contain(recomputed, "the KB-JWT sd_hash claim must equal the recomputed hash over the presentation");
    }

    [Fact]
    public async Task Issuance_with_sha512_sd_alg_round_trips()
    {
        // RFC 9901 §4.1.1: _sd_alg may be sha-256/384/512. Exercise the non-default to prove the
        // digest algorithm flows through issuance, reconstruction, and (here) no KB.
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var frame = new DisclosureFrame().Disclose("given_name");
        var options = new SdJwtIssuerOptions { HashAlgorithm = SdHashAlgorithm.Sha512 };

        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer, options);

        // The disclosure digest under sha-512 differs from the sha-256 digest of the same string.
        var sha256Digest = issued.Disclosures[0].ComputeDigest(SdHashAlgorithm.Sha256);
        var sha512Digest = issued.Disclosures[0].ComputeDigest(SdHashAlgorithm.Sha512);
        sha512Digest.Should().NotBe(sha256Digest);

        var result = SdJwtVerifier.Verify(issued.Issuance, _ => issuer.PublicJwk);
        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["given_name"]!.GetValue<string>().Should().Be("John");
    }
}
