using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>FR-1: model (de)serialization — spec member names, null omission, round-tripping.</summary>
public class DataIntegrityProofModelTests
{
    private static string Serialize(DataIntegrityProof proof)
        => JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default);

    private static DataIntegrityProof Deserialize(string json)
        => JsonSerializer.Deserialize<DataIntegrityProof>(json, DataProofsJsonOptions.Default)!;

    [Fact]
    public void Serializes_WithSpecMemberNames_AndOmitsNulls()
    {
        var proof = new DataIntegrityProof
        {
            Cryptosuite = "eddsa-jcs-2022",
            Created = "2026-01-01T00:00:00Z",
            VerificationMethod = "did:example:alice#key-1",
            ProofPurpose = ProofPurposes.AssertionMethod,
            ProofValue = "z3FXQ",
        };

        var json = Serialize(proof);
        using var document = JsonDocument.Parse(json);
        var names = document.RootElement.EnumerateObject().Select(p => p.Name).ToList();

        names.Should().BeEquivalentTo(
            ["type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"]);
        document.RootElement.GetProperty("type").GetString().Should().Be("DataIntegrityProof");
        // Quoted member names: a bare substring check would false-positive on values
        // (e.g. the "id" inside the did: URI in verificationMethod).
        json.Should().NotContain("\"challenge\"").And.NotContain("\"domain\"").And.NotContain("\"nonce\"")
            .And.NotContain("\"expires\"").And.NotContain("\"previousProof\"").And.NotContain("\"id\"");
    }

    [Fact]
    public void AllModeledMembers_RoundTrip()
    {
        const string json = """
            {
              "id": "urn:uuid:1",
              "type": "DataIntegrityProof",
              "cryptosuite": "ecdsa-jcs-2019",
              "created": "2026-01-01T00:00:00Z",
              "expires": "2027-01-01T00:00:00Z",
              "verificationMethod": "did:example:alice#key-1",
              "proofPurpose": "authentication",
              "challenge": "abc123",
              "domain": "https://rp.example",
              "nonce": "n-42",
              "previousProof": "urn:uuid:0",
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "proofValue": "zSig"
            }
            """;

        var proof = Deserialize(json);

        proof.Id.Should().Be("urn:uuid:1");
        proof.Type.Should().Be("DataIntegrityProof");
        proof.Cryptosuite.Should().Be("ecdsa-jcs-2019");
        proof.Created.Should().Be("2026-01-01T00:00:00Z");
        proof.Expires.Should().Be("2027-01-01T00:00:00Z");
        proof.VerificationMethod.Should().Be("did:example:alice#key-1");
        proof.ProofPurpose.Should().Be("authentication");
        proof.Challenge.Should().Be("abc123");
        proof.Domain.Should().Be("https://rp.example");
        proof.Nonce.Should().Be("n-42");
        proof.PreviousProof.Should().Be(PreviousProofReference.FromSingle("urn:uuid:0"));
        proof.Context!.Value.ValueKind.Should().Be(JsonValueKind.Array);
        proof.ProofValue.Should().Be("zSig");

        JsonElement.DeepEquals(
            JsonSerializer.SerializeToElement(proof, DataProofsJsonOptions.Default),
            JsonDocument.Parse(json).RootElement).Should().BeTrue();
    }

    [Fact]
    public void PreviousProof_RoundTrips_PreservingWireShape()
    {
        var single = Deserialize("""{"previousProof":"urn:uuid:0"}""");
        var set = Deserialize("""{"previousProof":["urn:uuid:0","urn:uuid:1"]}""");

        single.PreviousProof!.IsArrayForm.Should().BeFalse();
        set.PreviousProof!.IsArrayForm.Should().BeTrue();
        set.PreviousProof.Values.Should().Equal("urn:uuid:0", "urn:uuid:1");

        Serialize(single).Should().Contain("\"previousProof\":\"urn:uuid:0\"");
        Serialize(set).Should().Contain("\"previousProof\":[\"urn:uuid:0\",\"urn:uuid:1\"]");
    }

    [Fact]
    public void UnmodeledMembers_RoundTrip_ThroughExtensionData()
    {
        const string json = """{"type":"DataIntegrityProof","proofValue":"z1","extensionField":{"a":1}}""";

        var proof = Deserialize(json);

        proof.AdditionalProperties.Should().ContainKey("extensionField");
        JsonElement.DeepEquals(
            JsonSerializer.SerializeToElement(proof, DataProofsJsonOptions.Default),
            JsonDocument.Parse(json).RootElement).Should().BeTrue();
    }

    [Fact]
    public void Type_DefaultsToDataIntegrityProof()
        => new DataIntegrityProof().Type.Should().Be(DataIntegrityProof.DataIntegrityProofType);

    [Fact]
    public void MalformedPreviousProof_ThrowsJsonException()
    {
        var actEmpty = () => Deserialize("""{"previousProof":""}""");
        var actNumber = () => Deserialize("""{"previousProof":42}""");
        var actEmptyArray = () => Deserialize("""{"previousProof":[]}""");
        var actMixedArray = () => Deserialize("""{"previousProof":["a",1]}""");

        actEmpty.Should().Throw<JsonException>();
        actNumber.Should().Throw<JsonException>();
        actEmptyArray.Should().Throw<JsonException>();
        actMixedArray.Should().Throw<JsonException>();
    }
}
