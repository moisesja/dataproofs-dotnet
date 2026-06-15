using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;
using JoseDefaultCryptoProvider = DataProofsDotnet.Jose.JoseCryptoProvider;

namespace DataProofsDotnet.Jose.Tests.Envelopes.Signing;

public sealed class JwsRoundTripTests
{
    private static readonly JoseDefaultCryptoProvider _crypto = new();

    // Ported payload adaptation (from the didcomm-dotnet port): the porting source signed a DIDComm Message built
    // via MessageBuilder; dataproofs signs arbitrary bytes, so the same logical content travels
    // as a JSON payload and the Message.Id / Message.From assertions read the payload JSON.
    private static byte[] Payload(string from = "did:example:alice", string? to = "did:example:bob") =>
        Encoding.UTF8.GetBytes(to is null
            ? $"{{\"id\":\"m1\",\"type\":\"https://didcomm.org/empty/1.0/empty\",\"from\":\"{from}\"}}"
            : $"{{\"id\":\"m1\",\"type\":\"https://didcomm.org/empty/1.0/empty\",\"from\":\"{from}\",\"to\":[\"{to}\"]}}");

    [Theory]
    [InlineData(KeyType.Ed25519, "EdDSA")]
    [InlineData(KeyType.P256, "ES256")]
    [InlineData(KeyType.Secp256k1, "ES256K")]
    public async Task Sign_then_verify_round_trips_for_each_alg(KeyType keyType, string expectedAlg)
    {
        var signer = TestKeyMaterial.Generate(keyType, "did:example:alice#key-1");
        var payload = Payload();

        var packed = await JwsBuilder.BuildJsonAsync(payload, new[] { signer.Signer });

        var result = JwsParser.Parse(packed,
            kid => kid == signer.PublicJwk.Kid ? signer.PublicJwk : null,
            _crypto);

        result.SignatureAlgorithm.Should().Be(expectedAlg);
        result.SignerKid.Should().Be("did:example:alice#key-1");
        using var doc = System.Text.Json.JsonDocument.Parse(result.PayloadBytes);
        doc.RootElement.GetProperty("id").GetString().Should().Be("m1");
        doc.RootElement.GetProperty("from").GetString().Should().Be("did:example:alice");
    }

    [Fact]
    public async Task Tampered_payload_fails_verification()
    {
        var signer = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#k");
        var payload = Payload(to: null);

        var packed = await JwsBuilder.BuildJsonAsync(payload, new[] { signer.Signer });

        // Flip a byte in the base64url payload to invalidate the signature.
        var tampered = packed.Replace("\"payload\":\"e", "\"payload\":\"f", StringComparison.Ordinal);

        Action act = () => JwsParser.Parse(tampered,
            _ => signer.PublicJwk,
            _crypto);

        act.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public async Task Verifier_with_no_matching_kid_throws_crypto()
    {
        var signer = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#k");
        var payload = Payload(to: null);

        var packed = await JwsBuilder.BuildJsonAsync(payload, new[] { signer.Signer });

        Action act = () => JwsParser.Parse(packed, _ => null, _crypto);
        act.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public async Task Single_signer_emits_flattened_form()
    {
        var signer = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#k");
        var payload = Payload(to: null);

        var packed = await JwsBuilder.BuildJsonAsync(payload, new[] { signer.Signer });

        // Flattened JSON: top-level "signature" + "protected", no "signatures" array.
        packed.Should().Contain("\"signature\":");
        packed.Should().NotContain("\"signatures\":");
    }

    [Fact]
    public async Task Multiple_signers_emit_general_form_and_either_verifies()
    {
        var signerA = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#ed");
        var signerB = TestKeyMaterial.Generate(KeyType.P256, "did:example:alice#p256");
        var payload = Payload(to: null);

        var packed = await JwsBuilder.BuildJsonAsync(payload, new[] { signerA.Signer, signerB.Signer });

        packed.Should().Contain("\"signatures\":");

        // General form's only top-level "signature" property is inside the array — assert by
        // parsing rather than substring.
        using var doc = System.Text.Json.JsonDocument.Parse(packed);
        doc.RootElement.TryGetProperty("signature", out _).Should().BeFalse("general form has no top-level 'signature'");

        var byKid = new Dictionary<string, Jwk>
        {
            [signerA.PublicJwk.Kid!] = signerA.PublicJwk,
            [signerB.PublicJwk.Kid!] = signerB.PublicJwk,
        };

        var resolveA = (string kid) => kid == signerA.PublicJwk.Kid ? signerA.PublicJwk : null;
        var resultA = JwsParser.Parse(packed, resolveA, _crypto);
        resultA.SignerKid.Should().Be(signerA.PublicJwk.Kid);

        var resolveB = (string kid) => kid == signerB.PublicJwk.Kid ? signerB.PublicJwk : null;
        var resultB = JwsParser.Parse(packed, resolveB, _crypto);
        resultB.SignerKid.Should().Be(signerB.PublicJwk.Kid);
    }
}
