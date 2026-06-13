using System.Text;
using System.Text.Json;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// AC-3 step 6 — VC-JOSE-COSE, JOSE half (FR-18, "Securing Verifiable Credentials using JOSE and
/// COSE"). Envelopes a VCDM 2.0 credential as a compact JWS via <see cref="VcJose"/> and asserts
/// the spec's media type (<c>application/vc+jwt</c>) and required protected headers
/// (<c>typ: vc+jwt</c>, <c>cty: vc</c>) are produced and validated on the round trip; a
/// wrong/absent <c>typ</c> or <c>cty</c> is rejected. Mirrors the COSE half (AC-4).
/// </summary>
public sealed class VcJoseTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    // A minimal but well-formed VCDM 2.0 credential (treated as opaque bytes; data-model
    // validation is out of scope per PRD §11).
    private const string Vcdm2Credential = """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiableCredential"],
          "issuer": "https://issuer.example.com",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": { "id": "did:example:subject", "alumniOf": "Example University" }
        }
        """;

    private static byte[] CredentialBytes => Encoding.UTF8.GetBytes(Vcdm2Credential);

    [Fact]
    public async Task Envelope_produces_the_required_typ_and_cty_protected_headers()
    {
        var signer = TestKeyMaterial.Generate(KeyType.P256, "issuer").Signer;

        var envelope = await VcJose.EnvelopeCredentialAsync(CredentialBytes, signer);

        var headerJson = Base64Url.DecodeUtf8(envelope.Split('.')[0]);
        using var header = JsonDocument.Parse(headerJson);
        header.RootElement.GetProperty("typ").GetString().Should().Be(VcJose.EnvelopeType).And.Be("vc+jwt");
        header.RootElement.GetProperty("cty").GetString().Should().Be(VcJose.CredentialContentType).And.Be("vc");
        header.RootElement.GetProperty("alg").GetString().Should().Be("ES256");
    }

    [Fact]
    public void Media_type_constant_is_the_registered_application_vc_jwt()
    {
        VcJose.MediaType.Should().Be("application/vc+jwt");
        VcJose.MediaType.Should().Be("application/" + VcJose.EnvelopeType);
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Secp256k1)]
    public async Task Envelope_round_trips_and_returns_the_exact_credential_bytes(KeyType keyType)
    {
        var km = TestKeyMaterial.Generate(keyType, "issuer");

        var envelope = await VcJose.EnvelopeCredentialAsync(CredentialBytes, km.Signer);
        var recovered = VcJose.VerifyCredential(envelope, _ => km.PublicJwk, _crypto);

        recovered.Should().Equal(CredentialBytes, "the verified envelope must return the enveloped credential verbatim");
    }

    [Fact]
    public async Task Envelope_of_non_json_payload_is_rejected()
    {
        var signer = TestKeyMaterial.Generate(KeyType.P256, "issuer").Signer;

        Func<Task> act = () => VcJose.EnvelopeCredentialAsync(Encoding.UTF8.GetBytes("not json"), signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*well-formed JSON*");
    }

    [Fact]
    public async Task Envelope_of_a_json_array_payload_is_rejected_must_be_object()
    {
        var signer = TestKeyMaterial.Generate(KeyType.P256, "issuer").Signer;

        Func<Task> act = () => VcJose.EnvelopeCredentialAsync(Encoding.UTF8.GetBytes("[1,2,3]"), signer);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("*JSON object*");
    }

    [Fact]
    public async Task Verification_rejects_a_plain_jws_with_wrong_typ()
    {
        // A generic JWS (no vc+jwt typ) signed by the same key must be rejected by VcJose: the
        // envelope's content type is what distinguishes a VC envelope from any other JWS.
        var km = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var plainJws = await JwsBuilder.BuildCompactAsync(CredentialBytes, km.Signer); // no typ/cty

        Action act = () => VcJose.VerifyCredential(plainJws, _ => km.PublicJwk, _crypto);

        act.Should().Throw<MalformedJoseException>().WithMessage("*typ*");
    }

    [Fact]
    public async Task Verification_rejects_an_envelope_with_wrong_cty()
    {
        // Hand-build a JWS with the right typ but a wrong cty, signed correctly — the cty gate must
        // still reject it (mirrors VcCose's content-type check).
        var km = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var header = new JwsProtectedHeader
        {
            Alg = km.Signer.Algorithm,
            Kid = km.Signer.Kid ?? string.Empty,
            Typ = VcJose.EnvelopeType,
            AdditionalMembers = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["cty"] = JsonSerializer.SerializeToElement("application/json"), // wrong cty
            },
        };
        var protectedB64u = header.EncodeBase64Url();
        var payloadB64u = Base64Url.Encode(CredentialBytes);
        var signingInput = Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u);
        var signature = await km.Signer.SignAsync(signingInput, default);
        var forged = string.Concat(protectedB64u, ".", payloadB64u, ".", Base64Url.Encode(signature));

        Action act = () => VcJose.VerifyCredential(forged, _ => km.PublicJwk, _crypto);

        act.Should().Throw<MalformedJoseException>().WithMessage("*cty*");
    }

    [Fact]
    public async Task Verification_rejects_a_tampered_envelope_payload()
    {
        var km = TestKeyMaterial.Generate(KeyType.P256, "issuer");
        var envelope = await VcJose.EnvelopeCredentialAsync(CredentialBytes, km.Signer);
        var segments = envelope.Split('.');
        var tampered = $"{segments[0]}.{Base64Url.Encode(Encoding.UTF8.GetBytes("""{"@context":["x"],"type":["VerifiableCredential"]}"""))}.{segments[2]}";

        Action act = () => VcJose.VerifyCredential(tampered, _ => km.PublicJwk, _crypto);

        act.Should().Throw<JoseCryptoException>("a tampered payload must fail signature verification");
    }

    [Fact]
    public void Verification_rejects_a_structurally_invalid_envelope()
    {
        var km = TestKeyMaterial.Generate(KeyType.P256, "issuer");

        Action act = () => VcJose.VerifyCredential("not.a.jws.envelope.x", _ => km.PublicJwk, _crypto);

        act.Should().Throw<MalformedJoseException>();
    }
}
