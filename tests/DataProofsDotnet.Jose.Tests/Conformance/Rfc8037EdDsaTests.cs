using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 1 — RFC 8037 EdDSA appendix vectors (fixtures: <c>fixtures/ietf/rfc8037/</c>).
/// Ed25519 signing is deterministic, so the creation direction is byte-compared; verification
/// runs through the public parsers.
/// </summary>
public sealed class Rfc8037EdDsaTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    [Fact]
    public async Task A4_compact_jws_creation_is_byte_identical()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc8037", "a4-a5-ed25519-jws.json");
        var root = fixture.RootElement;
        var privateJwk = Fixtures.ToJwk(root.GetProperty("privateKeyJwk"));
        var payload = Encoding.UTF8.GetBytes(root.GetProperty("payloadText").GetString()!);

        var pair = new DefaultKeyGenerator().FromPrivateKey(KeyType.Ed25519, Base64Url.Decode(privateJwk.D!));
        var signer = new JwsSigner(new KeyPairSigner(pair, new DefaultCryptoProvider())); // no kid: header must be exactly {"alg":"EdDSA"}

        var compact = await JwsBuilder.BuildCompactAsync(payload, signer);

        compact.Should().Be(root.GetProperty("compactJws").GetString(),
            because: "RFC 8037 Appendix A.4/A.5 publishes the exact compact JWS; Ed25519 is deterministic.");

        var segments = compact.Split('.');
        segments[0].Should().Be(root.GetProperty("protectedHeaderB64url").GetString());
        segments[1].Should().Be(root.GetProperty("payloadB64url").GetString());
        Base64Url.Decode(segments[2]).Should().Equal(Hex.Decode(root.GetProperty("signatureHex").GetString()!));
    }

    [Fact]
    public void A5_compact_jws_verifies_through_the_public_parser()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc8037", "a4-a5-ed25519-jws.json");
        var root = fixture.RootElement;
        var publicJwk = Fixtures.ToJwk(root.GetProperty("publicKeyJwk"));
        var compact = root.GetProperty("compactJws").GetString()!;

        var result = JwsParser.ParseCompact(compact, _ => publicJwk, _crypto);

        result.SignatureAlgorithm.Should().Be("EdDSA");
        Encoding.UTF8.GetString(result.PayloadBytes).Should().Be(root.GetProperty("payloadText").GetString());
    }

    [Fact]
    public void A4_fixture_compact_file_matches_the_json_fixture()
    {
        // The standalone .txt fixture carries the same artifact; guard against fixture drift.
        var txt = File.ReadAllText(Fixtures.PathOf("ietf", "rfc8037", "a4-ed25519-compact.jws.txt")).Trim();
        using var fixture = Fixtures.LoadJson("ietf", "rfc8037", "a4-a5-ed25519-jws.json");
        txt.Should().Be(fixture.RootElement.GetProperty("compactJws").GetString());
    }

    [Fact]
    public void A5_tampered_payload_is_rejected()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc8037", "a4-a5-ed25519-jws.json");
        var root = fixture.RootElement;
        var publicJwk = Fixtures.ToJwk(root.GetProperty("publicKeyJwk"));
        var compact = root.GetProperty("compactJws").GetString()!;
        var segments = compact.Split('.');
        var tampered = segments[0] + "." + Base64Url.EncodeUtf8("Example of Ed25519 signing!") + "." + segments[2];

        Action act = () => JwsParser.ParseCompact(tampered, _ => publicJwk, _crypto);
        act.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public void A6_x25519_ecdh_es_shared_secret_matches()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc8037", "a6-x25519-ecdh-es.json");
        var root = fixture.RootElement;
        var ephemeralSecret = Hex.Decode(root.GetProperty("ephemeralSecretHex").GetString()!);
        var recipientPublic = Hex.Decode(root.GetProperty("recipientPublicKeyHex").GetString()!);

        var z = new DefaultCryptoProvider().DeriveSharedSecret(KeyType.X25519, ephemeralSecret, recipientPublic);

        z.Should().Equal(Hex.Decode(root.GetProperty("zHex").GetString()!),
            because: "RFC 8037 Appendix A.6 publishes the raw X25519 shared secret Z.");

        // The recipient public key JWK decodes to the same raw key the hex carries.
        var recipientJwk = Fixtures.ToJwk(root.GetProperty("recipientPublicKeyJwk"));
        var (keyType, raw) = JwkConversion.ExtractPublicKey(recipientJwk);
        keyType.Should().Be(KeyType.X25519);
        raw.Should().Equal(recipientPublic);
    }
}
