using DataProofsDotnet.Jose.Encryption;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 1 — RFC 7518 Appendix C ECDH-ES Concat-KDF worked example
/// (fixture: <c>fixtures/ietf/rfc7518/appendix-c-ecdh-es-concat-kdf.json</c>).
/// Deterministic, so every intermediate and the final derived key are byte-compared.
/// </summary>
public sealed class Rfc7518ConcatKdfTests
{
    private static readonly NetCrypto.ICryptoProvider _netCrypto = new DefaultCryptoProvider();

    [Fact]
    public void Appendix_C_shared_secret_Z_matches()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7518", "appendix-c-ecdh-es-concat-kdf.json");
        var root = fixture.RootElement;
        var alice = Fixtures.ToJwk(root.GetProperty("aliceEphemeralPrivateKeyJwk"));
        var bob = Fixtures.ToJwk(root.GetProperty("bobStaticPrivateKeyJwk"));

        var (_, bobPublic) = JwkConversion.ExtractPublicKey(bob);
        var z = _netCrypto.DeriveSharedSecret(KeyType.P256, Base64Url.Decode(alice.D!), bobPublic);

        z.Should().Equal(Hex.Decode(root.GetProperty("zHex").GetString()!),
            because: "RFC 7518 Appendix C publishes the raw P-256 ECDH output Z.");
    }

    [Fact]
    public void Appendix_C_derived_key_matches_through_EcdhEsKdf()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7518", "appendix-c-ecdh-es-concat-kdf.json");
        var root = fixture.RootElement;
        var alice = Fixtures.ToJwk(root.GetProperty("aliceEphemeralPrivateKeyJwk"));
        var bob = Fixtures.ToJwk(root.GetProperty("bobStaticPrivateKeyJwk"));
        var header = root.GetProperty("header");

        var (_, bobPublic) = JwkConversion.ExtractPublicKey(bob);
        var algorithmId = Encoding.ASCII.GetBytes(header.GetProperty("enc").GetString()!); // direct mode: AlgorithmID = enc
        var apu = Base64Url.Decode(header.GetProperty("apu").GetString()!);                 // "Alice"
        var apv = Base64Url.Decode(header.GetProperty("apv").GetString()!);                 // "Bob"
        var keyDataLen = root.GetProperty("keydatalen").GetInt32() / 8;

        var derived = EcdhEsKdf.DeriveKey(
            _netCrypto, KeyType.P256,
            Base64Url.Decode(alice.D!), bobPublic,
            algorithmId, apu, apv, keyDataLen);

        derived.Should().Equal(Hex.Decode(root.GetProperty("derivedKeyHex").GetString()!),
            because: "RFC 7518 Appendix C publishes the 128-bit Concat-KDF output.");
        Base64Url.Encode(derived).Should().Be(root.GetProperty("derivedKeyB64url").GetString());
    }

    [Fact]
    public void Appendix_C_receiver_side_derivation_matches_sender_side()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7518", "appendix-c-ecdh-es-concat-kdf.json");
        var root = fixture.RootElement;
        var alice = Fixtures.ToJwk(root.GetProperty("aliceEphemeralPrivateKeyJwk"));
        var bob = Fixtures.ToJwk(root.GetProperty("bobStaticPrivateKeyJwk"));
        var header = root.GetProperty("header");

        var (_, alicePublic) = JwkConversion.ExtractPublicKey(alice);
        var algorithmId = Encoding.ASCII.GetBytes(header.GetProperty("enc").GetString()!);
        var apu = Base64Url.Decode(header.GetProperty("apu").GetString()!);
        var apv = Base64Url.Decode(header.GetProperty("apv").GetString()!);

        var derived = EcdhEsKdf.DeriveKeyForReceiver(
            _netCrypto, KeyType.P256,
            Base64Url.Decode(bob.D!), alicePublic,
            algorithmId, apu, apv, keyDataLen: 16);

        derived.Should().Equal(Hex.Decode(root.GetProperty("derivedKeyHex").GetString()!),
            because: "DH commutativity: Bob derives the same key from his static private key and Alice's ephemeral public key.");
    }
}
