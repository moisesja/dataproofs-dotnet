using System.Text.Json;
using DataProofsDotnet.Jose.Encryption;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 1 — ECDH-1PU vectors from <c>draft-madden-jose-ecdh-1pu-04</c>
/// (fixtures: <c>fixtures/ietf/ecdh-1pu-04/</c>). Every derivation is deterministic and
/// byte-compared. The Appendix B complete JWE wraps the CEK with <c>A128KW</c> (16-byte KEK),
/// which NetCrypto's 32-byte-KEK-only <c>AesKeyWrap</c> cannot unwrap (see
/// <c>jwe-algorithm-omissions.md</c>, "Not backable"); coverage therefore stops at the
/// byte-compared KEK derivation plus the content-encryption KAT — exactly the deterministic
/// operations the draft publishes.
/// </summary>
public sealed class Ecdh1PuDraft04VectorTests
{
    private static readonly NetCrypto.ICryptoProvider _netCrypto = new DefaultCryptoProvider();
    private static readonly JoseCryptoProvider _crypto = new();

    [Fact]
    public void Appendix_A_direct_mode_Ze_Zs_and_Z_match()
    {
        using var fixture = Fixtures.LoadJson("ietf", "ecdh-1pu-04", "appendix-a-ecdh-1pu-direct-a256gcm.json");
        var root = fixture.RootElement;
        var alice = Fixtures.ToJwk(root.GetProperty("aliceStaticPrivateKeyJwk"));
        var bob = Fixtures.ToJwk(root.GetProperty("bobStaticPrivateKeyJwk"));
        var ephemeral = Fixtures.ToJwk(root.GetProperty("aliceEphemeralPrivateKeyJwk"));
        var (_, bobPublic) = JwkConversion.ExtractPublicKey(bob);

        var ze = _netCrypto.DeriveSharedSecret(KeyType.P256, Base64Url.Decode(ephemeral.D!), bobPublic);
        var zs = _netCrypto.DeriveSharedSecret(KeyType.P256, Base64Url.Decode(alice.D!), bobPublic);

        ze.Should().Equal(Hex.Decode(root.GetProperty("zeHex").GetString()!));
        zs.Should().Equal(Hex.Decode(root.GetProperty("zsHex").GetString()!));
        byte[] z = [.. ze, .. zs];
        z.Should().Equal(Hex.Decode(root.GetProperty("zHex").GetString()!),
            because: "draft-madden-04 §2.1: Z = Ze || Zs, ephemeral-static first.");
    }

    [Fact]
    public void Appendix_A_direct_mode_derived_key_matches()
    {
        using var fixture = Fixtures.LoadJson("ietf", "ecdh-1pu-04", "appendix-a-ecdh-1pu-direct-a256gcm.json");
        var root = fixture.RootElement;
        var alice = Fixtures.ToJwk(root.GetProperty("aliceStaticPrivateKeyJwk"));
        var bob = Fixtures.ToJwk(root.GetProperty("bobStaticPrivateKeyJwk"));
        var ephemeral = Fixtures.ToJwk(root.GetProperty("aliceEphemeralPrivateKeyJwk"));
        var header = root.GetProperty("header");
        var (_, bobPublic) = JwkConversion.ExtractPublicKey(bob);

        var derived = Ecdh1PuKdf.DeriveKey(
            _netCrypto, KeyType.P256,
            senderPrivateKey: Base64Url.Decode(alice.D!),
            ephemeralPrivateKey: Base64Url.Decode(ephemeral.D!),
            recipientPublicKey: bobPublic,
            algorithmId: Encoding.ASCII.GetBytes(header.GetProperty("enc").GetString()!), // direct mode: AlgorithmID = enc
            apu: Base64Url.Decode(header.GetProperty("apu").GetString()!),
            apv: Base64Url.Decode(header.GetProperty("apv").GetString()!),
            aeadTag: ReadOnlySpan<byte>.Empty, // direct mode has no cctag block in SuppPubInfo
            keyDataLen: root.GetProperty("keydatalen").GetInt32() / 8);

        derived.Should().Equal(Hex.Decode(root.GetProperty("derivedKeyHex").GetString()!),
            because: "draft-madden-04 Appendix A publishes the 256-bit direct-mode CEK.");
        Base64Url.Encode(derived).Should().Be(root.GetProperty("derivedKeyB64url").GetString());
    }

    [Theory]
    [InlineData("keyAgreementForBob", "bobStaticPrivateKeyJwk")]
    [InlineData("keyAgreementForCharlie", "charlieStaticPrivateKeyJwk")]
    public void Appendix_B_per_recipient_KEK_derivation_matches_both_directions(string agreementProperty, string recipientProperty)
    {
        using var fixture = Fixtures.LoadJson("ietf", "ecdh-1pu-04", "appendix-b-ecdh-1pu-a128kw-a256cbc-hs512.json");
        var root = fixture.RootElement;
        var alice = Fixtures.ToJwk(root.GetProperty("aliceStaticPrivateKeyJwk"));
        var ephemeral = Fixtures.ToJwk(root.GetProperty("aliceEphemeralPrivateKeyJwk"));
        var recipient = Fixtures.ToJwk(root.GetProperty(recipientProperty));
        var agreement = root.GetProperty(agreementProperty);

        var (_, recipientPublic) = JwkConversion.ExtractPublicKey(recipient);
        var (_, alicePublic) = JwkConversion.ExtractPublicKey(alice);
        var (_, ephemeralPublic) = JwkConversion.ExtractPublicKey(ephemeral);

        // Header values from the draft's protected header.
        using var header = JsonDocument.Parse(root.GetProperty("protectedHeaderJson").GetString()!);
        var algorithmId = Encoding.ASCII.GetBytes(header.RootElement.GetProperty("alg").GetString()!); // "ECDH-1PU+A128KW"
        var apu = Base64Url.Decode(header.RootElement.GetProperty("apu").GetString()!);                // "Alice"
        var apv = Base64Url.Decode(header.RootElement.GetProperty("apv").GetString()!);                // "Bob and Charlie"
        var tag = Base64Url.Decode(root.GetProperty("tagB64url").GetString()!);
        var keyDataLen = agreement.GetProperty("keydatalen").GetInt32() / 8;

        // Sender-side intermediates.
        var ze = _netCrypto.DeriveSharedSecret(KeyType.X25519, Base64Url.Decode(ephemeral.D!), recipientPublic);
        var zs = _netCrypto.DeriveSharedSecret(KeyType.X25519, Base64Url.Decode(alice.D!), recipientPublic);
        ze.Should().Equal(Hex.Decode(agreement.GetProperty("zeHex").GetString()!));
        zs.Should().Equal(Hex.Decode(agreement.GetProperty("zsHex").GetString()!));

        var expectedKek = Hex.Decode(agreement.GetProperty("derivedKeyHex").GetString()!);

        var senderSide = Ecdh1PuKdf.DeriveKey(
            _netCrypto, KeyType.X25519,
            senderPrivateKey: Base64Url.Decode(alice.D!),
            ephemeralPrivateKey: Base64Url.Decode(ephemeral.D!),
            recipientPublicKey: recipientPublic,
            algorithmId, apu, apv, tag, keyDataLen);
        senderSide.Should().Equal(expectedKek,
            because: "draft-madden-04 Appendix B publishes the per-recipient A128KW KEK (tag bound into SuppPubInfo with its 4-byte length prefix).");

        var receiverSide = Ecdh1PuKdf.DeriveKeyForReceiver(
            _netCrypto, KeyType.X25519,
            recipientPrivateKey: Base64Url.Decode(recipient.D!),
            ephemeralPublicKey: ephemeralPublic,
            senderPublicKey: alicePublic,
            algorithmId, apu, apv, tag, keyDataLen);
        receiverSide.Should().Equal(expectedKek,
            because: "DH commutativity gives the recipient the same KEK.");
    }

    [Fact]
    public void Appendix_B_content_encryption_KAT_matches_via_the_provider()
    {
        using var fixture = Fixtures.LoadJson("ietf", "ecdh-1pu-04", "appendix-b-ecdh-1pu-a128kw-a256cbc-hs512.json");
        var root = fixture.RootElement;
        var cek = Hex.Decode(root.GetProperty("cekHex").GetString()!);
        var iv = Hex.Decode(root.GetProperty("ivHex").GetString()!);
        var aad = Encoding.ASCII.GetBytes(root.GetProperty("protectedHeaderB64url").GetString()!);
        var plaintext = Encoding.UTF8.GetBytes(root.GetProperty("plaintextText").GetString()!);

        var (ciphertext, tag) = _crypto.AeadEncrypt(JoseAlgorithms.A256CbcHs512, cek, iv, aad, plaintext);

        Base64Url.Encode(ciphertext).Should().Be(root.GetProperty("ciphertextB64url").GetString());
        Base64Url.Encode(tag).Should().Be(root.GetProperty("tagB64url").GetString());

        var recovered = _crypto.AeadDecrypt(JoseAlgorithms.A256CbcHs512, cek, iv, aad, ciphertext, tag);
        Encoding.UTF8.GetString(recovered).Should().Be("Three is a magic number.");
    }

    [Fact]
    public void Appendix_B_protected_header_b64url_matches_its_json()
    {
        using var fixture = Fixtures.LoadJson("ietf", "ecdh-1pu-04", "appendix-b-ecdh-1pu-a128kw-a256cbc-hs512.json");
        var root = fixture.RootElement;
        var json = root.GetProperty("protectedHeaderJson").GetString()!;
        Base64Url.EncodeUtf8(json).Should().Be(root.GetProperty("protectedHeaderB64url").GetString());
    }
}
