using System.Text.Json;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 1 — generated frozen vectors for ES256K and XC20P
/// (fixtures: <c>fixtures/generated/</c>; generation script and the explicit
/// no-external-secp256k1-oracle note in its PROVENANCE.md). ES256K signing is RFC 6979
/// deterministic, so the creation direction is byte-compared; the XC20P AEAD KAT and the
/// frozen JWE's decrypt direction are likewise deterministic.
/// </summary>
public sealed class GeneratedVectorTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    [Fact]
    public async Task Es256k_compact_jws_creation_is_byte_identical_to_the_frozen_vector()
    {
        using var fixture = Fixtures.LoadJson("generated", "es256k-jws.json");
        var root = fixture.RootElement;
        var privateJwk = Fixtures.ToJwk(root.GetProperty("privateKeyJwk"));
        var payload = Encoding.UTF8.GetBytes(root.GetProperty("payloadText").GetString()!);

        var pair = new DefaultKeyGenerator().FromPrivateKey(KeyType.Secp256k1, Base64Url.Decode(privateJwk.D!));
        var signer = new JwsSigner(new KeyPairSigner(pair, new DefaultCryptoProvider()), kid: privateJwk.Kid);

        var compact = await JwsBuilder.BuildCompactAsync(payload, signer);

        compact.Should().Be(root.GetProperty("compactJws").GetString(),
            because: "NetCrypto's secp256k1 signing uses RFC 6979 deterministic nonces — any drift in the primitive or the JWS composition changes these bytes.");

        var flattened = await JwsBuilder.BuildJsonAsync(payload, [signer]);
        flattened.Should().Be(JsonSerializer.Serialize(root.GetProperty("flattenedJws")));
    }

    [Fact]
    public void Es256k_frozen_jws_verifies_through_the_public_parsers()
    {
        using var fixture = Fixtures.LoadJson("generated", "es256k-jws.json");
        var root = fixture.RootElement;
        var publicJwk = Fixtures.ToJwk(root.GetProperty("publicKeyJwk"));

        var fromCompact = JwsParser.ParseCompact(root.GetProperty("compactJws").GetString()!, _ => publicJwk, _crypto);
        fromCompact.SignatureAlgorithm.Should().Be("ES256K");
        Encoding.UTF8.GetString(fromCompact.PayloadBytes).Should().Be(root.GetProperty("payloadText").GetString());

        var fromFlattened = JwsParser.Parse(JsonSerializer.Serialize(root.GetProperty("flattenedJws")), _ => publicJwk, _crypto);
        fromFlattened.SignerKid.Should().Be(publicJwk.Kid);
    }

    [Fact]
    public void Es256k_tampered_signature_is_rejected()
    {
        using var fixture = Fixtures.LoadJson("generated", "es256k-jws.json");
        var root = fixture.RootElement;
        var publicJwk = Fixtures.ToJwk(root.GetProperty("publicKeyJwk"));
        var compact = root.GetProperty("compactJws").GetString()!;
        var segments = compact.Split('.');
        var sig = Base64Url.Decode(segments[2]);
        sig[0] ^= 0x01;
        var tampered = segments[0] + "." + segments[1] + "." + Base64Url.Encode(sig);

        Action act = () => JwsParser.ParseCompact(tampered, _ => publicJwk, _crypto);
        act.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public void Xc20p_aead_kat_matches_in_both_directions()
    {
        using var fixture = Fixtures.LoadJson("generated", "xc20p.json");
        var kat = fixture.RootElement.GetProperty("aeadKat");
        var key = Convert.FromHexString(kat.GetProperty("keyHex").GetString()!);
        var nonce = Convert.FromHexString(kat.GetProperty("nonceHex").GetString()!);
        var aad = Encoding.ASCII.GetBytes(kat.GetProperty("aadAscii").GetString()!);
        var plaintext = Encoding.UTF8.GetBytes(kat.GetProperty("plaintextUtf8").GetString()!);

        var (ciphertext, tag) = _crypto.AeadEncrypt(JoseAlgorithms.XC20P, key, nonce, aad, plaintext);
        Convert.ToHexStringLower(ciphertext).Should().Be(kat.GetProperty("ciphertextHex").GetString());
        Convert.ToHexStringLower(tag).Should().Be(kat.GetProperty("tagHex").GetString());

        var recovered = _crypto.AeadDecrypt(JoseAlgorithms.XC20P, key, nonce, aad, ciphertext, tag);
        recovered.Should().Equal(plaintext);
    }

    [Fact]
    public void Xc20p_frozen_jwe_decrypts_to_the_frozen_plaintext()
    {
        using var fixture = Fixtures.LoadJson("generated", "xc20p.json");
        var frozen = fixture.RootElement.GetProperty("frozenJwe");
        var recipientPrivate = Fixtures.ToJwk(frozen.GetProperty("recipientPrivateKeyJwk"));
        var packed = JsonSerializer.Serialize(frozen.GetProperty("jweGeneralJson"));

        var result = JweParser.Parse(
            packed,
            new Envelopes.DictionarySecretsLookup([recipientPrivate]),
            senderKeys: null,
            _crypto);

        result.ContentEncryption.Should().Be("XC20P");
        result.Algorithm.Should().Be("ECDH-ES+A256KW");
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(frozen.GetProperty("plaintextUtf8").GetString());
    }

    [Fact]
    public void Xc20p_frozen_jwe_with_tampered_ciphertext_is_rejected()
    {
        using var fixture = Fixtures.LoadJson("generated", "xc20p.json");
        var frozen = fixture.RootElement.GetProperty("frozenJwe");
        var recipientPrivate = Fixtures.ToJwk(frozen.GetProperty("recipientPrivateKeyJwk"));
        var packed = JsonSerializer.Serialize(frozen.GetProperty("jweGeneralJson"));

        var idx = packed.IndexOf("\"ciphertext\":\"", StringComparison.Ordinal) + "\"ciphertext\":\"".Length;
        var bumped = packed[idx] == 'A' ? 'B' : 'A';
        var tampered = string.Concat(packed.AsSpan(0, idx), bumped.ToString(), packed.AsSpan(idx + 1));

        Action act = () => JweParser.Parse(
            tampered, new Envelopes.DictionarySecretsLookup([recipientPrivate]), null, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*AEAD decryption failed*");
    }
}
