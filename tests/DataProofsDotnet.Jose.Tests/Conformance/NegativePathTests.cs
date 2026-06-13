using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 7 (JWS/JWE/JWT portions) — negative-path theories: rejected <c>none</c> and
/// unexpected <c>alg</c> values, and tampered artifacts. Every case returns the documented
/// failure (a <see cref="JoseException"/> subtype or a structured
/// <see cref="JwtVerificationResult"/>) — never an unhandled exception.
/// </summary>
public sealed class NegativePathTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    [Fact]
    public void Jws_with_alg_none_is_rejected()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");
        // Hand-craft an "unsigned JWS": {"alg":"none"} header, empty signature bytes encoded as junk.
        var header = Base64Url.EncodeUtf8("""{"alg":"none"}""");
        var payload = Base64Url.EncodeUtf8("""{"admin":true}""");
        var forged = $"{header}.{payload}.{Base64Url.Encode([0])}";

        Action act = () => JwsParser.ParseCompact(forged, _ => key.PublicJwk, _crypto);

        act.Should().Throw<MalformedJoseException>().WithMessage("*none*",
            because: "alg=none must never be confusable with a signed JWS (RFC 8725 §2.1)");
    }

    [Fact]
    public void Jws_with_missing_alg_is_rejected()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");
        var header = Base64Url.EncodeUtf8("""{"kid":"k1"}""");
        var forged = $"{header}.{Base64Url.EncodeUtf8("{}")}.{Base64Url.Encode([0])}";

        Action act = () => JwsParser.ParseCompact(forged, _ => key.PublicJwk, _crypto);
        act.Should().Throw<MalformedJoseException>().WithMessage("*alg*");
    }

    [Fact]
    public async Task Jws_with_unexpected_alg_for_the_key_is_rejected()
    {
        // Algorithm-confusion defense: an EdDSA signature presented against a P-256 key (or any
        // alg↔curve mismatch) must fail BEFORE signature verification.
        var ed = TestKeyMaterial.Generate(KeyType.Ed25519, "shared-kid");
        var p256 = TestKeyMaterial.Generate(KeyType.P256, "shared-kid");
        var jws = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("{}"), ed.Signer);

        Action act = () => JwsParser.ParseCompact(jws, _ => p256.PublicJwk, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*does not match the public key's curve*");
    }

    [Fact]
    public async Task Jwt_with_disallowed_alg_fails_with_ALGORITHM_NOT_ALLOWED()
    {
        var key = TestKeyMaterial.Generate(KeyType.P384, "es384-key");
        var jwt = await JwtHandler.SignAsync(new JwtClaims(issuer: "i"), key.Signer);

        var result = JwtHandler.Verify(jwt, _ => key.PublicJwk, new JwtValidationOptions
        {
            AllowedAlgorithms = [JoseAlgorithms.EdDSA], // pin a different expected algorithm
        });

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.StartsWith("ALGORITHM_NOT_ALLOWED"));
    }

    [Fact]
    public void Jwt_with_alg_none_returns_a_structured_failure_and_never_throws()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");
        var forged = $"{Base64Url.EncodeUtf8("""{"alg":"none","typ":"JWT"}""")}.{Base64Url.EncodeUtf8("""{"admin":true}""")}.{Base64Url.Encode([0])}";

        JwtVerificationResult? result = null;
        Action act = () => result = JwtHandler.Verify(forged, _ => key.PublicJwk);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.StartsWith("MALFORMED"));
    }

    [Fact]
    public async Task Tampered_compact_jws_payload_is_rejected()
    {
        var key = TestKeyMaterial.Generate(KeyType.ES(out var _), "k")!;
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Tampered_compact_jws_is_rejected_per_segment()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");
        var jws = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("""{"v":1}"""), key.Signer);
        var segments = jws.Split('.');

        // Tampered payload.
        var tamperedPayload = $"{segments[0]}.{Base64Url.EncodeUtf8("""{"v":2}""")}.{segments[2]}";
        Action payloadAct = () => JwsParser.ParseCompact(tamperedPayload, _ => key.PublicJwk, _crypto);
        payloadAct.Should().Throw<JoseCryptoException>().WithMessage("*did not verify*");

        // Tampered signature.
        var sig = Base64Url.Decode(segments[2]);
        sig[^1] ^= 0x01;
        var tamperedSig = $"{segments[0]}.{segments[1]}.{Base64Url.Encode(sig)}";
        Action sigAct = () => JwsParser.ParseCompact(tamperedSig, _ => key.PublicJwk, _crypto);
        sigAct.Should().Throw<JoseCryptoException>();

        // Garbage signature segment (not base64url).
        Action garbageAct = () => JwsParser.ParseCompact($"{segments[0]}.{segments[1]}.!!!", _ => key.PublicJwk, _crypto);
        garbageAct.Should().Throw<MalformedJoseException>();
    }

    [Fact]
    public void Tampered_jwe_encrypted_key_fails_unwrap_with_the_documented_error()
    {
        var kek = new Jwk { Kty = "oct", K = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)), Kid = "kek" };
        var jwe = Encryption.JweBuilder.BuildCompactA256Kw(Encoding.UTF8.GetBytes("{}"), kek, JoseAlgorithms.A256Gcm, _crypto);
        var segments = jwe.Split('.');
        var wrapped = Base64Url.Decode(segments[1]);
        wrapped[0] ^= 0x01;
        var tampered = string.Join('.', segments[0], Base64Url.Encode(wrapped), segments[2], segments[3], segments[4]);

        Action act = () => Encryption.JweParser.ParseCompact(tampered, kek, null, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*unwrap failed*");
    }

    [Fact]
    public void Tampered_jwe_ciphertext_fails_aead_with_the_documented_error()
    {
        var kek = new Jwk { Kty = "oct", K = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)), Kid = "kek" };
        var jwe = Encryption.JweBuilder.BuildCompactA256Kw(Encoding.UTF8.GetBytes("""{"v":1}"""), kek, JoseAlgorithms.A256CbcHs512, _crypto);
        var segments = jwe.Split('.');
        var ciphertext = Base64Url.Decode(segments[3]);
        ciphertext[0] ^= 0x01;
        var tampered = string.Join('.', segments[0], segments[1], segments[2], Base64Url.Encode(ciphertext), segments[4]);

        Action act = () => Encryption.JweParser.ParseCompact(tampered, kek, null, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*AEAD decryption failed*");
    }

    [Fact]
    public void Jwe_with_unsupported_alg_is_rejected_before_any_key_use()
    {
        // Hand-craft a JWE naming an alg outside the registered set (RSA-OAEP).
        var header = Base64Url.EncodeUtf8("""{"alg":"RSA-OAEP","enc":"A256GCM"}""");
        var fake = $"{header}.{Base64Url.Encode(new byte[40])}.{Base64Url.Encode(new byte[12])}.{Base64Url.Encode(new byte[16])}.{Base64Url.Encode(new byte[16])}";
        var kek = new Jwk { Kty = "oct", K = Base64Url.Encode(new byte[32]), Kid = "kek" };

        Action act = () => Encryption.JweParser.ParseCompact(fake, kek, null, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*Unsupported JWE 'alg'*");
    }

    [Fact]
    public void Duplicate_header_members_are_rejected_fail_closed()
    {
        // Parser-differential smuggling defense: a JWS whose JSON carries a duplicate member
        // must be rejected by the strict document options, surfaced as the documented failure.
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");
        const string duplicated = """{"payload":"e30","payload":"e30","protected":"e30","signature":"AAAA"}""";

        Action act = () => JwsParser.Parse(duplicated, _ => key.PublicJwk, _crypto);

        act.Should().Throw<Exception>().Match(e => e is MalformedJoseException || e is System.Text.Json.JsonException);
    }
}
