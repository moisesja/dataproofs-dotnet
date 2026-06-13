using System.Text.Json;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 1 — RFC 7520 (JOSE cookbook) examples, v1-relevant algorithms
/// (fixtures: <c>fixtures/ietf/rfc7520/</c>; vendoring rationale in its PROVENANCE.md).
/// <para>
/// <b>Enumeration of consumed vs excluded (required by AC-3):</b> the cookbook's only
/// fully-v1-algorithm example is the Ed25519 JWS (consumed positively, byte-compared — Ed25519
/// is deterministic). Every other vendored example uses an algorithm outside the v1 set
/// (ES512, the AES-128 family, <c>dir</c>, direct ECDH-ES, JWE <c>aad</c>) and is consumed in
/// the <b>negative direction</b>: fed through the public parsers and asserted to produce the
/// documented <see cref="JoseException"/> failure — never an unhandled exception (AC-3 step 7
/// convention). <see cref="Every_vendored_fixture_is_enumerated_as_consumed_or_negative"/>
/// mechanically guards that no vendored file escapes this enumeration.
/// </para>
/// </summary>
public sealed class Rfc7520CookbookTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    /// <summary>Positively consumed (creation byte-compare + verify direction).</summary>
    private static readonly string[] ConsumedPositive =
    [
        "curve25519/eddsa_ed25519_jws.json",
    ];

    /// <summary>Consumed as negative vectors: documented rejection of out-of-scope algorithms/features.</summary>
    private static readonly string[] ConsumedNegative =
    [
        "jws/4_3.ecdsa_signature.json",                                                       // ES512 — out of v1 scope (PRD FR-13)
        "jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json", // A128GCM/A128KW — no NetCrypto primitive
        "jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json",                    // direct ECDH-ES — omitted (jwe-algorithm-omissions.md)
        "jwe/5_6.direct_encryption_using_aes-gcm.json",                                       // dir — omitted (jwe-algorithm-omissions.md)
        "jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json",                               // A128KW/A128GCM — no NetCrypto primitive
        "jwe/5_10.including_additional_authentication_data.json",                             // JWE 'aad' member — rejected fail-closed
        "jwe/5_11.protecting_specific_header_fields.json",                                    // A128KW/A128GCM — no NetCrypto primitive
        "jwe/5_12.protecting_content_only.json",                                              // no protected header — rejected
        "curve25519/ecdh-es_x25519.json",                                                     // direct ECDH-ES — omitted; X25519 ECDH coverage: RFC 8037 A.6
    ];

    [Fact]
    public void Every_vendored_fixture_is_enumerated_as_consumed_or_negative()
    {
        var root = Fixtures.PathOf("ietf", "rfc7520");
        var actual = Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories)
            .Select(p => Path.GetRelativePath(root, p).Replace('\\', '/'))
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        var enumerated = ConsumedPositive.Concat(ConsumedNegative)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        actual.Should().Equal(enumerated,
            because: "AC-3 requires enumerating consumed vs excluded cookbook fixtures; an unaccounted file means the enumeration is stale.");
    }

    [Fact]
    public async Task Ed25519_jws_creation_is_byte_identical_to_the_cookbook()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7520", "curve25519", "eddsa_ed25519_jws.json");
        var root = fixture.RootElement;
        var input = root.GetProperty("input");
        var key = Fixtures.ToJwk(input.GetProperty("key"));
        var payload = Encoding.UTF8.GetBytes(input.GetProperty("payload").GetString()!);
        var output = root.GetProperty("output");

        var pair = new DefaultKeyGenerator().FromPrivateKey(KeyType.Ed25519, Base64Url.Decode(key.D!));
        var signer = new JwsSigner(new KeyPairSigner(pair, new DefaultCryptoProvider())); // no kid — cookbook header is {"alg":"EdDSA"}

        var compact = await JwsBuilder.BuildCompactAsync(payload, signer);
        compact.Should().Be(output.GetProperty("compact").GetString(),
            because: "Ed25519 signing is deterministic; the cookbook publishes the exact compact JWS.");

        // Flattened JSON serialization: byte-identical to the cookbook's json_flat (the builder
        // omits the unprotected header for a kid-less signer and orders members per the spec).
        var flattened = await JwsBuilder.BuildJsonAsync(payload, [signer]);
        flattened.Should().Be(JsonSerializer.Serialize(output.GetProperty("json_flat")));
    }

    [Fact]
    public void Ed25519_jws_all_three_serializations_verify()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7520", "curve25519", "eddsa_ed25519_jws.json");
        var root = fixture.RootElement;
        var publicJwk = Fixtures.ToJwk(root.GetProperty("input").GetProperty("key"));
        publicJwk.D = null; // verify with the public half only
        var output = root.GetProperty("output");
        var expectedPayload = root.GetProperty("input").GetProperty("payload").GetString();

        var fromCompact = JwsParser.ParseCompact(output.GetProperty("compact").GetString()!, _ => publicJwk, _crypto);
        Encoding.UTF8.GetString(fromCompact.PayloadBytes).Should().Be(expectedPayload);

        var fromGeneral = JwsParser.Parse(JsonSerializer.Serialize(output.GetProperty("json")), _ => publicJwk, _crypto);
        Encoding.UTF8.GetString(fromGeneral.PayloadBytes).Should().Be(expectedPayload);

        var fromFlattened = JwsParser.Parse(JsonSerializer.Serialize(output.GetProperty("json_flat")), _ => publicJwk, _crypto);
        Encoding.UTF8.GetString(fromFlattened.PayloadBytes).Should().Be(expectedPayload);
        fromFlattened.SignatureAlgorithm.Should().Be("EdDSA");
    }

    [Fact]
    public void Es512_jws_is_rejected_with_the_documented_out_of_scope_failure()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7520", "jws", "4_3.ecdsa_signature.json");
        var root = fixture.RootElement;
        var publicJwk = Fixtures.ToJwk(root.GetProperty("input").GetProperty("key"));
        publicJwk.D = null;
        var compact = root.GetProperty("output").GetProperty("compact").GetString()!;

        Action act = () => JwsParser.ParseCompact(compact, _ => publicJwk, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*not supported*",
            because: "ES512 (P-521) is out of v1 scope (PRD FR-13); the parser must surface the documented failure, never an unhandled dispatch exception.");
    }

    [Theory]
    [InlineData("jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json")]
    [InlineData("jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json")]
    public void A128_family_compact_jwes_are_rejected_as_unsupported_enc(string relativePath)
    {
        using var fixture = Fixtures.LoadJson(["ietf", "rfc7520", .. relativePath.Split('/')]);
        var compact = fixture.RootElement.GetProperty("output").GetProperty("compact").GetString()!;
        var dummyKey = new Jwk { Kty = "oct", K = Base64Url.Encode(new byte[32]), Kid = "k" };

        Action act = () => JweParser.ParseCompact(compact, dummyKey, null, _crypto);

        act.Should().Throw<JoseCryptoException>().WithMessage("*Unsupported JWE 'enc'*",
            because: "the AES-128 family has no NetCrypto primitive (jwe-algorithm-omissions.md, 'Not backable'); rejection happens before any key use.");
    }

    [Theory]
    [InlineData("jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json")]
    [InlineData("jwe/5_6.direct_encryption_using_aes-gcm.json")]
    [InlineData("curve25519/ecdh-es_x25519.json")]
    public void Direct_mode_compact_jwes_are_rejected_with_a_documented_failure(string relativePath)
    {
        // Direct key agreement / direct encryption produce an empty encrypted-key segment;
        // direct modes are deliberate omissions (jwe-algorithm-omissions.md).
        using var fixture = Fixtures.LoadJson(["ietf", "rfc7520", .. relativePath.Split('/')]);
        var compact = fixture.RootElement.GetProperty("output").GetProperty("compact").GetString()!;
        var dummyKey = new Jwk { Kty = "oct", K = Base64Url.Encode(new byte[32]), Kid = "k" };

        Action act = () => JweParser.ParseCompact(compact, dummyKey, null, _crypto);

        act.Should().Throw<MalformedJoseException>().WithMessage("*encrypted-key segment is empty*");
    }

    [Fact]
    public void Jwe_aad_member_is_rejected_fail_closed()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7520", "jwe", "5_10.including_additional_authentication_data.json");
        var json = JsonSerializer.Serialize(fixture.RootElement.GetProperty("output").GetProperty("json"));
        var resolver = new DictionaryResolver();

        Action act = () => JweParser.Parse(json, resolver, null, _crypto);

        act.Should().Throw<MalformedJoseException>().WithMessage("*'aad'*",
            because: "the JSON-serialization 'aad' member changes the AAD construction; ignoring it would mis-verify, so the parser fails closed.");
    }

    [Fact]
    public void Jwe_without_protected_header_is_rejected()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7520", "jwe", "5_12.protecting_content_only.json");
        var json = JsonSerializer.Serialize(fixture.RootElement.GetProperty("output").GetProperty("json"));
        var resolver = new DictionaryResolver();

        Action act = () => JweParser.Parse(json, resolver, null, _crypto);

        act.Should().Throw<MalformedJoseException>().WithMessage("*protected*");
    }

    [Fact]
    public void Jwe_with_split_headers_and_a128_family_is_rejected_with_a_documented_failure()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7520", "jwe", "5_11.protecting_specific_header_fields.json");
        var json = JsonSerializer.Serialize(fixture.RootElement.GetProperty("output").GetProperty("json"));
        var resolver = new DictionaryResolver();

        Action act = () => JweParser.Parse(json, resolver, null, _crypto);

        act.Should().Throw<JoseException>(
            because: "every parser failure must be a documented JoseException subtype, never an unhandled exception (AC-3 step 7).");
    }

    private sealed class DictionaryResolver : IJweRecipientKeyResolver
    {
        public Jwk? TryGet(string kid) => null;
        public IReadOnlyList<string> FindPresent(IEnumerable<string> kids) => [];
    }
}
