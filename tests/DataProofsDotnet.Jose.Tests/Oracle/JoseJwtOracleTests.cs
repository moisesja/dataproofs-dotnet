using System.Text.Json;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Json;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;
using OracleJoseException = global::Jose.JoseException;
using OracleJweAlgorithm = global::Jose.JweAlgorithm;
using OracleJwt = global::Jose.JWT;
using OracleSettings = global::Jose.JwtSettings;

namespace DataProofsDotnet.Jose.Tests.Oracle;

/// <summary>
/// AC-3 step 3 — <c>jose-jwt</c> oracle cross-verification over the <b>programmatically
/// computed</b> intersection of {algorithms this library implements} ∩ {algorithms the
/// oracle's registry supports}. The oracle's registry is interrogated through
/// <see cref="OracleSettings"/>'s header-mapping methods — not hard-coded — and
/// <see cref="Every_shared_algorithm_is_cross_verified_in_both_directions"/> <b>fails if any
/// shared algorithm lacks a cross-check handler</b>. Algorithms outside the intersection
/// (EdDSA, ES256K, XC20P, ECDH-1PU+A256KW — absent from jose-jwt's closed enums) are covered
/// by the RFC / generated vectors of AC-3 step 1 instead.
/// </summary>
public sealed class JoseJwtOracleTests
{
    private static readonly JoseCryptoProvider _crypto = new();
    private static readonly OracleSettings _oracle = OracleJwt.DefaultSettings;
    private const string Payload = """{"hello":"oracle"}""";

    private static bool OracleSupportsJws(string headerValue)
    {
        try { return _oracle.Jws(_oracle.JwsAlgorithmFromHeader(headerValue)) is not null; }
        catch (Exception ex) when (ex is OracleJoseException or ArgumentException or InvalidOperationException) { return false; }
    }

    private static bool OracleSupportsKeyManagement(string headerValue)
    {
        try { return _oracle.Jwa(_oracle.JwaAlgorithmFromHeader(headerValue)) is not null; }
        catch (Exception ex) when (ex is OracleJoseException or ArgumentException or InvalidOperationException) { return false; }
    }

    private static bool OracleSupportsEncryption(string headerValue)
    {
        try { return _oracle.Jwe(_oracle.JweAlgorithmFromHeader(headerValue)) is not null; }
        catch (Exception ex) when (ex is OracleJoseException or ArgumentException or InvalidOperationException) { return false; }
    }

    private static IReadOnlyList<string> JwsIntersection()
        => JoseAlgorithms.SupportedSignatureAlgorithms.Where(OracleSupportsJws).ToArray();

    private static IReadOnlyList<string> KeyManagementIntersection()
        => JoseAlgorithms.SupportedKeyManagementAlgorithms.Where(OracleSupportsKeyManagement).ToArray();

    private static IReadOnlyList<string> EncryptionIntersection()
        => JoseAlgorithms.SupportedContentEncryptionAlgorithms.Where(OracleSupportsEncryption).ToArray();

    [Fact]
    public void Intersection_matches_the_prd_baseline_expectations()
    {
        // PRD AC-3 step 3: "currently at least ES256, ES384, A256GCM, A256CBC-HS512, A256KW,
        // and ECDH-ES+A256KW; EdDSA, ES256K, XC20P, ECDH-1PU+A256KW are outside it".
        JwsIntersection().Should().Contain(["ES256", "ES384"]).And.NotContain(["EdDSA", "ES256K"]);
        KeyManagementIntersection().Should().Contain(["A256KW", "ECDH-ES+A256KW"]).And.NotContain("ECDH-1PU+A256KW");
        EncryptionIntersection().Should().Contain(["A256GCM", "A256CBC-HS512"]).And.NotContain("XC20P");
    }

    [Fact]
    public async Task Every_shared_algorithm_is_cross_verified_in_both_directions()
    {
        // JWS: one handler per shared signature algorithm. A shared algorithm without a handler
        // fails the test by construction (the AC-3 "no uncovered shared algorithm" rule).
        foreach (var alg in JwsIntersection())
        {
            var keyType = alg switch
            {
                "ES256" => KeyType.P256,
                "ES384" => KeyType.P384,
                _ => throw Uncovered("JWS", alg),
            };
            await CrossCheckJws(alg, keyType);
        }

        // JWE: full (shared alg × shared enc) matrix, one handler per shared key-management
        // algorithm; both directions each.
        foreach (var alg in KeyManagementIntersection())
        {
            foreach (var enc in EncryptionIntersection())
            {
                switch (alg)
                {
                    case "A256KW":
                        CrossCheckA256Kw(enc);
                        break;
                    case "ECDH-ES+A256KW":
                        CrossCheckEcdhEsA256Kw(enc);
                        break;
                    default:
                        throw Uncovered("JWE key-management", alg);
                }
            }
        }

        static Xunit.Sdk.XunitException Uncovered(string family, string alg) => new(
            $"Shared {family} algorithm '{alg}' has no oracle cross-check handler. AC-3 step 3 requires every " +
            "algorithm in the computed intersection to be cross-verified in both directions — add a handler.");
    }

    private static async Task CrossCheckJws(string alg, KeyType keyType)
    {
        var km = TestKeyMaterial.Generate(keyType, $"oracle-{alg}");
        var oracleAlg = _oracle.JwsAlgorithmFromHeader(alg);

        // (a) produced by DataProofsDotnet.Jose → verifies in jose-jwt
        var ours = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(Payload), km.Signer);
        var decodedByOracle = OracleJwt.Decode(ours, ToOracleEcdsa(km.PublicJwk, includePrivate: false), oracleAlg);
        decodedByOracle.Should().Be(Payload, because: $"a {alg} JWS we produce must verify in jose-jwt");

        // (b) produced by jose-jwt → verifies here
        var theirs = OracleJwt.Encode(Payload, ToOracleEcdsa(km.PrivateJwk, includePrivate: true), oracleAlg);
        var result = JwsParser.ParseCompact(theirs, _ => km.PublicJwk, _crypto);
        result.SignatureAlgorithm.Should().Be(alg);
        Encoding.UTF8.GetString(result.PayloadBytes).Should().Be(Payload, because: $"a {alg} JWS jose-jwt produces must verify here");
    }

    private static void CrossCheckA256Kw(string enc)
    {
        var kekBytes = RandomNumberGenerator.GetBytes(32);
        var kekJwk = new Jwk { Kty = "oct", K = Base64Url.Encode(kekBytes), Kid = "oracle-kek" };
        var oracleEnc = _oracle.JweAlgorithmFromHeader(enc);

        // (a) ours → oracle
        var ours = JweBuilder.BuildCompactA256Kw(Encoding.UTF8.GetBytes(Payload), kekJwk, enc, _crypto);
        OracleJwt.Decode(ours, kekBytes, OracleJweAlgorithm.A256KW, oracleEnc)
            .Should().Be(Payload, because: $"an A256KW/{enc} JWE we produce must decrypt in jose-jwt");

        // (b) oracle → ours
        var theirs = OracleJwt.Encode(Payload, kekBytes, OracleJweAlgorithm.A256KW, oracleEnc);
        var result = JweParser.ParseCompact(theirs, kekJwk, null, _crypto);
        result.Algorithm.Should().Be("A256KW");
        result.ContentEncryption.Should().Be(enc);
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Payload, because: $"an A256KW/{enc} JWE jose-jwt produces must decrypt here");
    }

    private static void CrossCheckEcdhEsA256Kw(string enc)
    {
        var km = TestKeyMaterial.Generate(KeyType.P256, "oracle-ecdh");
        var oracleEnc = _oracle.JweAlgorithmFromHeader(enc);

        // (a) ours → oracle
        var ours = JweBuilder.BuildCompactEcdhEsA256Kw(Encoding.UTF8.GetBytes(Payload), km.PublicJwk, enc, _crypto);
        using (var recipient = ToOracleEcdh(km.PrivateJwk, includePrivate: true))
        {
            OracleJwt.Decode(ours, recipient, OracleJweAlgorithm.ECDH_ES_A256KW, oracleEnc)
                .Should().Be(Payload, because: $"an ECDH-ES+A256KW/{enc} JWE we produce must decrypt in jose-jwt");
        }

        // (b) oracle → ours
        string theirs;
        using (var recipientPublic = ToOracleEcdh(km.PublicJwk, includePrivate: false))
        {
            theirs = OracleJwt.Encode(Payload, recipientPublic, OracleJweAlgorithm.ECDH_ES_A256KW, oracleEnc);
        }
        var result = JweParser.ParseCompact(theirs, km.PrivateJwk, null, _crypto);
        result.Algorithm.Should().Be("ECDH-ES+A256KW");
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Payload, because: $"an ECDH-ES+A256KW/{enc} JWE jose-jwt produces must decrypt here");
    }

    // jose-jwt key adapters (test-side only; BCL crypto types are permitted in tests — the
    // AC-6 NetCrypto-only rule governs src/ exclusively).

    private static ECDsa ToOracleEcdsa(Jwk jwk, bool includePrivate)
        => ECDsa.Create(ToEcParameters(jwk, includePrivate));

    private static ECDiffieHellman ToOracleEcdh(Jwk jwk, bool includePrivate)
        => ECDiffieHellman.Create(ToEcParameters(jwk, includePrivate));

    private static ECParameters ToEcParameters(Jwk jwk, bool includePrivate) => new()
    {
        Curve = jwk.Crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => throw new NotSupportedException($"No oracle curve mapping for '{jwk.Crv}'."),
        },
        Q = new ECPoint
        {
            X = Base64Url.Decode(jwk.X!),
            Y = Base64Url.Decode(jwk.Y!),
        },
        D = includePrivate ? Base64Url.Decode(jwk.D!) : null,
    };

    // Keep JoseJson referenced so the serializer options stay aligned if a Jwk-JSON bridge is
    // ever needed for the oracle (jose-jwt's Jwk.FromJson path).
    private static string SerializeJwk(Jwk jwk) => JsonSerializer.Serialize(jwk, JoseJson.Default);

    [Fact]
    public void Jwk_serialization_for_the_oracle_omits_null_members()
    {
        var jwk = new Jwk { Kty = "EC", Crv = "P-256", X = "AQ", Y = "Ag" };
        SerializeJwk(jwk).Should().NotContain("null");
    }
}
