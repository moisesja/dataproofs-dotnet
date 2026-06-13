using DataProofsDotnet.Jose.Json;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 2 — RFC 7638 JWK thumbprints (FR-15): byte-equality against the RFC 7638 §3.1
/// worked example and the RFC 8037 A.3 Ed25519 example, plus thumbprint stability across
/// Multikey ↔ JWK round-trips.
/// </summary>
public sealed class JwkThumbprintTests
{
    [Fact]
    public void Rfc7638_section_3_1_rsa_thumbprint_is_byte_identical()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc7638", "section3-1-rsa-jwk-thumbprint.json");
        var root = fixture.RootElement;
        var jwk = Fixtures.ToJwk(root.GetProperty("jwk"));

        var thumbprint = JwkThumbprint.Compute(jwk);

        thumbprint.Should().Equal(Hex.Decode(root.GetProperty("sha256Hex").GetString()!),
            because: "RFC 7638 §3.1 publishes the exact SHA-256 thumbprint bytes.");
        JwkThumbprint.ComputeBase64Url(jwk).Should().Be(root.GetProperty("thumbprintB64url").GetString());
        JwkThumbprint.ComputeKid(jwk).Should().Be(root.GetProperty("thumbprintB64url").GetString(),
            because: "RFC 7638 §3.1 defines the kid convention as the base64url thumbprint.");
    }

    [Fact]
    public void Rfc8037_a3_ed25519_thumbprint_is_byte_identical()
    {
        using var fixture = Fixtures.LoadJson("ietf", "rfc8037", "a3-ed25519-jwk-thumbprint.json");
        var root = fixture.RootElement;
        var jwk = Fixtures.ToJwk(root.GetProperty("publicKeyJwk"));

        JwkThumbprint.Compute(jwk).Should().Equal(Hex.Decode(root.GetProperty("sha256Hex").GetString()!));
        JwkThumbprint.ComputeBase64Url(jwk).Should().Be(root.GetProperty("thumbprintB64url").GetString());
    }

    [Fact]
    public void Canonical_member_serialization_matches_the_rfc_worked_examples()
    {
        // The canonical JSON the thumbprint hashes must match the RFC's published string —
        // lexicographic member order, no whitespace (JCS-consistent serialization, FR-15).
        using var okp = Fixtures.LoadJson("ietf", "rfc8037", "a3-ed25519-jwk-thumbprint.json");
        var okpJwk = Fixtures.ToJwk(okp.RootElement.GetProperty("publicKeyJwk"));
        var canonical = Encoding.UTF8.GetString(Hash(okpJwk));
        canonical.Should().Be(okp.RootElement.GetProperty("thumbprintCanonicalJson").GetString());

        using var rsa = Fixtures.LoadJson("ietf", "rfc7638", "section3-1-rsa-jwk-thumbprint.json");
        var rsaJwk = Fixtures.ToJwk(rsa.RootElement.GetProperty("jwk"));
        Encoding.UTF8.GetString(Hash(rsaJwk)).Should().Be(rsa.RootElement.GetProperty("thumbprintCanonicalJson").GetString());

        static byte[] Hash(Jwk jwk)
        {
            // Reproduce the canonical bytes via the production writer over the required members
            // (mirrors JwkThumbprint's internals; asserts the exact published string).
            var node = new System.Text.Json.Nodes.JsonObject();
            if (jwk.Kty == "RSA")
            {
                node["e"] = jwk.AdditionalData!["e"].GetString();
                node["kty"] = "RSA";
                node["n"] = jwk.AdditionalData!["n"].GetString();
            }
            else
            {
                node["crv"] = jwk.Crv;
                node["kty"] = jwk.Kty;
                node["x"] = jwk.X;
            }
            return DeterministicJsonWriter.WriteUtf8(node);
        }
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    public void Thumbprint_is_stable_across_multikey_jwk_round_trips(KeyType keyType)
    {
        var pair = new DefaultKeyGenerator().Generate(keyType);
        var jwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, kid: "ignored-by-thumbprint");

        var original = JwkThumbprint.ComputeBase64Url(jwk);

        var multikey = JwkConversion.ToMultikey(jwk);
        var roundTripped = JwkConversion.FromMultikey(multikey);
        var afterRoundTrip = JwkThumbprint.ComputeBase64Url(roundTripped);

        afterRoundTrip.Should().Be(original,
            because: "AC-3 step 2: a Multikey↔JWK round-trip must not change the RFC 7638 thumbprint.");

        // Second hop for stability.
        JwkConversion.ToMultikey(roundTripped).Should().Be(multikey);
    }

    [Fact]
    public void Oct_thumbprint_uses_k_and_kty_members()
    {
        // RFC 7638 §3.2: oct keys hash {"k":…,"kty":"oct"}. Sanity-pin the member selection.
        var jwk = new Jwk { Kty = "oct", K = Base64Url.Encode(new byte[32]) };
        var expected = Hash256($"{{\"k\":\"{jwk.K}\",\"kty\":\"oct\"}}");
        JwkThumbprint.Compute(jwk).Should().Equal(expected);

        static byte[] Hash256(string canonical) => NetCrypto.Hash.Sha256(Encoding.UTF8.GetBytes(canonical));
    }

    [Fact]
    public void Missing_required_member_is_a_documented_failure()
    {
        var jwk = new Jwk { Kty = "EC", Crv = "P-256", X = "AAAA" }; // no 'y'
        Action act = () => JwkThumbprint.Compute(jwk);
        act.Should().Throw<MalformedJoseException>().WithMessage("*'y'*");
    }
}
