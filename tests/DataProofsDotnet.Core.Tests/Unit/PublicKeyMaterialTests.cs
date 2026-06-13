using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>FR-8: Multikey and JWK intake, normalized to NetCrypto representations.</summary>
public class PublicKeyMaterialTests
{
    // The W3C fixture keys, decoded once.
    private static string EddsaFixtureMultikey()
        => Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "keyPair.json")
            .GetProperty("publicKeyMultibase").GetString()!;

    private static string P256FixtureMultikey()
        => Fx.Json("w3c", "vc-di-ecdsa", "spec", "p256KeyPair.json")
            .GetProperty("publicKeyMultibase").GetString()!;

    private static string P384FixtureMultikey()
        => Fx.Json("w3c", "vc-di-ecdsa", "spec", "p384KeyPair.json")
            .GetProperty("publicKeyMultibase").GetString()!;

    [Fact]
    public void FromMultikey_DecodesW3cFixtureKeys()
    {
        var ed25519 = PublicKeyMaterial.FromMultikey(EddsaFixtureMultikey());
        var p256 = PublicKeyMaterial.FromMultikey(P256FixtureMultikey());
        var p384 = PublicKeyMaterial.FromMultikey(P384FixtureMultikey());

        ed25519.KeyType.Should().Be(KeyType.Ed25519);
        ed25519.KeyBytes.Length.Should().Be(32);
        p256.KeyType.Should().Be(KeyType.P256);
        p256.KeyBytes.Length.Should().Be(33, "SEC1 compressed");
        p384.KeyType.Should().Be(KeyType.P384);
        p384.KeyBytes.Length.Should().Be(49, "SEC1 compressed");
    }

    [Fact]
    public void ToMultikey_RoundTrips()
    {
        var multikey = EddsaFixtureMultikey();

        PublicKeyMaterial.FromMultikey(multikey).ToMultikey().Should().Be(multikey);
        PublicKeyMaterial.FromMultikey(P384FixtureMultikey()).ToMultikey().Should().Be(P384FixtureMultikey());
    }

    [Fact]
    public void FromRaw_AcceptsCanonicalLengths_AndMatchesMultikeyDecoding()
    {
        var decoded = PublicKeyMaterial.FromMultikey(EddsaFixtureMultikey());

        var raw = PublicKeyMaterial.FromRaw(KeyType.Ed25519, decoded.KeyBytes.Span);

        raw.KeyBytes.ToArray().Should().Equal(decoded.KeyBytes.ToArray());
        raw.ToMultikey().Should().Be(EddsaFixtureMultikey());
    }

    [Fact]
    public void FromRaw_RejectsInvalidLengths()
    {
        FluentActions.Invoking(() => PublicKeyMaterial.FromRaw(KeyType.Ed25519, new byte[31]))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => PublicKeyMaterial.FromRaw(KeyType.P256, new byte[32]))
            .Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-multibase")]
    [InlineData("zzzzzz")]
    [InlineData("uMTIz")] // base64url multibase, not base58-btc Multikey
    public void FromMultikey_RejectsMalformedValues(string value)
        => FluentActions.Invoking(() => PublicKeyMaterial.FromMultikey(value))
            .Should().Throw<ArgumentException>();

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    public void JsonWebKey_RoundTrips(KeyType keyType)
    {
        var original = PublicKeyMaterial.FromRaw(keyType, Fx.SeedKey(0x31, keyType).PublicKey);

        var roundTripped = PublicKeyMaterial.FromJsonWebKey(original.ToJsonWebKey());

        roundTripped.KeyType.Should().Be(keyType);
        roundTripped.KeyBytes.ToArray().Should().Equal(original.KeyBytes.ToArray());
    }

    [Fact]
    public void FromJsonWebKey_RejectsNullAndMalformed()
    {
        FluentActions.Invoking(() => PublicKeyMaterial.FromJsonWebKey(null!))
            .Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => PublicKeyMaterial.FromJsonWebKey(new Microsoft.IdentityModel.Tokens.JsonWebKey()))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void KeyBytes_AreImmutableFromTheOutside()
    {
        var material = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey);
        var before = material.KeyBytes.ToArray();

        // ReadOnlyMemory prevents direct mutation; mutating the source array used for
        // construction must not affect the stored copy either.
        var source = Fx.SeedKey(0x01).PublicKey;
        var fromSource = PublicKeyMaterial.FromRaw(KeyType.Ed25519, source);
        source[0] ^= 0xFF;

        fromSource.KeyBytes.ToArray().Should().Equal(before);
    }
}
