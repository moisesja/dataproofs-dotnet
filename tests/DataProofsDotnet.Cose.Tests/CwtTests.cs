using DataProofsDotnet.Cose.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Cose.Tests;

/// <summary>
/// AC-4 CWT conformance against RFC 8392 Appendix A (<c>tests/fixtures/ietf/rfc8392/</c>):
/// the A.1 claims set decoded and asserted claim by claim, the A.3 ES256-signed CWT verified
/// with the A.2.3 key, exp/nbf boundary and clock-skew handling, the out-of-scope A.4–A.7
/// structures rejected with documented codes, and construction round-trips.
/// </summary>
public sealed class CwtTests
{
    // RFC 8392 Appendix A.1 claim values.
    private const string Issuer = "coap://as.example.com";
    private const string Subject = "erikw";
    private const string Audience = "coap://light.example.com";
    private const long Exp = 1444064944;
    private const long Nbf = 1443944944;
    private const long Iat = 1443944944;

    /// <summary>A validation instant inside the A.1 validity window (nbf ≤ t &lt; exp).</summary>
    private static readonly DateTimeOffset InsideWindow = DateTimeOffset.FromUnixTimeSeconds(1444000000);

    /// <summary>The RFC 8392 A.2.3 ECDSA P-256 key as an uncompressed SEC1 point (0x04‖X‖Y).</summary>
    private static byte[] A23PublicKey =>
    [
        0x04,
        .. Fixtures.Hex("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
        .. Fixtures.Hex("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
    ];

    private static byte[] A1ClaimsSet => Fixtures.HexFile("ietf", "rfc8392", "a1-claims-set.hex.txt");

    private static byte[] A3SignedCwt => Fixtures.HexFile("ietf", "rfc8392", "a3-signed-cwt.hex.txt");

    private static void AssertA1Claims(CwtClaims claims)
    {
        claims.Issuer.Should().Be(Issuer);
        claims.Subject.Should().Be(Subject);
        claims.Audience.Should().Be(Audience);
        claims.ExpirationTime.Should().Be(DateTimeOffset.FromUnixTimeSeconds(Exp));
        claims.NotBefore.Should().Be(DateTimeOffset.FromUnixTimeSeconds(Nbf));
        claims.IssuedAt.Should().Be(DateTimeOffset.FromUnixTimeSeconds(Iat));
        claims.CwtId!.Value.ToArray().Should().Equal(Fixtures.Hex("0b71"));
    }

    // ----- manifest -----

    /// <summary>
    /// Guards against silently dropped fixtures: 9 artifacts × (hex + diag) per PROVENANCE.md.
    /// A.2.1/A.2.2 (symmetric keys) and A.4–A.7 are consumed only as negative/structural inputs
    /// here — MAC and encryption are outside the v1 COSE scope (PRD §6/FR-19).
    /// </summary>
    [Fact]
    public void VendoredRfc8392FixtureSetMatchesProvenance()
    {
        string root = Fixtures.PathOf("ietf", "rfc8392");
        string[] files = Directory
            .EnumerateFiles(root)
            .Select(Path.GetFileName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray()!;

        files.Where(name => name!.EndsWith(".hex.txt", StringComparison.Ordinal)).Should().HaveCount(9);
        files.Where(name => name!.EndsWith(".diag.txt", StringComparison.Ordinal)).Should().HaveCount(9);
        files.Should().Contain("PROVENANCE.md");
    }

    // ----- Appendix A.1: bare claims set -----

    [Fact]
    public void A1ClaimsSetDecodes()
    {
        CwtClaims claims = Cwt.DecodeClaims(A1ClaimsSet);
        AssertA1Claims(claims);
    }

    [Fact]
    public async Task A1ClaimsSetReEncodesByteExactly()
    {
        // Deterministic emission (NFR-5): integer claim keys 1–7 ascending, integer NumericDates —
        // re-encoding the decoded A.1 claims must reproduce the RFC bytes exactly. Asserted
        // through the public API by round-tripping the claims through a signed CWT's payload.
        CwtClaims claims = Cwt.DecodeClaims(A1ClaimsSet);
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        byte[] cwt = await Cwt.SignAsync(claims, signer, new CwtSignOptions { Algorithm = CoseAlgorithm.EdDsa });

        CoseSign1.Decode(cwt).Payload!.Value.ToArray().Should().Equal(A1ClaimsSet);
    }

    // ----- Appendix A.3: signed CWT verified with the RFC key -----

    [Fact]
    public void A3SignedCwtVerifiesWithRfcKey()
    {
        CwtVerificationResult result = Cwt.Verify(
            A3SignedCwt,
            KeyType.P256,
            A23PublicKey,
            new CwtValidationOptions { ValidationTime = InsideWindow });

        result.Verified.Should().BeTrue(result.Failure?.Message);
        AssertA1Claims(result.Claims!);
    }

    [Fact]
    public void A3WithCwtTagPrefixVerifies()
    {
        // RFC 8392 §6: 61(18(…)) must also be accepted on intake.
        byte[] tagged = TestCose.PrependTag(61, A3SignedCwt);

        Cwt.Verify(tagged, KeyType.P256, A23PublicKey, new CwtValidationOptions { ValidationTime = InsideWindow })
            .Verified.Should().BeTrue();
    }

    [Fact]
    public void A3WithWrongKeyFails()
    {
        KeyPair otherKey = TestCose.KeyGenerator.Generate(KeyType.P256);

        CwtVerificationResult result = Cwt.Verify(
            A3SignedCwt,
            KeyType.P256,
            otherKey.PublicKey,
            new CwtValidationOptions { ValidationTime = InsideWindow });

        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
        result.Claims.Should().BeNull("claims must not be surfaced from an unverified token");
    }

    [Fact]
    public void A3TamperedPayloadFails()
    {
        // Flip a byte inside the embedded claims payload (the issuer string region).
        byte[] tampered = TestCose.FlipByte(A3SignedCwt, 30);

        Cwt.Verify(tampered, KeyType.P256, A23PublicKey, new CwtValidationOptions { ValidationTime = InsideWindow })
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    // ----- exp / nbf boundaries and clock skew (RFC 8392 §3.1.4–3.1.5) -----

    public static TheoryData<string, long, long, bool, CoseVerificationErrorCode?> TimeValidationCases => new()
    {
        // description, validation time (epoch s), skew (s), expect verified, expected code
        { "inside the window", 1444000000, 0, true, null },
        { "one second before exp", Exp - 1, 0, true, null },
        { "exactly at exp (exp is exclusive)", Exp, 0, false, CoseVerificationErrorCode.Expired },
        { "after exp", Exp + 30, 0, false, CoseVerificationErrorCode.Expired },
        { "after exp but within skew", Exp + 30, 60, true, null },
        { "after exp beyond skew", Exp + 90, 60, false, CoseVerificationErrorCode.Expired },
        { "exactly at nbf (nbf is inclusive)", Nbf, 0, true, null },
        { "one second before nbf", Nbf - 1, 0, false, CoseVerificationErrorCode.NotYetValid },
        { "before nbf but within skew", Nbf - 30, 60, true, null },
        { "before nbf beyond skew", Nbf - 90, 60, false, CoseVerificationErrorCode.NotYetValid },
    };

    [Theory]
    [MemberData(nameof(TimeValidationCases))]
    public void ExpAndNbfValidationRespectsClockSkew(
        string description, long validationTime, long skewSeconds, bool expectVerified, CoseVerificationErrorCode? expectedCode)
    {
        CwtVerificationResult result = Cwt.Verify(
            A3SignedCwt,
            KeyType.P256,
            A23PublicKey,
            new CwtValidationOptions
            {
                ValidationTime = DateTimeOffset.FromUnixTimeSeconds(validationTime),
                ClockSkew = TimeSpan.FromSeconds(skewSeconds),
            });

        result.Verified.Should().Be(expectVerified, description);
        if (expectedCode is { } code)
        {
            result.Failure!.Code.Should().Be(code, description);
            result.Claims.Should().NotBeNull("the signature verified; only time validation failed");
        }
    }

    [Fact]
    public void NegativeClockSkewIsMisconfiguration()
    {
        Action act = () => Cwt.Verify(
            A3SignedCwt,
            KeyType.P256,
            A23PublicKey,
            new CwtValidationOptions { ClockSkew = TimeSpan.FromSeconds(-1) });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    // ----- Appendix A.4–A.7: structures outside v1 scope, each with a documented rejection -----

    public static TheoryData<string, string, CoseVerificationErrorCode> OutOfScopeCwts => new()
    {
        // A.4 is 61(17(…)): a MACed CWT (COSE_Mac0) behind the CWT tag.
        { "a4-maced-cwt.hex.txt", "MACed CWT (COSE_Mac0)", CoseVerificationErrorCode.UnsupportedCoseStructure },
        // A.5 is 16(…): an encrypted CWT (COSE_Encrypt0).
        { "a5-encrypted-cwt.hex.txt", "encrypted CWT (COSE_Encrypt0)", CoseVerificationErrorCode.UnsupportedCoseStructure },
        // A.6 is 16(…): the nested CWT travels inside a COSE_Encrypt0.
        { "a6-nested-cwt.hex.txt", "nested CWT (outer COSE_Encrypt0)", CoseVerificationErrorCode.UnsupportedCoseStructure },
        // A.7 is 17(…): a MACed CWT with a floating-point iat, no CWT tag.
        { "a7-maced-cwt-float.hex.txt", "MACed CWT (COSE_Mac0, float iat)", CoseVerificationErrorCode.UnsupportedCoseStructure },
    };

    [Theory]
    [MemberData(nameof(OutOfScopeCwts))]
    public void OutOfScopeStructuresAreRejectedStructurally(string fixtureFile, string description, CoseVerificationErrorCode expected)
    {
        byte[] encoded = Fixtures.HexFile("ietf", "rfc8392", fixtureFile);

        CwtVerificationResult result = Cwt.Verify(encoded, KeyType.P256, A23PublicKey);

        result.Verified.Should().BeFalse(description);
        result.Failure!.Code.Should().Be(expected, description);
    }

    [Fact]
    public void CwtTagOverUntaggedMessageIsRejected()
    {
        // RFC 8392 §6: when the CWT tag is present it MUST prefix a *tagged* COSE message.
        byte[] untagged = TestCose.StripLeadingTag(A3SignedCwt);
        byte[] cwtTagOnly = TestCose.PrependTag(61, untagged);

        Cwt.Verify(cwtTagOnly, KeyType.P256, A23PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.UnexpectedCborTag);
    }

    [Fact]
    public void UntaggedCoseSign1IsAcceptedAtTheCwtEntryPoint()
    {
        byte[] untagged = TestCose.StripLeadingTag(A3SignedCwt);

        Cwt.Verify(untagged, KeyType.P256, A23PublicKey, new CwtValidationOptions { ValidationTime = InsideWindow })
            .Verified.Should().BeTrue();
    }

    // ----- malformed claims -----

    [Fact]
    public async Task NonMapClaimsPayloadIsMalformedClaims()
    {
        // A validly signed COSE_Sign1 whose payload is not a CBOR map: the signature verifies,
        // then claims decoding fails with the documented code.
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] notAMap = [0x01];
        byte[] encoded = await CoseSign1.SignAsync(notAMap, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa });

        CwtVerificationResult result = Cwt.Verify(encoded, KeyType.Ed25519, keyPair.PublicKey);

        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedClaims);
    }

    [Fact]
    public void DecodeClaimsThrowsOnMalformedInput()
    {
        Action act = () => Cwt.DecodeClaims(new byte[] { 0x01 });
        act.Should().Throw<CoseException>();
    }

    [Fact]
    public void DecodeClaimsRejectsWrongClaimType()
    {
        // {1: 42} — iss must be a text string.
        Action act = () => Cwt.DecodeClaims(new byte[] { 0xA1, 0x01, 0x18, 0x2A });
        act.Should().Throw<CoseException>();
    }

    // ----- construction round-trips -----

    public static TheoryData<CoseAlgorithm, KeyType> Algorithms => new()
    {
        { CoseAlgorithm.EdDsa, KeyType.Ed25519 },
        { CoseAlgorithm.ES256, KeyType.P256 },
        { CoseAlgorithm.ES384, KeyType.P384 },
        { CoseAlgorithm.ES256K, KeyType.Secp256k1 },
    };

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task SignThenVerifyRoundTrips(CoseAlgorithm algorithm, KeyType keyType)
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(keyType);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        DateTimeOffset now = new(2026, 6, 12, 12, 0, 0, TimeSpan.Zero);
        var claims = new CwtClaims
        {
            Issuer = "https://issuer.example",
            Subject = "subject-1",
            Audience = "https://audience.example",
            ExpirationTime = now.AddHours(1),
            NotBefore = now.AddMinutes(-5),
            IssuedAt = now,
            CwtId = new byte[] { 0xAB, 0xCD },
        };

        byte[] cwt = await Cwt.SignAsync(
            claims,
            signer,
            new CwtSignOptions { Algorithm = algorithm, KeyId = "cwt-key"u8.ToArray() });

        CwtVerificationResult result = Cwt.Verify(
            cwt,
            keyType,
            keyPair.PublicKey,
            new CwtValidationOptions { ValidationTime = now });

        result.Verified.Should().BeTrue(result.Failure?.Message);
        result.Claims!.Issuer.Should().Be(claims.Issuer);
        result.Claims.Subject.Should().Be(claims.Subject);
        result.Claims.Audience.Should().Be(claims.Audience);
        result.Claims.ExpirationTime.Should().Be(claims.ExpirationTime);
        result.Claims.NotBefore.Should().Be(claims.NotBefore);
        result.Claims.IssuedAt.Should().Be(claims.IssuedAt);
        result.Claims.CwtId!.Value.ToArray().Should().Equal(new byte[] { 0xAB, 0xCD });
    }

    [Fact]
    public async Task CwtTagEmissionRoundTrips()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        var claims = new CwtClaims { Issuer = "https://issuer.example" };

        byte[] cwt = await Cwt.SignAsync(
            claims,
            signer,
            new CwtSignOptions { Algorithm = CoseAlgorithm.EdDsa, IncludeCwtTag = true });

        // 61(18(…)): 0xD8 0x3D is the two-byte encoding of tag 61, 0xD2 the one-byte tag 18.
        cwt[..3].Should().Equal(new byte[] { 0xD8, 0x3D, 0xD2 });
        Cwt.Verify(cwt, KeyType.Ed25519, keyPair.PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task TokenWithoutTimeClaimsSkipsTimeValidation()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        var claims = new CwtClaims { Issuer = "https://issuer.example" };

        byte[] cwt = await Cwt.SignAsync(claims, signer, new CwtSignOptions { Algorithm = CoseAlgorithm.EdDsa });

        CwtVerificationResult result = Cwt.Verify(cwt, KeyType.Ed25519, keyPair.PublicKey);
        result.Verified.Should().BeTrue();
        result.Claims!.ExpirationTime.Should().BeNull();
        result.Claims.NotBefore.Should().BeNull();
        result.Claims.CwtId.Should().BeNull("no cti was emitted — absence must surface as null, not empty");
    }
}
