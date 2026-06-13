using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Jwt;

/// <summary>
/// FR-15 — JWT claims-set construction and validation atop the FR-13 JWS layer:
/// exp/nbf/iat/iss/aud/sub checks with configurable clock skew, structured (never-throwing)
/// verification results, and the <c>typ="JWT"</c> header convention.
/// </summary>
public sealed class JwtHandlerTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 12, 12, 0, 0, TimeSpan.Zero);

    private static TestKeyMaterial NewKey(KeyType keyType = KeyType.Ed25519, string kid = "did:example:iss#jwt-1")
        => TestKeyMaterial.Generate(keyType, kid);

    private static JwtClaims FullClaims() => new(
        issuer: "did:example:iss",
        subject: "did:example:sub",
        audiences: ["did:example:aud"],
        expiresAt: Now.AddMinutes(10),
        notBefore: Now.AddMinutes(-1),
        issuedAt: Now,
        jwtId: "jti-1",
        additionalClaims: new Dictionary<string, JsonNode?> { ["scope"] = "read write" });

    [Theory]
    [InlineData(KeyType.Ed25519, "EdDSA")]
    [InlineData(KeyType.P256, "ES256")]
    [InlineData(KeyType.P384, "ES384")]
    [InlineData(KeyType.Secp256k1, "ES256K")]
    public async Task Sign_then_verify_round_trips_for_every_v1_algorithm(KeyType keyType, string expectedAlg)
    {
        var key = NewKey(keyType);
        var jwt = await JwtHandler.SignAsync(FullClaims(), key.Signer);

        var result = JwtHandler.Verify(jwt, _ => key.PublicJwk, new JwtValidationOptions
        {
            CurrentTime = Now,
            ExpectedIssuer = "did:example:iss",
            ExpectedAudience = "did:example:aud",
            ExpectedSubject = "did:example:sub",
            RequireExpirationTime = true,
        });

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.SignatureAlgorithm.Should().Be(expectedAlg);
        result.SignerKid.Should().Be(key.PublicJwk.Kid);
        result.Claims!.Issuer.Should().Be("did:example:iss");
        result.Claims.JwtId.Should().Be("jti-1");
        result.Claims.AdditionalClaims["scope"]!.GetValue<string>().Should().Be("read write");
    }

    [Fact]
    public async Task Header_typ_is_JWT()
    {
        var key = NewKey();
        var jwt = await JwtHandler.SignAsync(FullClaims(), key.Signer);
        var header = JsonDocument.Parse(Base64Url.Decode(jwt.Split('.')[0]));
        header.RootElement.GetProperty("typ").GetString().Should().Be("JWT");
        header.RootElement.GetProperty("alg").GetString().Should().Be("EdDSA");
    }

    [Fact]
    public async Task Expired_token_fails_with_EXPIRED_and_passes_inside_the_skew()
    {
        var key = NewKey();
        var claims = new JwtClaims(expiresAt: Now);
        var jwt = await JwtHandler.SignAsync(claims, key.Signer);

        var pastSkew = JwtHandler.Verify(jwt, _ => key.PublicJwk,
            new JwtValidationOptions { CurrentTime = Now.AddSeconds(120), ClockSkew = TimeSpan.FromSeconds(60) });
        pastSkew.IsValid.Should().BeFalse();
        pastSkew.Errors.Should().ContainSingle(e => e.StartsWith("EXPIRED"));

        var withinSkew = JwtHandler.Verify(jwt, _ => key.PublicJwk,
            new JwtValidationOptions { CurrentTime = Now.AddSeconds(30), ClockSkew = TimeSpan.FromSeconds(60) });
        withinSkew.IsValid.Should().BeTrue(because: "the configurable clock skew must absorb small clock drift (FR-15)");
    }

    [Fact]
    public async Task Not_yet_valid_token_fails_with_NOT_YET_VALID_and_passes_inside_the_skew()
    {
        var key = NewKey();
        var claims = new JwtClaims(notBefore: Now.AddSeconds(90));
        var jwt = await JwtHandler.SignAsync(claims, key.Signer);

        var early = JwtHandler.Verify(jwt, _ => key.PublicJwk,
            new JwtValidationOptions { CurrentTime = Now, ClockSkew = TimeSpan.FromSeconds(60) });
        early.IsValid.Should().BeFalse();
        early.Errors.Should().ContainSingle(e => e.StartsWith("NOT_YET_VALID"));

        var withinSkew = JwtHandler.Verify(jwt, _ => key.PublicJwk,
            new JwtValidationOptions { CurrentTime = Now.AddSeconds(45), ClockSkew = TimeSpan.FromSeconds(60) });
        withinSkew.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Issued_in_the_future_fails_with_ISSUED_IN_FUTURE()
    {
        var key = NewKey();
        var jwt = await JwtHandler.SignAsync(new JwtClaims(issuedAt: Now.AddMinutes(10)), key.Signer);

        var result = JwtHandler.Verify(jwt, _ => key.PublicJwk, new JwtValidationOptions { CurrentTime = Now });
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.StartsWith("ISSUED_IN_FUTURE"));
    }

    [Fact]
    public async Task Issuer_audience_and_subject_mismatches_each_produce_their_error()
    {
        var key = NewKey();
        var jwt = await JwtHandler.SignAsync(FullClaims(), key.Signer);

        var result = JwtHandler.Verify(jwt, _ => key.PublicJwk, new JwtValidationOptions
        {
            CurrentTime = Now,
            ExpectedIssuer = "did:example:other-iss",
            ExpectedAudience = "did:example:other-aud",
            ExpectedSubject = "did:example:other-sub",
        });

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.StartsWith("ISSUER_MISMATCH"));
        result.Errors.Should().Contain(e => e.StartsWith("AUDIENCE_MISMATCH"));
        result.Errors.Should().Contain(e => e.StartsWith("SUBJECT_MISMATCH"));
    }

    [Fact]
    public async Task Multi_valued_audience_matches_any_entry()
    {
        var key = NewKey();
        var claims = new JwtClaims(audiences: ["aud-1", "aud-2"]);
        var jwt = await JwtHandler.SignAsync(claims, key.Signer);

        JwtHandler.Verify(jwt, _ => key.PublicJwk,
                new JwtValidationOptions { CurrentTime = Now, ExpectedAudience = "aud-2" })
            .IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Missing_exp_fails_only_when_the_policy_requires_it()
    {
        var key = NewKey();
        var jwt = await JwtHandler.SignAsync(new JwtClaims(issuer: "i"), key.Signer);

        JwtHandler.Verify(jwt, _ => key.PublicJwk, new JwtValidationOptions { CurrentTime = Now })
            .IsValid.Should().BeTrue();

        var strict = JwtHandler.Verify(jwt, _ => key.PublicJwk,
            new JwtValidationOptions { CurrentTime = Now, RequireExpirationTime = true });
        strict.IsValid.Should().BeFalse();
        strict.Errors.Should().ContainSingle(e => e.StartsWith("MISSING_EXPIRATION"));
    }

    [Fact]
    public void Claims_set_round_trips_through_json()
    {
        var claims = FullClaims();
        var parsed = JwtClaims.Parse(claims.ToJsonBytes());

        parsed.Issuer.Should().Be(claims.Issuer);
        parsed.Subject.Should().Be(claims.Subject);
        parsed.Audiences.Should().Equal(claims.Audiences);
        parsed.ExpiresAt.Should().Be(claims.ExpiresAt);
        parsed.NotBefore.Should().Be(claims.NotBefore);
        parsed.IssuedAt.Should().Be(claims.IssuedAt);
        parsed.JwtId.Should().Be(claims.JwtId);
        parsed.AdditionalClaims["scope"]!.GetValue<string>().Should().Be("read write");
        // Single audience serializes as a bare string (RFC 7519 §4.1.3).
        Encoding.UTF8.GetString(claims.ToJsonBytes()).Should().Contain("\"aud\":\"did:example:aud\"");
    }

    [Fact]
    public void Claims_with_wrong_types_are_rejected_as_malformed()
    {
        Action numericIss = () => JwtClaims.Parse("{\"iss\":42}"u8);
        numericIss.Should().Throw<MalformedJoseException>().WithMessage("*iss*");

        Action stringExp = () => JwtClaims.Parse("{\"exp\":\"tomorrow\"}"u8);
        stringExp.Should().Throw<MalformedJoseException>().WithMessage("*exp*");

        Action mixedAud = () => JwtClaims.Parse("{\"aud\":[\"ok\",7]}"u8);
        mixedAud.Should().Throw<MalformedJoseException>().WithMessage("*aud*");
    }

    /// <summary>
    /// FR-23 regression. <c>JwtClaims.RequireNumericDate</c> now range-checks before calling
    /// <c>DateTimeOffset.FromUnixTimeSeconds</c>. An out-of-range NumericDate (a huge integer, a
    /// huge double that would saturate on cast, or a hugely negative integer) must surface as the
    /// documented <see cref="MalformedJoseException"/> — never an unhandled
    /// <see cref="ArgumentOutOfRangeException"/> leaking from the framework. Run against the
    /// unfixed RequireNumericDate (no range check) these throw ArgumentOutOfRangeException.
    /// </summary>
    [Theory]
    [InlineData("{\"exp\":99999999999999999}")]   // integer past DateTimeOffset.MaxValue epoch seconds
    [InlineData("{\"exp\":1e308}")]                // double that saturates to long.MaxValue on cast
    [InlineData("{\"exp\":-99999999999999999}")]   // integer before DateTimeOffset.MinValue
    [InlineData("{\"nbf\":99999999999999999}")]
    [InlineData("{\"iat\":1e308}")]
    public void Out_of_range_numeric_date_is_MalformedJoseException_not_ArgumentOutOfRange(string json)
    {
        Action act = () => JwtClaims.Parse(Encoding.UTF8.GetBytes(json));

        act.Should().Throw<MalformedJoseException>("an out-of-range NumericDate is malformed input, not a framework crash")
            .Which.Should().NotBeOfType<ArgumentOutOfRangeException>();
    }

    /// <summary>
    /// FR-23 regression through the full JWT verify path: a signed JWT whose payload carries an
    /// out-of-range <c>exp</c> must return a structured MALFORMED failure and never throw. The
    /// payload is hand-built (JwtClaims cannot construct an out-of-range exp) and signed normally.
    /// </summary>
    [Fact]
    public async Task Jwt_with_out_of_range_exp_returns_structured_failure_and_never_throws()
    {
        var key = NewKey();
        var jwt = await JwsBuilder.BuildCompactAsync(
            Encoding.UTF8.GetBytes("""{"iss":"i","exp":99999999999999999}"""), key.Signer, typ: "JWT");

        JwtVerificationResult? result = null;
        Action act = () => result = JwtHandler.Verify(jwt, _ => key.PublicJwk, new JwtValidationOptions { CurrentTime = Now });

        act.Should().NotThrow("an out-of-range exp must produce a structured result, never an unhandled exception (FR-23)");
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.StartsWith("MALFORMED"));
    }

    [Fact]
    public async Task Wrong_key_yields_SIGNATURE_INVALID_without_throwing()
    {
        var key = NewKey();
        var otherKey = NewKey(kid: key.PublicJwk.Kid!); // same kid, different key material
        var jwt = await JwtHandler.SignAsync(FullClaims(), key.Signer);

        JwtVerificationResult? result = null;
        Action act = () => result = JwtHandler.Verify(jwt, _ => otherKey.PublicJwk, new JwtValidationOptions { CurrentTime = Now });

        act.Should().NotThrow(because: "invalid tokens produce structured results, never unhandled exceptions (AC-3 step 7)");
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.StartsWith("SIGNATURE_INVALID"));
    }
}
