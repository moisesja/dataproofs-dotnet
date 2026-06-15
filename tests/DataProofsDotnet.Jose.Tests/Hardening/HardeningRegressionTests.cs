using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Regression tests for the issue #6 adversarial-hardening pass. Each test pins a confirmed
/// finding's fix so it cannot regress before GA.
/// </summary>
public class HardeningRegressionTests
{
    private static readonly DefaultKeyGenerator KeyGen = new();
    private static readonly DefaultCryptoProvider NetCrypto = new();
    private static readonly JoseCryptoProvider Jose = new();

    // ── Finding #0 (HIGH): SD-JWT reconstruction must bound recursion and FAIL CLOSED on a deep
    //    recursive-disclosure chain, rather than overflow the stack (uncatchable, crashes the host).
    [Fact]
    public void Reconstruct_DeepRecursiveDisclosureChain_FailsClosed_NoStackOverflow()
    {
        const string sdAlg = SdHashAlgorithm.Sha256;
        var disclosures = new List<Disclosure>();

        // Build a chain well beyond the depth bound: each link's disclosed value is
        // {"_sd":[digest(next)]}, so reconstruction recurses one frame per link.
        var leaf = Disclosure.ForObjectProperty("salt-leaf", "n", JsonValue.Create("v"));
        disclosures.Add(leaf);
        var childDigest = leaf.ComputeDigest(sdAlg);

        for (var i = 0; i < 200; i++)
        {
            var value = new JsonObject { ["_sd"] = new JsonArray(childDigest) };
            var link = Disclosure.ForObjectProperty($"salt-{i}", "n", value);
            disclosures.Add(link);
            childDigest = link.ComputeDigest(sdAlg);
        }

        var payload = new JsonObject { ["_sd"] = new JsonArray(childDigest), ["_sd_alg"] = sdAlg };

        var act = () => SdJwtReconstructor.Reconstruct(payload, disclosures, sdAlg);

        act.Should().Throw<MalformedJoseException>().WithMessage("*depth*");
    }

    // ── Finding #1 (MEDIUM): a malformed/unsupported verifier JWK (e.g. an attacker-influenced
    //    SD-JWT 'cnf') must make CompactJwt.Verify FAIL CLOSED as MalformedJoseException — which
    //    both call sites catch — not escape as NotSupportedException / a crypto exception.
    [Fact]
    public async Task CompactJwt_Verify_UnsupportedCurveJwk_ThrowsMalformed_NotRawException()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "h");
        var jwt = await JwtHandler.SignAsync(new JwtClaims(subject: "s"), key.Signer);
        var compact = CompactJwt.Decode(jwt);

        var unsupportedCurve = new Jwk { Kty = "EC", Crv = "P-192", X = "AAAA", Y = "AAAA" };

        var act = () => compact.Verify(unsupportedCurve, Jose);

        act.Should().Throw<MalformedJoseException>();
    }

    [Fact]
    public async Task CompactJwt_Verify_MalformedOkpJwk_ThrowsMalformed_NotRawException()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "h");
        var jwt = await JwtHandler.SignAsync(new JwtClaims(subject: "s"), key.Signer);
        var compact = CompactJwt.Decode(jwt);

        // Valid base64url, but decodes to 3 bytes — not the 32 an Ed25519 public key requires.
        var malformedOkp = new Jwk { Kty = "OKP", Crv = "Ed25519", X = "AAAA" };

        var act = () => compact.Verify(malformedOkp, Jose);

        act.Should().Throw<MalformedJoseException>();
    }

    // ── Finding #2 (LOW): the verified SignerKid must come ONLY from the integrity-protected
    //    header. A kid that lives solely in the unauthenticated unprotected header is a routing
    //    hint (used to resolve the key) but must never be surfaced as the verified identity.
    [Fact]
    public async Task JwsJson_KidOnlyInUnprotectedHeader_VerifiesButReportsNoSignerKid()
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signerNoKid = new JwsSigner(new KeyPairSigner(pair, NetCrypto)); // protected header carries no kid

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signerNoKid);
        var parts = compact.Split('.');

        // Flattened JSON JWS with kid placed ONLY in the unprotected header.
        var flattened = new JsonObject
        {
            ["payload"] = parts[1],
            ["protected"] = parts[0],
            ["header"] = new JsonObject { ["kid"] = "k1" },
            ["signature"] = parts[2],
        }.ToJsonString();

        Func<string, Jwk?> resolver = kid => kid == "k1" ? publicJwk : null;
        var result = JwsParser.Parse(flattened, resolver, Jose);

        Encoding.UTF8.GetString(result.PayloadBytes).Should().Be("hello", "the unprotected kid is still a valid resolution hint");
        result.SignerKid.Should().BeEmpty("an unprotected-only kid is unauthenticated and must not be reported as the verified signer");
    }

    [Fact]
    public async Task JwsCompact_KidInProtectedHeader_IsReportedAsSignerKid()
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signerWithKid = new JwsSigner(new KeyPairSigner(pair, NetCrypto), "k1");

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signerWithKid);
        var result = JwsParser.ParseCompact(compact, _ => publicJwk, Jose);

        result.SignerKid.Should().Be("k1");
    }

    // ── Finding #3 (LOW): JwtValidationOptions.ExpectedType enforces RFC 8725 §3.11 explicit
    //    typing (opt-in), tolerating the 'application/' prefix; default behavior is unchanged.
    [Fact]
    public async Task JwtVerify_ExpectedType_EnforcesTyp_PrefixTolerant()
    {
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k");
        var jwt = await JwtHandler.SignAsync(new JwtClaims(subject: "s"), key.Signer); // SignAsync writes typ="JWT"
        Func<string, Jwk?> resolver = _ => key.PublicJwk;

        JwtHandler.Verify(jwt, resolver).IsValid
            .Should().BeTrue("typ is not checked by default");
        JwtHandler.Verify(jwt, resolver, new JwtValidationOptions { ExpectedType = "JWT" }).IsValid
            .Should().BeTrue();
        JwtHandler.Verify(jwt, resolver, new JwtValidationOptions { ExpectedType = "application/jwt" }).IsValid
            .Should().BeTrue("the application/ prefix and case are tolerated (RFC 8725 §3.11)");

        var mismatch = JwtHandler.Verify(jwt, resolver, new JwtValidationOptions { ExpectedType = "kb+jwt" });
        mismatch.IsValid.Should().BeFalse();
        mismatch.Errors.Should().Contain(e => e.StartsWith("TYPE_MISMATCH", StringComparison.Ordinal));
    }

    // ── Finding #4 (LOW): Base64Url.Decode is strict — interior/surrounding whitespace, '='
    //    padding, and standard-base64 '+'/'/' are rejected (the documented no-pad contract).
    [Theory]
    [InlineData("AQ ID")]   // interior space
    [InlineData(" AQID")]   // leading space
    [InlineData("AQID ")]   // trailing space
    [InlineData("AQ\nID")]  // newline
    [InlineData("AQID=")]   // padding
    [InlineData("AQ/D")]    // standard-base64 '/'
    [InlineData("AQ+D")]    // standard-base64 '+'
    public void Base64Url_Decode_RejectsNonAlphabet(string value)
    {
        var act = () => Base64Url.Decode(value);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Base64Url_Decode_AcceptsCanonicalNoPad()
        => Base64Url.Decode("AQID").Should().Equal(1, 2, 3);
}
