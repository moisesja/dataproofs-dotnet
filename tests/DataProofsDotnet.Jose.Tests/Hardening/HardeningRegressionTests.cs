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

    // ── Finding #2 (LOW), CORRECTED by issue #10: the verified SignerKid is the kid that resolved
    //    the *verifying* key. Issue #6 originally dropped an unprotected-only kid as "unauthenticated";
    //    issue #10 showed that is wrong AFTER verification — a forged unprotected kid resolves a
    //    different key under which the signature cannot verify, so a kid that produced a SUCCESSFUL
    //    verification is authentic. DIDComm v2.1 carries the signer kid only in the unprotected
    //    header, so this kid MUST be reported (else signed/authcrypt unpack loses the signer identity).
    [Fact]
    public async Task JwsJson_KidOnlyInUnprotectedHeader_VerifiesAndReportsTheResolvedSignerKid()
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signerNoKid = new JwsSigner(new KeyPairSigner(pair, NetCrypto)); // protected header carries no kid

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signerNoKid);
        var parts = compact.Split('.');

        // Flattened JSON JWS with kid placed ONLY in the unprotected header (the DIDComm v2.1 shape).
        var flattened = new JsonObject
        {
            ["payload"] = parts[1],
            ["protected"] = parts[0],
            ["header"] = new JsonObject { ["kid"] = "k1" },
            ["signature"] = parts[2],
        }.ToJsonString();

        Func<string, Jwk?> resolver = kid => kid == "k1" ? publicJwk : null;
        var result = JwsParser.Parse(flattened, resolver, Jose);

        Encoding.UTF8.GetString(result.PayloadBytes).Should().Be("hello", "the unprotected kid is a valid resolution hint");
        result.SignerKid.Should().Be("k1", "the kid that resolved the verifying key is the authentic signer (issue #10)");
    }

    // ── Issue #10: a JWS whose protected and unprotected kids DISAGREE is still rejected. Surfacing
    //    the unprotected kid post-verification does not relax the agreement check.
    [Fact]
    public async Task JwsJson_ConflictingProtectedAndUnprotectedKid_IsRejected()
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signerWithKid = new JwsSigner(new KeyPairSigner(pair, NetCrypto), "k1"); // protected kid = k1

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signerWithKid);
        var parts = compact.Split('.');

        // Same valid signature, but the unprotected header advertises a DIFFERENT kid than the
        // (integrity-protected) protected header. The resolver returns the real key for either kid so
        // resolution succeeds and the parser reaches — and trips — the agreement check.
        var flattened = new JsonObject
        {
            ["payload"] = parts[1],
            ["protected"] = parts[0],
            ["header"] = new JsonObject { ["kid"] = "k2" },
            ["signature"] = parts[2],
        }.ToJsonString();

        Func<string, Jwk?> resolver = _ => publicJwk;
        var act = () => JwsParser.Parse(flattened, resolver, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*does not match the unprotected header*");
    }

    // ── Issue #10: the General (signatures-array) serialization with an unprotected-only kid behaves
    //    identically to the Flattened form — the resolved kid is reported. This is the shape DIDComm
    //    v2.1 multi-recipient / authcrypt(sign(...)) envelopes use.
    [Fact]
    public async Task JwsGeneral_KidOnlyInUnprotectedHeader_VerifiesAndReportsTheResolvedSignerKid()
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signerNoKid = new JwsSigner(new KeyPairSigner(pair, NetCrypto)); // protected header carries no kid

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signerNoKid);
        var parts = compact.Split('.');

        // General JSON JWS: signatures[] with the kid only in the per-signature unprotected header.
        var general = new JsonObject
        {
            ["payload"] = parts[1],
            ["signatures"] = new JsonArray(new JsonObject
            {
                ["protected"] = parts[0],
                ["header"] = new JsonObject { ["kid"] = "k1" },
                ["signature"] = parts[2],
            }),
        }.ToJsonString();

        Func<string, Jwk?> resolver = kid => kid == "k1" ? publicJwk : null;
        var result = JwsParser.Parse(general, resolver, Jose);

        result.SignerKid.Should().Be("k1", "the kid that resolved the verifying key is the authentic signer (issue #10)");
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

    // ── Issue #15: a non-string unprotected 'header.kid' (number/object/array/boolean/null) must FAIL
    //    CLOSED as MalformedJoseException — the documented contract — not escape as a raw
    //    InvalidOperationException from JsonElement.GetString(). Reachable pre-authentication:
    //    the read happens while enumerating raw signatures, before any verification, so any peer
    //    that can deliver bytes can throw it (downstream this tore down a didcomm-dotnet
    //    WebSocket receive loop).
    [Theory]
    [InlineData("123")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("true")]
    [InlineData("null")]
    public async Task JwsJson_NonStringUnprotectedKid_ThrowsMalformed_NotRawException(string kidJson)
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signer = new JwsSigner(new KeyPairSigner(pair, NetCrypto));

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signer);
        var parts = compact.Split('.');

        // The protected header carries no kid, so the malformed unprotected kid is the envelope's
        // only kid parameter. This isolates the wrong-type condition from RFC 7515's disjoint-header
        // rule; no key material is needed to craft the malformed input.
        var flattened = new JsonObject
        {
            ["payload"] = parts[1],
            ["protected"] = parts[0],
            ["header"] = new JsonObject { ["kid"] = JsonNode.Parse(kidJson) },
            ["signature"] = parts[2],
        }.ToJsonString();

        var act = () => JwsParser.Parse(flattened, _ => publicJwk, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*'kid' must be a string*");
    }

    // ── Issue #15: same contract for the General serialization — a non-string kid in ANY entry of
    //    the signatures array rejects the envelope, matching how a missing 'protected'/'signature'
    //    in any entry already behaves (structural enumeration is all-or-nothing, before any
    //    signature is tried).
    [Theory]
    [InlineData("123")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("true")]
    [InlineData("null")]
    public async Task JwsGeneral_NonStringUnprotectedKid_InOneEntry_ThrowsMalformed(string kidJson)
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signer = new JwsSigner(new KeyPairSigner(pair, NetCrypto));

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signer);
        var parts = compact.Split('.');

        // The first entry is RFC-valid and would verify: kid appears only in its unprotected header.
        // The second carries the malformed kid, also with no protected-header duplicate.
        var general = new JsonObject
        {
            ["payload"] = parts[1],
            ["signatures"] = new JsonArray(
                new JsonObject
                {
                    ["protected"] = parts[0],
                    ["header"] = new JsonObject { ["kid"] = "k1" },
                    ["signature"] = parts[2],
                },
                new JsonObject
                {
                    ["protected"] = parts[0],
                    ["header"] = new JsonObject { ["kid"] = JsonNode.Parse(kidJson) },
                    ["signature"] = parts[2],
                }),
        }.ToJsonString();

        var act = () => JwsParser.Parse(general, _ => publicJwk, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*'kid' must be a string*");
    }

    // ── Issue #15 regression guard: an absent unprotected kid still falls back to the protected
    //    header's kid. JSON null is present but non-string and is rejected by the theories above.
    [Fact]
    public async Task JwsJson_AbsentUnprotectedKid_FallsBackToProtectedKid()
    {
        var pair = KeyGen.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signerWithKid = new JwsSigner(new KeyPairSigner(pair, NetCrypto), "k1"); // protected kid = k1

        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signerWithKid);
        var parts = compact.Split('.');

        var flattened = new JsonObject
        {
            ["payload"] = parts[1],
            ["protected"] = parts[0],
            ["header"] = new JsonObject(),
            ["signature"] = parts[2],
        }.ToJsonString();

        Func<string, Jwk?> resolver = kid => kid == "k1" ? publicJwk : null;
        var result = JwsParser.Parse(flattened, resolver, Jose);

        result.SignerKid.Should().Be("k1", "a missing unprotected kid falls back to the protected header's kid");
    }

    // ── Issue #15 (adversarial follow-up): malformed JSON must FAIL CLOSED as MalformedJoseException,
    //    not escape as a raw System.Text.Json.JsonException. This is the SAME failure class as the
    //    non-string kid — an untyped fault escaping the parser pre-verification — and is strictly
    //    more reachable (a truncated frame or duplicate member trips it before any header is read).
    //    The sibling JWE/JWT parsers already wrap JsonDocument.Parse this way; JwsParser now matches.
    [Theory]
    [InlineData("{")]                                                                              // truncated
    [InlineData("{\"payload\":\"AQID\"}trailing")]                                                 // trailing junk
    [InlineData("{\"payload\":\"AQID\",\"payload\":\"AQIE\",\"protected\":\"e30\",\"signature\":\"AQID\"}")] // duplicate 'payload'
    [InlineData("{\"payload\":\"AQID\",\"protected\":\"e30\",\"header\":{\"kid\":\"a\",\"kid\":1},\"signature\":\"AQID\"}")] // duplicate 'kid'
    public void JwsJson_MalformedJson_ThrowsMalformed_NotRawJsonException(string packed)
    {
        var act = () => JwsParser.Parse(packed, _ => null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*not valid JSON*");
    }

    // Note: the "valid string unprotected kid still verifies after the strictness change" regression
    // is already covered by JwsJson_KidOnlyInUnprotectedHeader_VerifiesAndReportsTheResolvedSignerKid
    // (issue #10) — a kid ONLY in the unprotected header, which is the RFC 7515-disjoint (§5.2 step 4)
    // shape. A fixture carrying kid in BOTH headers is not RFC-valid even when the values match, so it
    // is deliberately not asserted here.
}
