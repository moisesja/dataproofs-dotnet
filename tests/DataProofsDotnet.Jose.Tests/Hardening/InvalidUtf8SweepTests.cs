using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Issue #28, same-class sweep. Every decoder in the package that base64url-decodes bytes and
/// parses them as JSON had the same omission as the JWS protected header: nothing validated the
/// octets as UTF-8. The consequences differed by decoder — <c>JsonNode</c> is lazy and throws a raw
/// <see cref="InvalidOperationException"/> at first access of a member name it cannot transcode,
/// which escaped <c>SdJwtVerifier.Verify</c> and <c>JwtHandler.Verify</c> (both documented as never
/// throwing) and reached the SD-JWT verifier <em>before</em> any signature check; the JWE header
/// deserializer silently replaced the name with U+FFFD. All now fail as
/// <see cref="MalformedJoseException"/> ("… is not valid UTF-8"). One layer up, a .NET string that
/// is not well-formed UTF-16 made <c>JsonDocument.Parse(string)</c> throw
/// <see cref="ArgumentException"/> out of the JSON-serialization parsers.
/// </summary>
public sealed class InvalidUtf8SweepTests
{
    private static readonly JoseCryptoProvider Jose = new();

    /// <summary>Two bytes that never occur in UTF-8.</summary>
    private static readonly byte[] Bad = [0xFF, 0xFE];

    private static byte[] U8(string s) => Encoding.UTF8.GetBytes(s);

    // ── JWE protected header (RFC 7516 §5.2 step 3) ───────────────────────────────────────────

    [Theory]
    [InlineData("member-name")]
    [InlineData("extension-value")]
    public void JweProtectedHeader_Decode_WithNonUtf8_IsMalformed(string placement)
    {
        byte[] header = placement == "member-name"
            ? [.. U8("""{"alg":"A256KW","enc":"A256GCM","""), (byte)'"', .. Bad, .. U8("\":1}")]
            : [.. U8("{\"alg\":\"A256KW\",\"enc\":\"A256GCM\",\"x\":\""), .. Bad, .. U8("\"}")];

        var act = () => JweProtectedHeader.Decode(Base64Url.Encode(header));

        act.Should().Throw<MalformedJoseException>().WithMessage("*not valid UTF-8*");
    }

    [Fact]
    public void CompactJwe_WithNonUtf8ProtectedHeaderMemberName_IsMalformed_BeforeDecryption()
    {
        // Anyone can send these bytes, and the check rejects them before any key work. The header
        // is the AEAD's AAD, though, so before the fix only an envelope its sender sealed over this
        // header could have decrypted — the same exposure class as the JWS report. Hand-sealed
        // because JweBuilder cannot emit it.
        byte[] header = [.. U8("""{"alg":"A256KW","enc":"A256GCM","kid":"kek-1","""), (byte)'"', .. Bad, .. U8("\":1}")];
        var (compact, kek) = SealA256KwA256Gcm(header, U8("{}"));

        var act = () => JweParser.ParseCompact(compact, kek, senderKeys: null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*not valid UTF-8*");
    }

    [Fact]
    public void CompactJwe_HandSealedControl_Decrypts()
    {
        // Proves the hand-sealing in the test above is sound, so its failure is the UTF-8 check and
        // not a broken AAD or key wrap.
        byte[] header = U8("""{"alg":"A256KW","enc":"A256GCM","kid":"kek-1","x":1}""");
        var plaintext = U8("""{"hello":"world"}""");
        var (compact, kek) = SealA256KwA256Gcm(header, plaintext);

        var result = JweParser.ParseCompact(compact, kek, senderKeys: null, Jose);

        result.Plaintext.Should().Equal(plaintext);
    }

    private static (string Compact, Jwk Kek) SealA256KwA256Gcm(byte[] headerBytes, byte[] plaintext)
    {
        // Mirrors JweBuilder's sealing: CEK + IV from the provider's CSPRNG, AAD = ASCII(base64url(header)).
        var kek = new byte[32];
        Jose.Fill(kek);
        var kekJwk = new Jwk { Kty = "oct", K = Base64Url.Encode(kek), Kid = "kek-1" };
        var cek = new byte[32];
        var iv = new byte[12];
        Jose.Fill(cek);
        Jose.Fill(iv);

        var protectedB64u = Base64Url.Encode(headerBytes);
        var (ciphertext, tag) = Jose.AeadEncrypt(JoseAlgorithms.A256Gcm, cek, iv, Encoding.ASCII.GetBytes(protectedB64u), plaintext);
        var encryptedKey = Jose.KeyWrap(JoseAlgorithms.A256Kw, kek, cek);

        var compact = string.Join('.',
            protectedB64u, Base64Url.Encode(encryptedKey), Base64Url.Encode(iv), Base64Url.Encode(ciphertext), Base64Url.Encode(tag));
        return (compact, kekJwk);
    }

    // ── JWT claims set (RFC 7519 §7.2 step 10) ────────────────────────────────────────────────

    [Theory]
    [InlineData("claim-name")]
    [InlineData("registered-string-value")]
    [InlineData("unregistered-string-value")]
    public void JwtClaims_Parse_WithNonUtf8_IsMalformed_NotInvalidOperationException(string placement)
    {
        // Before the fix: the first two threw a raw InvalidOperationException ("Cannot transcode
        // invalid UTF-8 JSON text"), the third was accepted and carried the bytes into the model.
        byte[] json = placement switch
        {
            "claim-name" => [.. U8("""{"iss":"i","""), (byte)'"', .. Bad, .. U8("\":1}")],
            "registered-string-value" => [.. U8("{\"iss\":\""), .. Bad, .. U8("\"}")],
            _ => [.. U8("{\"iss\":\"i\",\"x\":\""), .. Bad, .. U8("\"}")],
        };

        var act = () => JwtClaims.Parse(json);

        act.Should().Throw<MalformedJoseException>().WithMessage("*not valid UTF-8*");
    }

    [Fact]
    public async Task JwtHandler_Verify_SignedJwtWithNonUtf8ClaimName_IsStructuredFailure_NeverThrows()
    {
        // Genuinely signed, so this is the key holder's doing — but JwtHandler.Verify is documented
        // as never throwing for an invalid token, and it did.
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");
        byte[] payload = [.. U8("""{"iss":"i","""), (byte)'"', .. Bad, .. U8("\":1}")];
        var jwt = await JwsBuilder.BuildCompactAsync(payload, key.Signer, typ: "JWT");

        JwtVerificationResult? result = null;
        var act = () => result = JwtHandler.Verify(jwt, _ => key.PublicJwk);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED").And.Contain("not valid UTF-8");
    }

    // ── SD-JWT: issuer JWT, Key Binding JWT, Disclosures (RFC 9901 §4.2.1) ────────────────────

    [Theory]
    [InlineData("header")]
    [InlineData("payload")]
    public void SdJwtVerifier_Verify_IssuerJwtWithNonUtf8MemberName_IsStructuredFailure_NeverThrows(string segment)
    {
        // Unauthenticated input: CompactJwt.Decode runs in step 1 of the verifier, before the
        // issuer signature is checked. Before the fix the lazy JsonObject threw a raw
        // InvalidOperationException on the first member read ('alg' / '_sd_alg'), straight through
        // the verifier's catch (MalformedJoseException) and out of a never-throws API.
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        byte[] header = segment == "header"
            ? [.. U8("""{"alg":"EdDSA","typ":"example+sd-jwt","""), (byte)'"', .. Bad, .. U8("\":1}")]
            : U8("""{"alg":"EdDSA","typ":"example+sd-jwt"}""");
        byte[] payload = segment == "payload"
            ? [.. U8("""{"_sd":[],"_sd_alg":"sha-256","""), (byte)'"', .. Bad, .. U8("\":1}")]
            : U8("""{"_sd":[],"_sd_alg":"sha-256"}""");
        var forged = $"{Base64Url.Encode(header)}.{Base64Url.Encode(payload)}.{Base64Url.Encode(new byte[64])}~";

        SdJwtVerificationResult? result = null;
        var act = () => result = SdJwtVerifier.Verify(forged, _ => issuer.PublicJwk);

        act.Should().NotThrow("an unauthenticated presentation must never crash the verifier");
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED").And.Contain("not valid UTF-8");
    }

    [Fact]
    public async Task SdJwtVerifier_Verify_DisclosureWithNonUtf8ClaimName_IsStructuredFailure_NeverThrows()
    {
        // A valid issuance plus one attacker-appended Disclosure. Disclosures are parsed in step 1,
        // before the issuer signature; before the fix Disclosure.Parse threw a raw
        // InvalidOperationException from GetValue<string>() on the claim name.
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var claims = new JsonObject { ["iss"] = "https://issuer.example.com", ["given_name"] = "John" };
        var issued = await SdJwtIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), issuer.Signer);
        byte[] disclosure = [.. U8("[\"salt\",\""), .. Bad, .. U8("\",\"v\"]")];
        var presentation = issued.Issuance + Base64Url.Encode(disclosure) + "~";

        SdJwtVerificationResult? result = null;
        var act = () => result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk);

        act.Should().NotThrow("an unauthenticated presentation must never crash the verifier");
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED").And.Contain("not valid UTF-8");
    }

    [Theory]
    [InlineData("header", "member-name")]
    [InlineData("header", "extension-value")]
    [InlineData("payload", "member-name")]
    [InlineData("payload", "extension-value")]
    public async Task SdJwtVerifier_Verify_KeyBindingJwtWithNonUtf8_IsKbJwtMalformed_NeverThrows(string segment, string placement)
    {
        // End to end through the Key Binding boundary: a genuinely issued SD-JWT carrying a cnf key,
        // presented with a malformed KB-JWT. KeyBindingJwt.Verify is the only source of the
        // KB_JWT_MALFORMED prefix, so the assertion proves the path is reached. Before the fix a
        // header member name threw a raw InvalidOperationException out of the verifier, and a header
        // extension value was decoded and failed later, at the signature check.
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var claims = new JsonObject { ["iss"] = "https://issuer.example.com", ["given_name"] = "John" };
        var issued = await SdJwtIssuer.IssueAsync(
            claims, new DisclosureFrame().Disclose("given_name"), issuer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });
        var sdJwt = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));

        byte[] Malformed(string prefix) => placement == "member-name"
            ? [.. U8(prefix), (byte)'"', .. Bad, .. U8("\":1}")]
            : [.. U8(prefix), .. U8("\"x\":\""), .. Bad, .. U8("\"}")];
        var header = segment == "header"
            ? Malformed("""{"alg":"ES256","typ":"kb+jwt",""")
            : U8("""{"alg":"ES256","typ":"kb+jwt"}""");
        var payload = segment == "payload"
            ? Malformed("""{"iat":1,"aud":"https://verifier.example.org","nonce":"n1",""")
            : U8("""{"iat":1,"aud":"https://verifier.example.org","nonce":"n1"}""");
        var kbJwt = $"{Base64Url.Encode(header)}.{Base64Url.Encode(payload)}.{Base64Url.Encode(new byte[64])}";

        SdJwtVerificationResult? result = null;
        var act = () => result = SdJwtVerifier.Verify(sdJwt + kbJwt, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = "https://verifier.example.org",
            ExpectedNonce = "n1",
        });

        act.Should().NotThrow("a holder-supplied Key Binding JWT must never crash the verifier");
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("KB_JWT_MALFORMED").And.Contain("not valid UTF-8");
    }

    [Theory]
    [InlineData("object-property-name")]
    [InlineData("array-element-value")]
    public void Disclosure_Parse_WithNonUtf8_IsMalformed(string placement)
    {
        // The object-property name crashed (transcoded by GetValue<string>); the array-element
        // value was silently accepted (DeepClone never transcodes). Both are now rejected.
        byte[] bytes = placement == "object-property-name"
            ? [.. U8("[\"salt\",\""), .. Bad, .. U8("\",\"v\"]")]
            : [.. U8("[\"salt\",\""), .. Bad, .. U8("\"]")];

        var act = () => Disclosure.Parse(Base64Url.Encode(bytes));

        act.Should().Throw<MalformedJoseException>().WithMessage("*not valid UTF-8*");
    }

    [Theory]
    [InlineData("header")]
    [InlineData("payload")]
    public void CompactJwt_Decode_WithNonUtf8MemberName_IsMalformed(string segment)
    {
        byte[] header = segment == "header"
            ? [.. U8("""{"alg":"EdDSA","""), (byte)'"', .. Bad, .. U8("\":1}")]
            : U8("""{"alg":"EdDSA"}""");
        byte[] payload = segment == "payload"
            ? [.. U8("""{"iss":"i","""), (byte)'"', .. Bad, .. U8("\":1}")]
            : U8("""{"iss":"i"}""");

        var act = () => CompactJwt.Decode($"{Base64Url.Encode(header)}.{Base64Url.Encode(payload)}.{Base64Url.Encode(new byte[64])}");

        act.Should().Throw<MalformedJoseException>().WithMessage("*not valid UTF-8*");
    }

    // ── One layer up: the caller's .NET string is not well-formed UTF-16 ──────────────────────

    [Fact]
    public void JwsParser_Parse_StringWithLoneSurrogate_IsMalformed_NotArgumentException()
    {
        // JsonDocument.Parse(string) transcodes to UTF-8 first and reports a lone surrogate as
        // ArgumentException. Not reachable from wire bytes decoded by .NET (they become U+FFFD) —
        // only from a caller's own text — but it escaped the documented contract all the same.
        var act = () => JwsParser.Parse("{\"payload\":\"e30\",\"protected\":\"\ud800\",\"signature\":\"AA\"}", _ => null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*UTF-16*");
    }

    [Fact]
    public void JweParser_Parse_StringWithLoneSurrogate_IsMalformed_NotArgumentException()
    {
        var act = () => JweParser.Parse("{\"protected\":\"\ud800\"}", new DictionarySecretsLookup([]), senderKeys: null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*UTF-16*");
    }
}
