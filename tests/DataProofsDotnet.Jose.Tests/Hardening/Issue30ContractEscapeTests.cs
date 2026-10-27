using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Issue #30: three input classes escaped the documented contracts — <c>SdJwtVerifier.Verify</c>,
/// <c>SdJwtVcVerifier.VerifyAsync</c> and <c>JwtHandler.Verify</c> never throw for an invalid token,
/// and the parsers fail only as <see cref="MalformedJoseException"/> or <see cref="JoseCryptoException"/>.
/// <list type="number">
/// <item>A JSON escape for an unpaired UTF-16 surrogate (<c>\uD800</c>). It is valid UTF-8, so the
/// issue #28 check passed it, and System.Text.Json throws <see cref="InvalidOperationException"/> when
/// the string — or a member name it compares — is transcoded. Most placements crashed a verifier
/// before any signature check; an unread one was accepted, and a signed JWT carrying one in an
/// unregistered claim verified and then crashed the consumer that read the claim. RFC 8259 §8.2
/// calls such a string's behaviour "unpredictable"; RFC 7493 §2.1 forbids it.</item>
/// <item><c>JwtClaims.Parse</c> with a non-object root threw from <c>JsonObject.Create</c>.</item>
/// <item><c>JweParser</c> with <c>"protected": ""</c> threw <see cref="ArgumentException"/>.</item>
/// </list>
/// Every negative case asserts the exact fixed message, so each fails against the pre-fix code
/// whichever way that code mishandled it (raw exception, a different message, or acceptance). The
/// over-rejection guards prove that well-formed escapes — a surrogate <em>pair</em>, <c>é</c>,
/// <c>\/</c> — still read back on every path.
/// </summary>
public sealed class Issue30ContractEscapeTests
{
    private static readonly JoseCryptoProvider Jose = new();

    /// <summary>JSON escapes that denote no Unicode scalar value, each a different reader fault.</summary>
    private static readonly string[] LoneSurrogates =
    [
        @"\uD800",       // high surrogate, end of string
        @"\uDC00",       // low surrogate with no high surrogate before it
        @"\uD800A",      // high surrogate followed by a plain character
        @"\uD800\uD800", // high surrogate followed by another high surrogate
    ];

    /// <summary>Well-formed escapes the check must let through: a surrogate pair, a BMP escape, an escaped solidus.</summary>
    private const string WellFormedEscapes = @"😀 é a\/b";

    private const string WellFormedDecoded = "\U0001F600 é a/b";

    private static readonly TestKeyMaterial Signer = TestKeyMaterial.Generate(KeyType.Ed25519, "k1");

    private static readonly byte[] CredentialPayload = U8(
        """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:issuer","credentialSubject":{"id":"did:example:s"}}""");

    // ── JSON text helpers. Plain concatenation, so an escape is spliced in verbatim. ─────────────

    private static byte[] U8(string s) => Encoding.UTF8.GetBytes(s);

    private static string B64(string json) => Base64Url.Encode(U8(json));

    private static string Obj(params string[] members) => "{" + string.Join(",", members.Where(m => m.Length > 0)) + "}";

    private static string Arr(params string[] items) => "[" + string.Join(",", items) + "]";

    private static string M(string name, string valueJson) => $"\"{name}\":{valueJson}";

    private static string S(string value) => $"\"{value}\"";

    private static (string Protected, string Payload, string Signature) Split3(string compact)
    {
        var parts = compact.Split('.');
        return (parts[0], parts[1], parts[2]);
    }

    /// <summary>
    /// Signs a hand-written header and payload exactly as given — <see cref="JwsBuilder"/> cannot emit
    /// these headers. Ed25519 output is already JOSE-native, so the raw signature needs no transcoding.
    /// </summary>
    private static async Task<string> SignCompactAsync(TestKeyMaterial key, string headerJson, byte[] payload)
    {
        var signingInput = $"{B64(headerJson)}.{Base64Url.Encode(payload)}";
        var signature = await key.Signer.Signer.SignAsync(Encoding.ASCII.GetBytes(signingInput), CancellationToken.None);
        return $"{signingInput}.{Base64Url.Encode(signature)}";
    }

    private static TheoryData<TPlacement, string> Cases<TPlacement>(IEnumerable<TPlacement> placements)
    {
        var data = new TheoryData<TPlacement, string>();
        foreach (var placement in placements)
            foreach (var escape in LoneSurrogates)
                data.Add(placement, escape);
        return data;
    }

    private static TheoryData<string, TPlacement, string> CasesByEntryPoint<TPlacement>(IEnumerable<(string EntryPoint, TPlacement Placement)> pairs)
    {
        var data = new TheoryData<string, TPlacement, string>();
        foreach (var (entryPoint, placement) in pairs)
            foreach (var escape in LoneSurrogates)
                data.Add(entryPoint, placement, escape);
        return data;
    }

    private static IEnumerable<(string, T)> Cross<T>(IEnumerable<string> entryPoints, Func<string, T, bool>? include = null)
        where T : struct, Enum
        => from entryPoint in entryPoints
           from placement in Enum.GetValues<T>()
           where include?.Invoke(entryPoint, placement) ?? true
           select (entryPoint, placement);

    // ── 1. JWS protected header, every serialization (RFC 7515 §5.2 step 3) ───────────────────

    public enum JwsHeaderPlacement
    {
        /// <summary><c>{…, "\uD800": 1}</c> — failed as "not valid JSON"/"malformed" before the fix.</summary>
        MemberName,

        /// <summary><c>"kid": "\uD800"</c> — a modelled field; failed as "not valid JSON".</summary>
        KidValue,

        /// <summary><c>"x": "\uD800"</c> — never read, so it was accepted and the JWS verified.</summary>
        ExtensionValue,

        /// <summary><c>"cty": "\uD800"</c> — VcJose read it and threw a raw InvalidOperationException.</summary>
        CtyValue,
    }

    private static readonly string[] JwsEntryPoints =
        ["flattened", "general", "compact", "vcjose", "flattened-detached", "compact-detached"];

    public static TheoryData<string, JwsHeaderPlacement, string> JwsHeaderCases()
        => CasesByEntryPoint(Cross<JwsHeaderPlacement>(JwsEntryPoints));

    [Theory]
    [MemberData(nameof(JwsHeaderCases))]
    public async Task JwsProtectedHeader_WithUnpairedSurrogateEscape_IsMalformed_BeforeKeyResolution(
        string entryPoint, JwsHeaderPlacement placement, string escape)
    {
        // Genuinely signed: the escape is the key holder's doing, as in the report.
        var header = Obj(
            M("alg", S("EdDSA")),
            M("typ", S("vc+jwt")),
            M("cty", S(placement == JwsHeaderPlacement.CtyValue ? escape : "vc")),
            M("kid", S(placement == JwsHeaderPlacement.KidValue ? escape : "k1")),
            placement switch
            {
                JwsHeaderPlacement.MemberName => M(escape, "1"),
                JwsHeaderPlacement.ExtensionValue => M("x", S(escape)),
                _ => "",
            });
        var compact = await SignCompactAsync(Signer, header, CredentialPayload);
        var resolverCalled = false;

        var act = () => InvokeJws(entryPoint, compact, _ =>
        {
            resolverCalled = true;
            return Signer.PublicJwk;
        });

        act.Should().Throw<MalformedJoseException>()
            .WithMessage("JWS protected header contains an unpaired UTF-16 surrogate escape.");
        resolverCalled.Should().BeFalse("the header is rejected before any key resolution");
    }

    [Theory]
    [InlineData("flattened")]
    [InlineData("general")]
    [InlineData("compact")]
    [InlineData("vcjose")]
    [InlineData("flattened-detached")]
    [InlineData("compact-detached")]
    public async Task JwsProtectedHeader_WithWellFormedEscapes_StillVerifies(string entryPoint)
    {
        // Every placement above, escaped well: "vc" and "k1" spelled with \u escapes, plus an
        // escaped member name carrying a surrogate pair.
        var header = Obj(
            M("alg", S("EdDSA")),
            M("typ", S("vc+jwt")),
            M("cty", S(@"vc")),
            M("kid", S(@"k1")),
            M(@"é", S(WellFormedEscapes)));
        var compact = await SignCompactAsync(Signer, header, CredentialPayload);
        string? resolvedKid = null;

        var payload = InvokeJws(entryPoint, compact, kid =>
        {
            resolvedKid = kid;
            return Signer.PublicJwk;
        });

        payload.Should().Equal(CredentialPayload);
        resolvedKid.Should().Be("k1");
    }

    private static byte[] InvokeJws(string entryPoint, string compact, Func<string, Jwk?> resolver)
    {
        var (p, pl, s) = Split3(compact);
        return entryPoint switch
        {
            "flattened" => JwsParser.Parse(Obj(M("payload", S(pl)), M("protected", S(p)), M("signature", S(s))), resolver, Jose).PayloadBytes,
            "general" => JwsParser.Parse(Obj(M("payload", S(pl)), M("signatures", Arr(Obj(M("protected", S(p)), M("signature", S(s)))))), resolver, Jose).PayloadBytes,
            "compact" => JwsParser.ParseCompact(compact, resolver, Jose).PayloadBytes,
            "vcjose" => VcJose.VerifyCredential(compact, resolver, Jose),
            "flattened-detached" => JwsParser.Parse(Obj(M("protected", S(p)), M("signature", S(s))), Base64Url.Decode(pl), resolver, Jose).PayloadBytes,
            "compact-detached" => JwsParser.ParseCompact($"{p}..{s}", Base64Url.Decode(pl), resolver, Jose).PayloadBytes,
            _ => throw new ArgumentOutOfRangeException(nameof(entryPoint), entryPoint, "unknown entry point"),
        };
    }

    // ── 2. JWS JSON serialization: the outer JSON text ─────────────────────────────────────────

    public enum JwsJsonPlacement
    {
        PayloadValue,
        ProtectedValue,
        SignatureValue,
        UnprotectedKidValue,
        UnprotectedMemberName,

        /// <summary>Never read: accepted and verified before the fix.</summary>
        UnprotectedMemberValue,

        TopLevelMemberName,

        /// <summary>Never read: accepted and verified before the fix.</summary>
        TopLevelMemberValue,

        /// <summary>An extra member inside a General <c>signatures[]</c> entry.</summary>
        SignatureEntryMemberName,
    }

    private static readonly string[] JwsJsonEntryPoints = ["flattened", "general", "flattened-detached"];

    public static TheoryData<string, JwsJsonPlacement, string> JwsJsonCases()
        => CasesByEntryPoint(Cross<JwsJsonPlacement>(JwsJsonEntryPoints, (entryPoint, placement) => placement switch
        {
            JwsJsonPlacement.PayloadValue => entryPoint != "flattened-detached",
            JwsJsonPlacement.SignatureEntryMemberName => entryPoint == "general",
            _ => true,
        }));

    [Theory]
    [MemberData(nameof(JwsJsonCases))]
    public async Task JwsJson_WithUnpairedSurrogateEscape_IsMalformed(string entryPoint, JwsJsonPlacement placement, string escape)
    {
        var compact = await SignCompactAsync(Signer, """{"alg":"EdDSA"}""", CredentialPayload);
        var json = JwsJson(entryPoint, compact, placement, escape, kid: "k1");

        var act = () => InvokeJwsJson(entryPoint, json, compact, _ => Signer.PublicJwk);

        act.Should().Throw<MalformedJoseException>().WithMessage("JWS contains an unpaired UTF-16 surrogate escape.");
    }

    [Theory]
    [InlineData("flattened")]
    [InlineData("general")]
    [InlineData("flattened-detached")]
    public async Task JwsJson_WithWellFormedEscapes_StillVerifies(string entryPoint)
    {
        // Escapes in the unprotected kid, an unprotected member, and an extra top-level member.
        var compact = await SignCompactAsync(Signer, """{"alg":"EdDSA"}""", CredentialPayload);
        var json = JwsJson(entryPoint, compact, placement: null, WellFormedEscapes, kid: @"k1");

        var result = InvokeJwsJson(entryPoint, json, compact, kid => kid == "k1" ? Signer.PublicJwk : null);

        result.PayloadBytes.Should().Equal(CredentialPayload);
        result.SignerKid.Should().Be("k1");
    }

    /// <summary>Builds the JSON serialization of <paramref name="compact"/>, with the kid unprotected and <paramref name="escape"/> at <paramref name="placement"/>.</summary>
    private static string JwsJson(string entryPoint, string compact, JwsJsonPlacement? placement, string escape, string kid)
    {
        var (p, pl, s) = Split3(compact);
        string At(JwsJsonPlacement target, string value) => placement == target ? escape : value;

        var unprotected = Obj(
            M("kid", S(At(JwsJsonPlacement.UnprotectedKidValue, kid))),
            placement switch
            {
                JwsJsonPlacement.UnprotectedMemberName => M(escape, "1"),
                JwsJsonPlacement.UnprotectedMemberValue => M("x", S(escape)),
                null => M("x", S(escape)),
                _ => "",
            });
        var signature = new[]
        {
            M("protected", S(At(JwsJsonPlacement.ProtectedValue, p))),
            M("header", unprotected),
            M("signature", S(At(JwsJsonPlacement.SignatureValue, s))),
            placement == JwsJsonPlacement.SignatureEntryMemberName ? M(escape, "1") : "",
        };
        var topLevel = placement switch
        {
            JwsJsonPlacement.TopLevelMemberName => M(escape, "1"),
            JwsJsonPlacement.TopLevelMemberValue or null => M("x", S(escape)),
            _ => "",
        };
        var payload = entryPoint == "flattened-detached" ? "" : M("payload", S(At(JwsJsonPlacement.PayloadValue, pl)));

        return entryPoint == "general"
            ? Obj(payload, M("signatures", Arr(Obj(signature))), topLevel)
            : Obj([payload, .. signature, topLevel]);
    }

    private static JwsParseResult InvokeJwsJson(string entryPoint, string json, string compact, Func<string, Jwk?> resolver)
        => entryPoint == "flattened-detached"
            ? JwsParser.Parse(json, Base64Url.Decode(Split3(compact).Payload), resolver, Jose)
            : JwsParser.Parse(json, resolver, Jose);

    // ── 3. JWE JSON serialization: the outer JSON text ─────────────────────────────────────────

    private static readonly TestKeyMaterial Bob = TestKeyMaterial.Generate(KeyType.X25519, "bob-key");

    private static readonly byte[] Plaintext = U8("""{"hello":"world"}""");

    private sealed record JweParts(string Protected, string Kid, string EncryptedKey, string Iv, string Ciphertext, string Tag);

    private static readonly Lazy<JweParts> BaseJwe = new(() =>
    {
        var packed = JweBuilder.BuildEcdhEsA256Kw(Plaintext, [Bob.PublicJwk], JoseAlgorithms.A256Gcm, Jose);
        var root = JsonNode.Parse(packed)!;
        var recipient = root["recipients"]![0]!;
        return new JweParts(
            (string)root["protected"]!,
            (string)recipient["header"]!["kid"]!,
            (string)recipient["encrypted_key"]!,
            (string)root["iv"]!,
            (string)root["ciphertext"]!,
            (string)root["tag"]!);
    });

    public enum JweJsonPlacement
    {
        ProtectedValue,
        IvValue,
        CiphertextValue,
        TagValue,
        EncryptedKeyValue,
        RecipientKidValue,
        RecipientHeaderMemberName,

        /// <summary>Never read: accepted and decrypted before the fix.</summary>
        RecipientHeaderMemberValue,

        RecipientMemberName,
        TopLevelMemberName,

        /// <summary>Never read: accepted and decrypted before the fix.</summary>
        TopLevelMemberValue,
    }

    private static readonly string[] JweEntryPoints = ["parse", "peek", "parse-async"];

    public static TheoryData<string, JweJsonPlacement, string> JweJsonCases()
        => CasesByEntryPoint(Cross<JweJsonPlacement>(JweEntryPoints));

    [Theory]
    [MemberData(nameof(JweJsonCases))]
    public async Task JweJson_WithUnpairedSurrogateEscape_IsMalformed_BeforeKeyWork(string entryPoint, JweJsonPlacement placement, string escape)
    {
        var json = JweJson(BaseJwe.Value, placement, escape);

        var act = () => InvokeJweAsync(entryPoint, json);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("JWE contains an unpaired UTF-16 surrogate escape.");
    }

    [Theory]
    [InlineData("parse")]
    [InlineData("peek")]
    [InlineData("parse-async")]
    public async Task JweJson_RebuiltControl_Decrypts(string entryPoint)
    {
        // Proves the rebuilt envelope is sound, so every failure above is the escape check.
        var kids = await InvokeJweAsync(entryPoint, JweJson(BaseJwe.Value, placement: null, escape: null));

        kids.Should().Equal("bob-key");
    }

    [Theory]
    [InlineData("parse")]
    [InlineData("peek")]
    [InlineData("parse-async")]
    public async Task JweJson_WithWellFormedEscapes_StillDecrypts(string entryPoint)
    {
        // The recipient kid spelled with a \u escape (it feeds key lookup and the apv commitment),
        // plus escapes in an unread recipient-header member and an unread top-level member.
        var parts = BaseJwe.Value with { Kid = @"bob-key" };

        var kids = await InvokeJweAsync(entryPoint, JweJson(parts, placement: null, WellFormedEscapes));

        kids.Should().Equal("bob-key");
    }

    /// <summary>Rebuilds the General JSON envelope from <paramref name="parts"/>, with <paramref name="escape"/> at <paramref name="placement"/> (or, for null, in unread members only).</summary>
    private static string JweJson(JweParts parts, JweJsonPlacement? placement, string? escape)
    {
        string At(JweJsonPlacement target, string value) => placement == target ? escape! : value;
        var unread = placement is null && escape is not null;

        var header = Obj(
            M("kid", S(At(JweJsonPlacement.RecipientKidValue, parts.Kid))),
            placement == JweJsonPlacement.RecipientHeaderMemberName ? M(escape!, "1") : "",
            placement == JweJsonPlacement.RecipientHeaderMemberValue || unread ? M("x", S(escape!)) : "");
        var recipient = Obj(
            M("header", header),
            M("encrypted_key", S(At(JweJsonPlacement.EncryptedKeyValue, parts.EncryptedKey))),
            placement == JweJsonPlacement.RecipientMemberName ? M(escape!, "1") : "");
        return Obj(
            M("protected", S(At(JweJsonPlacement.ProtectedValue, parts.Protected))),
            M("recipients", Arr(recipient)),
            M("iv", S(At(JweJsonPlacement.IvValue, parts.Iv))),
            M("ciphertext", S(At(JweJsonPlacement.CiphertextValue, parts.Ciphertext))),
            M("tag", S(At(JweJsonPlacement.TagValue, parts.Tag))),
            placement == JweJsonPlacement.TopLevelMemberName ? M(escape!, "1") : "",
            placement == JweJsonPlacement.TopLevelMemberValue || unread ? M("y", S(escape!)) : "");
    }

    /// <summary>Runs one JWE JSON entry point and returns the recipient kids it reports.</summary>
    private static async Task<IReadOnlyList<string>> InvokeJweAsync(string entryPoint, string json)
    {
        switch (entryPoint)
        {
            case "parse":
                var parsed = JweParser.Parse(json, new DictionarySecretsLookup([Bob.PrivateJwk]), senderKeys: null, Jose);
                parsed.Plaintext.Should().Equal(Plaintext);
                return [parsed.RecipientKid];
            case "peek":
                return JweParser.PeekRecipients(json).RecipientKids;
            case "parse-async":
                var key = new RawEcdhKey(Bob.PrivateJwk.Crv!, Base64Url.Decode(Bob.PrivateJwk.D!), Jose);
                var parsedAsync = await JweParser.ParseAsync(json, key, senderKeys: null, Jose);
                parsedAsync.Plaintext.Should().Equal(Plaintext);
                return [parsedAsync.RecipientKid];
            default:
                throw new ArgumentOutOfRangeException(nameof(entryPoint), entryPoint, "unknown entry point");
        }
    }

    // ── 4. JWE protected header (RFC 7516 §5.2 step 3) ─────────────────────────────────────────

    public enum JweHeaderPlacement
    {
        MemberName,

        /// <summary>The modelled <c>kid</c>; failed as "not valid JSON" before the fix.</summary>
        KidValue,

        /// <summary>An extension value: accepted at decode before the fix, failing only later, at the AEAD tag.</summary>
        ExtensionValue,
    }

    private static readonly string[] JweHeaderEntryPoints = ["parse", "peek", "parse-async", "compact", "compact-async"];

    public static TheoryData<string, JweHeaderPlacement, string> JweHeaderCases()
        => CasesByEntryPoint(Cross<JweHeaderPlacement>(JweHeaderEntryPoints));

    [Theory]
    [MemberData(nameof(JweHeaderCases))]
    public async Task JweProtectedHeader_WithUnpairedSurrogateEscape_IsMalformed_BeforeKeyWork(
        string entryPoint, JweHeaderPlacement placement, string escape)
    {
        var header = Obj(
            M("alg", S(JoseAlgorithms.EcdhEsA256Kw)),
            M("enc", S(JoseAlgorithms.A256Gcm)),
            M("kid", S(placement == JweHeaderPlacement.KidValue ? escape : "bob-key")),
            placement switch
            {
                JweHeaderPlacement.MemberName => M(escape, "1"),
                JweHeaderPlacement.ExtensionValue => M("x", S(escape)),
                _ => "",
            });
        var parts = BaseJwe.Value with { Protected = B64(header) };

        Func<Task> act = entryPoint switch
        {
            "compact" => () => Task.FromResult(JweParser.ParseCompact(CompactJwe(parts), Bob.PrivateJwk, senderKeys: null, Jose)),
            "compact-async" => () => JweParser.ParseCompactAsync(
                CompactJwe(parts), new RawEcdhKey(Bob.PrivateJwk.Crv!, Base64Url.Decode(Bob.PrivateJwk.D!), Jose), senderKeys: null, Jose),
            _ => () => InvokeJweAsync(entryPoint, JweJson(parts, placement: null, escape: null)),
        };

        await act.Should().ThrowAsync<MalformedJoseException>()
            .WithMessage("JWE protected header contains an unpaired UTF-16 surrogate escape.");
    }

    private static string CompactJwe(JweParts parts)
        => string.Join('.', parts.Protected, parts.EncryptedKey, parts.Iv, parts.Ciphertext, parts.Tag);

    [Fact]
    public void CompactJwe_HandSealedOverUnpairedSurrogateExtensionValue_IsMalformed_BeforeDecryption()
    {
        // Sealed over this exact header, so before the fix it decrypted: the extension value was
        // never transcoded. It is rejected now, before any key work.
        var (compact, kek) = SealA256KwA256Gcm(Obj(M("alg", S("A256KW")), M("enc", S("A256GCM")), M("kid", S("kek-1")), M("x", S(@"\uD800"))));

        var act = () => JweParser.ParseCompact(compact, kek, senderKeys: null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("JWE protected header contains an unpaired UTF-16 surrogate escape.");
    }

    [Fact]
    public void CompactJwe_HandSealedOverWellFormedEscapes_Decrypts()
    {
        // Control for the test above, and an over-rejection guard: the same sealing, with
        // well-formed escapes in the modelled kid and in an extension value.
        var (compact, kek) = SealA256KwA256Gcm(Obj(M("alg", S("A256KW")), M("enc", S("A256GCM")), M("kid", S(@"kek-1")), M("x", S(WellFormedEscapes))));

        var result = JweParser.ParseCompact(compact, kek, senderKeys: null, Jose);

        result.Plaintext.Should().Equal(Plaintext);
    }

    private static (string Compact, Jwk Kek) SealA256KwA256Gcm(string headerJson)
    {
        // Mirrors JweBuilder's sealing: CEK + IV from the provider's CSPRNG, AAD = ASCII(base64url(header)).
        var kek = new byte[32];
        Jose.Fill(kek);
        var kekJwk = new Jwk { Kty = "oct", K = Base64Url.Encode(kek), Kid = "kek-1" };
        var cek = new byte[32];
        var iv = new byte[12];
        Jose.Fill(cek);
        Jose.Fill(iv);

        var protectedB64u = B64(headerJson);
        var (ciphertext, tag) = Jose.AeadEncrypt(JoseAlgorithms.A256Gcm, cek, iv, Encoding.ASCII.GetBytes(protectedB64u), Plaintext);
        var encryptedKey = Jose.KeyWrap(JoseAlgorithms.A256Kw, kek, cek);

        var compact = string.Join('.',
            protectedB64u, Base64Url.Encode(encryptedKey), Base64Url.Encode(iv), Base64Url.Encode(ciphertext), Base64Url.Encode(tag));
        return (compact, kekJwk);
    }

    // ── 5. Empty JWE "protected" (RFC 7516 §7.2.1) ─────────────────────────────────────────────

    [Theory]
    [InlineData("parse")]
    [InlineData("peek")]
    [InlineData("parse-async")]
    public async Task JweJson_WithEmptyProtected_IsMalformed_NotArgumentException(string entryPoint)
    {
        // The JWS counterpart already said "JWS protected header is empty."; the JWE one threw
        // ArgumentException from an argument guard, before any key work.
        var json = JweJson(BaseJwe.Value with { Protected = "" }, placement: null, escape: null);

        var act = () => InvokeJweAsync(entryPoint, json);

        await act.Should().ThrowAsync<MalformedJoseException>().WithMessage("JWE protected header is empty.");
    }

    // ── 6. JWT claims set (RFC 7519 §7.2 step 10) ──────────────────────────────────────────────

    public enum ClaimsPlacement
    {
        ClaimName,
        Iss,
        Sub,
        Jti,
        AudString,
        AudArrayElement,

        /// <summary>Accepted before the fix, and <c>JwtHandler.Verify</c> reported the token valid.</summary>
        UnregisteredValue,

        NestedKey,
        NestedValue,
    }

    private static string ClaimsWith(ClaimsPlacement placement, string escape) => placement switch
    {
        ClaimsPlacement.ClaimName => Obj(M("iss", S("i")), M(escape, "1")),
        ClaimsPlacement.Iss => Obj(M("iss", S(escape))),
        ClaimsPlacement.Sub => Obj(M("iss", S("i")), M("sub", S(escape))),
        ClaimsPlacement.Jti => Obj(M("iss", S("i")), M("jti", S(escape))),
        ClaimsPlacement.AudString => Obj(M("iss", S("i")), M("aud", S(escape))),
        ClaimsPlacement.AudArrayElement => Obj(M("iss", S("i")), M("aud", Arr(S("a"), S(escape)))),
        ClaimsPlacement.UnregisteredValue => Obj(M("iss", S("i")), M("x", S(escape))),
        ClaimsPlacement.NestedKey => Obj(M("iss", S("i")), M("x", Obj(M(escape, "1")))),
        ClaimsPlacement.NestedValue => Obj(M("iss", S("i")), M("x", Obj(M("y", Arr(S(escape)))))),
        _ => throw new ArgumentOutOfRangeException(nameof(placement)),
    };

    public static TheoryData<ClaimsPlacement, string> ClaimsCases() => Cases(Enum.GetValues<ClaimsPlacement>());

    [Theory]
    [MemberData(nameof(ClaimsCases))]
    public void JwtClaims_Parse_WithUnpairedSurrogateEscape_IsMalformed(ClaimsPlacement placement, string escape)
    {
        var act = () => JwtClaims.Parse(U8(ClaimsWith(placement, escape)));

        act.Should().Throw<MalformedJoseException>().WithMessage("JWT claims set contains an unpaired UTF-16 surrogate escape.");
    }

    [Theory]
    [MemberData(nameof(ClaimsCases))]
    public async Task JwtHandler_Verify_SignedClaimsWithUnpairedSurrogateEscape_IsMalformed_NeverThrows(ClaimsPlacement placement, string escape)
    {
        // Signed through JwsBuilder with raw payload bytes — the only way to produce one: JwtClaims
        // serializes from .NET strings, which write a lone surrogate as U+FFFD.
        var jwt = await JwsBuilder.BuildCompactAsync(U8(ClaimsWith(placement, escape)), Signer.Signer, typ: "JWT");

        JwtVerificationResult? result = null;
        var act = () => result = JwtHandler.Verify(jwt, _ => Signer.PublicJwk);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Claims.Should().BeNull("no claims model is handed back that would throw when read");
        result.Errors.Should().ContainSingle().Which.Should().Be("MALFORMED: JWT claims set contains an unpaired UTF-16 surrogate escape.");
    }

    [Fact]
    public async Task JwtHandler_Verify_IssueModelPoisoningCase_IsNoLongerValid()
    {
        // The exact case from the report: before the fix this verified (IsValid == true) and then
        // AdditionalClaims["x"].GetValue<string>(), ToJsonString() and ToJsonBytes() threw
        // InvalidOperationException in the consumer's own code.
        var jwt = await JwsBuilder.BuildCompactAsync(U8("""{"iss":"i","x":"\uD800"}"""), Signer.Signer, typ: "JWT");

        var result = JwtHandler.Verify(jwt, _ => Signer.PublicJwk);

        result.IsValid.Should().BeFalse();
        result.Claims.Should().BeNull();
    }

    [Theory]
    [InlineData("member-name")]
    [InlineData("kid-value")]
    [InlineData("typ-value")]
    public async Task JwtHandler_Verify_HeaderWithUnpairedSurrogateEscape_IsMalformed_NeverThrows(string placement)
    {
        var header = placement switch
        {
            "member-name" => """{"alg":"EdDSA","typ":"JWT","\uD800":1}""",
            "kid-value" => """{"alg":"EdDSA","typ":"JWT","kid":"\uD800"}""",
            _ => """{"alg":"EdDSA","typ":"\uD800"}""",
        };
        var jwt = await SignCompactAsync(Signer, header, U8("""{"iss":"i"}"""));

        JwtVerificationResult? result = null;
        var act = () => result = JwtHandler.Verify(jwt, _ => Signer.PublicJwk);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Be("MALFORMED: JWS protected header contains an unpaired UTF-16 surrogate escape.");
    }

    private const string WellFormedClaims = """{"iss":"i","aud":["😀"],"x":"😀 é a\/b","é":{"y":["a\/b"]}}""";

    [Fact]
    public void JwtClaims_Parse_WithWellFormedEscapes_ReadsBack()
    {
        var claims = JwtClaims.Parse(U8(WellFormedClaims));

        claims.Issuer.Should().Be("i");
        claims.Audiences.Should().Equal("\U0001F600");
        claims.AdditionalClaims["x"]!.GetValue<string>().Should().Be(WellFormedDecoded);
        claims.AdditionalClaims["é"]!["y"]![0]!.GetValue<string>().Should().Be("a/b");
        var roundTrip = () => JwtClaims.Parse(claims.ToJsonBytes());
        roundTrip.Should().NotThrow();
    }

    [Fact]
    public async Task JwtHandler_Verify_WithWellFormedEscapes_IsValid()
    {
        var jwt = await JwsBuilder.BuildCompactAsync(U8(WellFormedClaims), Signer.Signer, typ: "JWT");

        var result = JwtHandler.Verify(jwt, _ => Signer.PublicJwk);

        result.IsValid.Should().BeTrue();
        result.Claims!.AdditionalClaims["x"]!.GetValue<string>().Should().Be(WellFormedDecoded);
    }

    // ── 7. JWT claims set with a non-object root ───────────────────────────────────────────────

    [Theory]
    [InlineData("[]")]
    [InlineData("42")]
    [InlineData("\"x\"")]
    [InlineData("true")]
    [InlineData("null")]
    public void JwtClaims_Parse_NonObjectRoot_IsMalformed_NotInvalidOperationException(string root)
    {
        // null already failed correctly; the other four threw from JsonObject.Create.
        var act = () => JwtClaims.Parse(U8(root));

        act.Should().Throw<MalformedJoseException>().WithMessage("JWT claims set is not a JSON object.");
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("42")]
    [InlineData("\"x\"")]
    [InlineData("true")]
    [InlineData("null")]
    public async Task JwtHandler_Verify_SignedNonObjectRoot_IsMalformed_NeverThrows(string root)
    {
        var jwt = await JwsBuilder.BuildCompactAsync(U8(root), Signer.Signer, typ: "JWT");

        JwtVerificationResult? result = null;
        var act = () => result = JwtHandler.Verify(jwt, _ => Signer.PublicJwk);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Be("MALFORMED: JWT claims set is not a JSON object.");
    }

    // ── 8. SD-JWT and SD-JWT VC: unauthenticated input (RFC 9901 §7.1 step 1) ──────────────────

    public enum SdJwtPlacement
    {
        IssuerHeaderMemberName,
        IssuerHeaderAlg,
        IssuerHeaderKid,
        IssuerHeaderTyp,

        /// <summary>Accepted at decode before the fix; failed only at the signature.</summary>
        IssuerHeaderExtensionValue,

        IssuerPayloadMemberName,
        IssuerPayloadSdAlg,

        /// <summary>Accepted at decode before the fix; failed only at the signature.</summary>
        IssuerPayloadValue,

        /// <summary>Accepted at decode before the fix (the salt is type-checked, never read).</summary>
        DisclosureSalt,

        DisclosureClaimName,

        /// <summary>Accepted at decode before the fix.</summary>
        DisclosureValue,

        DisclosureNestedMemberName,
        ArrayElementDisclosureValue,
    }

    public static TheoryData<string, SdJwtPlacement, string> SdJwtCases()
        => CasesByEntryPoint(Cross<SdJwtPlacement>(["sd-jwt", "sd-jwt-vc"]));

    [Theory]
    [MemberData(nameof(SdJwtCases))]
    public async Task SdJwtVerifier_UnauthenticatedPresentationWithUnpairedSurrogateEscape_IsMalformed_NeverThrows(
        string verifier, SdJwtPlacement placement, string escape)
    {
        // Forged: an all-zero signature, so nothing here needs the issuer's key. Before the fix most
        // placements threw a raw InvalidOperationException out of a never-throws verifier.
        var header = Obj(
            M("alg", S(placement == SdJwtPlacement.IssuerHeaderAlg ? escape : "EdDSA")),
            M("typ", S(placement == SdJwtPlacement.IssuerHeaderTyp ? escape : "dc+sd-jwt")),
            placement switch
            {
                SdJwtPlacement.IssuerHeaderMemberName => M(escape, "1"),
                SdJwtPlacement.IssuerHeaderKid => M("kid", S(escape)),
                SdJwtPlacement.IssuerHeaderExtensionValue => M("x", S(escape)),
                _ => "",
            });
        var payload = Obj(
            M("_sd_alg", S(placement == SdJwtPlacement.IssuerPayloadSdAlg ? escape : "sha-256")),
            M("vct", S("https://credentials.example.com/identity")),
            placement switch
            {
                SdJwtPlacement.IssuerPayloadMemberName => M(escape, "1"),
                SdJwtPlacement.IssuerPayloadValue => M("x", S(escape)),
                _ => "",
            });
        var disclosure = placement switch
        {
            SdJwtPlacement.DisclosureSalt => Arr(S(escape), S("n"), S("v")),
            SdJwtPlacement.DisclosureClaimName => Arr(S("salt"), S(escape), S("v")),
            SdJwtPlacement.DisclosureValue => Arr(S("salt"), S("n"), S(escape)),
            SdJwtPlacement.DisclosureNestedMemberName => Arr(S("salt"), S("n"), Obj(M(escape, "1"))),
            SdJwtPlacement.ArrayElementDisclosureValue => Arr(S("salt"), S(escape)),
            _ => null,
        };
        var presentation = $"{B64(header)}.{B64(payload)}.{Base64Url.Encode(new byte[64])}~"
            + (disclosure is null ? "" : B64(disclosure) + "~");
        var resolverCalled = false;
        Func<string, Jwk?> resolver = _ =>
        {
            resolverCalled = true;
            return Signer.PublicJwk;
        };

        bool? isValid = null;
        IReadOnlyList<string> errors = [];
        var act = async () =>
        {
            if (verifier == "sd-jwt")
            {
                var r = SdJwtVerifier.Verify(presentation, resolver);
                (isValid, errors) = (r.IsValid, r.Errors);
            }
            else
            {
                var r = await SdJwtVcVerifier.VerifyAsync(presentation, resolver);
                (isValid, errors) = (r.IsValid, r.Errors);
            }
        };

        await act.Should().NotThrowAsync("an unauthenticated presentation must never crash the verifier");
        isValid.Should().BeFalse();
        errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED: ").And.EndWith("contains an unpaired UTF-16 surrogate escape.");
        resolverCalled.Should().BeFalse("the presentation is rejected before the issuer key is resolved");
    }

    public enum DisclosurePlacement { Salt, ClaimName, Value, NestedMemberName, ArrayElementValue }

    private static string DisclosureWith(DisclosurePlacement placement, string escape) => placement switch
    {
        DisclosurePlacement.Salt => Arr(S(escape), S("n"), S("v")),
        DisclosurePlacement.ClaimName => Arr(S("salt"), S(escape), S("v")),
        DisclosurePlacement.Value => Arr(S("salt"), S("n"), S(escape)),
        DisclosurePlacement.NestedMemberName => Arr(S("salt"), S("n"), Obj(M(escape, "1"))),
        DisclosurePlacement.ArrayElementValue => Arr(S("salt"), S(escape)),
        _ => throw new ArgumentOutOfRangeException(nameof(placement)),
    };

    public static TheoryData<DisclosurePlacement, string> DisclosureCases() => Cases(Enum.GetValues<DisclosurePlacement>());

    [Theory]
    [MemberData(nameof(DisclosureCases))]
    public void Disclosure_Parse_WithUnpairedSurrogateEscape_IsMalformed(DisclosurePlacement placement, string escape)
    {
        var act = () => Disclosure.Parse(B64(DisclosureWith(placement, escape)));

        act.Should().Throw<MalformedJoseException>().WithMessage("SD-JWT Disclosure contains an unpaired UTF-16 surrogate escape.");
    }

    [Theory]
    [MemberData(nameof(DisclosureCases))]
    public void SdJwtComponents_Parse_WithUnpairedSurrogateEscapeInDisclosure_IsMalformed(DisclosurePlacement placement, string escape)
    {
        var act = () => SdJwtComponents.Parse($"a.b.c~{B64(DisclosureWith(placement, escape))}~");

        act.Should().Throw<MalformedJoseException>().WithMessage("SD-JWT Disclosure contains an unpaired UTF-16 surrogate escape.");
    }

    // ── 9. SD-JWT after a valid issuer signature (a malicious issuer) ──────────────────────────

    public enum IssuerSignedPlacement
    {
        /// <summary>Read in reconstruction, after the signature: threw before the fix.</summary>
        SdDigest,

        /// <summary>An array <c>{"...": digest}</c> placeholder, read in reconstruction.</summary>
        ArrayPlaceholderDigest,

        /// <summary>Read by <c>ToJsonString()</c> when a Key Binding JWT is presented.</summary>
        CnfJwkMemberValue,
    }

    public static TheoryData<IssuerSignedPlacement, string> IssuerSignedCases() => Cases(Enum.GetValues<IssuerSignedPlacement>());

    [Theory]
    [MemberData(nameof(IssuerSignedCases))]
    public async Task SdJwtVerifier_IssuerSignedPayloadWithUnpairedSurrogateEscape_IsMalformed_NeverThrows(
        IssuerSignedPlacement placement, string escape)
    {
        var payload = placement switch
        {
            IssuerSignedPlacement.SdDigest => Obj(M("_sd", Arr(S(escape))), M("_sd_alg", S("sha-256"))),
            IssuerSignedPlacement.ArrayPlaceholderDigest => Obj(M("a", Arr(Obj(M("...", S(escape))))), M("_sd_alg", S("sha-256"))),
            _ => Obj(M("_sd_alg", S("sha-256")), M("cnf", Obj(M("jwk", Obj(M("kty", S("OKP")), M("crv", S("Ed25519")), M("x", S(escape))))))),
        };
        var issuerJwt = await JwsBuilder.BuildCompactAsync(U8(payload), Signer.Signer, typ: "example+sd-jwt");
        // A Key Binding JWT is appended so the cnf case reaches the cnf read; its content is irrelevant.
        var presentation = issuerJwt + "~" + (placement == IssuerSignedPlacement.CnfJwkMemberValue
            ? $"{B64("""{"alg":"EdDSA","typ":"kb+jwt"}""")}.{B64("{}")}.{Base64Url.Encode(new byte[64])}"
            : "");

        SdJwtVerificationResult? result = null;
        var act = () => result = SdJwtVerifier.Verify(presentation, _ => Signer.PublicJwk);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Be("MALFORMED: Compact JWT payload contains an unpaired UTF-16 surrogate escape.");
    }

    [Fact]
    public async Task SdJwtVerifier_DisclosureWithWellFormedEscapes_Verifies()
    {
        // A hand-built issuance whose Disclosure value is spelled with escapes. The digest covers
        // the encoded Disclosure as presented, so the escaped form is what the issuer committed to.
        var disclosure = B64(Arr(S("salt-0123456789abcdef"), S(@"n"), S(WellFormedEscapes)));
        var digest = Disclosure.Parse(disclosure).ComputeDigest("sha-256");
        var issuerJwt = await JwsBuilder.BuildCompactAsync(
            U8(Obj(M("_sd", Arr(S(digest))), M("_sd_alg", S("sha-256")))), Signer.Signer, typ: "example+sd-jwt");

        var result = SdJwtVerifier.Verify($"{issuerJwt}~{disclosure}~", _ => Signer.PublicJwk);

        result.IsValid.Should().BeTrue();
        result.DisclosedPayload!["n"]!.GetValue<string>().Should().Be(WellFormedDecoded);
    }

    // ── 10. Key Binding JWT, end to end (RFC 9901 §7.3) ────────────────────────────────────────

    public enum KeyBindingPlacement
    {
        /// <summary>Read outside any try before the fix: threw before the signature check.</summary>
        HeaderTyp,

        HeaderMemberName,

        /// <summary>The remaining four were read after the holder's signature verified.</summary>
        Nonce,

        Aud,
        SdHash,
        PayloadMemberName,
    }

    private static readonly TestKeyMaterial Holder = TestKeyMaterial.Generate(KeyType.Ed25519, "holder");

    private const string Audience = "https://verifier.example.org";

    private const string Nonce = "n1";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private static readonly SdJwtVerificationOptions KeyBindingPolicy = new()
    {
        ExpectedAudience = Audience,
        ExpectedNonce = Nonce,
        CurrentTime = Now,
    };

    public static TheoryData<KeyBindingPlacement, string> KeyBindingCases() => Cases(Enum.GetValues<KeyBindingPlacement>());

    [Theory]
    [MemberData(nameof(KeyBindingCases))]
    public async Task SdJwtVerifier_KeyBindingJwtWithUnpairedSurrogateEscape_IsKbJwtMalformed_NeverThrows(
        KeyBindingPlacement placement, string escape)
    {
        // A genuine issuance bound to the holder's key, and a KB-JWT genuinely signed by the holder:
        // before the fix the payload cases passed the signature check and then crashed on the read.
        var sdJwt = await IssueBoundSdJwtAsync();
        var sdHash = SdHashAlgorithm.ComputeSdHash("sha-256", sdJwt);
        var header = Obj(
            M("alg", S("EdDSA")),
            M("typ", S(placement == KeyBindingPlacement.HeaderTyp ? escape : "kb+jwt")),
            placement == KeyBindingPlacement.HeaderMemberName ? M(escape, "1") : "");
        var payload = Obj(
            M("nonce", S(placement == KeyBindingPlacement.Nonce ? escape : Nonce)),
            M("aud", S(placement == KeyBindingPlacement.Aud ? escape : Audience)),
            M("iat", Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            M("sd_hash", S(placement == KeyBindingPlacement.SdHash ? escape : sdHash)),
            placement == KeyBindingPlacement.PayloadMemberName ? M(escape, "1") : "");
        var kbJwt = await SignCompactAsync(Holder, header, U8(payload));
        var segment = placement is KeyBindingPlacement.HeaderTyp or KeyBindingPlacement.HeaderMemberName ? "header" : "payload";

        SdJwtVerificationResult? result = null;
        var act = () => result = SdJwtVerifier.Verify(sdJwt + kbJwt, _ => Signer.PublicJwk, KeyBindingPolicy);

        act.Should().NotThrow("a holder-supplied Key Binding JWT must never crash the verifier");
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Be(
            $"KB_JWT_MALFORMED: Compact JWT {segment} contains an unpaired UTF-16 surrogate escape.");
    }

    [Fact]
    public async Task SdJwtVerifier_KeyBindingJwtWithWellFormedEscapes_Verifies()
    {
        // Control for the test above (same issuance, header and signing), with nonce and aud
        // spelled with escapes that decode to the expected values.
        var sdJwt = await IssueBoundSdJwtAsync();
        var sdHash = SdHashAlgorithm.ComputeSdHash("sha-256", sdJwt);
        var payload = Obj(
            M("nonce", S(@"n1")),
            M("aud", S(@"https:\/\/verifier.example.org")),
            M("iat", Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            M("sd_hash", S(sdHash)),
            M(@"é", S(WellFormedEscapes)));
        var kbJwt = await SignCompactAsync(Holder, """{"alg":"EdDSA","typ":"kb+jwt"}""", U8(payload));

        var result = SdJwtVerifier.Verify(sdJwt + kbJwt, _ => Signer.PublicJwk, KeyBindingPolicy);

        result.Errors.Should().BeEmpty();
        result.IsValid.Should().BeTrue();
        result.KeyBindingVerified.Should().BeTrue();
    }

    private static async Task<string> IssueBoundSdJwtAsync()
    {
        var claims = new JsonObject { ["iss"] = "https://issuer.example.com", ["given_name"] = "John" };
        var issued = await SdJwtIssuer.IssueAsync(
            claims, new DisclosureFrame().Disclose("given_name"), Signer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = Holder.PublicJwk });
        return SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));
    }
}
