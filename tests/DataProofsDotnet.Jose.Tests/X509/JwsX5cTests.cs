using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Jose.Tests.X509.TestCertificates;
using Base64Url = DataProofsDotnet.Jose.Base64Url;
using OracleJwt = global::Jose.JWT;
using OracleJwsAlgorithm = global::Jose.JwsAlgorithm;

namespace DataProofsDotnet.Jose.Tests.X509;

/// <summary>
/// Issue #46 on JWS: a signer's chain is emitted as <c>x5c</c> in the protected header, and
/// <see cref="JwsParser.ParseCompactWithCertificateChain"/> verifies with the end-entity key, then asks the caller's
/// hook. Every <c>kid</c>-resolver path is unchanged: it never reads <c>x5c</c>.
/// </summary>
public sealed class JwsX5cTests
{
    private static readonly JoseCryptoProvider Crypto = new();
    private static readonly byte[] Payload = """{"iss":"https://issuer.example","n":1}"""u8.ToArray();

    // ------------------------------------------------------------------ helpers

    /// <summary>A compact JWS over any protected header, signed by <paramref name="signer"/>.</summary>
    private static async Task<string> SignWithHeader(JsonObject header, JwsSigner signer, byte[]? payload = null)
    {
        var protectedB64u = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64u = Base64Url.Encode(payload ?? Payload);
        var signature = await signer.SignAsync(Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u), CancellationToken.None);
        return protectedB64u + "." + payloadB64u + "." + Base64Url.Encode(signature);
    }

    private static JsonArray X5c(params byte[][] certificates)
        => new(certificates.Select(c => (JsonNode?)JsonValue.Create(Convert.ToBase64String(c))).ToArray());

    private static JsonObject ProtectedHeader(string compact)
        => JsonNode.Parse(Base64Url.Decode(compact.Split('.')[0]))!.AsObject();

    private static JwsSigner WithChain(Leaf leaf, string? kid = null, params byte[][] more)
        => new(leaf.Signer.Signer, kid) { CertificateChain = X509CertificateChain.Create([leaf.Certificate, .. more.Select(m => new ReadOnlyMemory<byte>(m))]) };

    private static bool Pinned(X509CertificateChain chain, byte[] endEntity)
        => chain.EndEntityCertificate.Span.SequenceEqual(endEntity);

    // ------------------------------------------------------------------ Done when 1: round trip

    [Theory]
    [InlineData(KeyType.Ed25519, "EdDSA")]
    [InlineData(KeyType.P256, "ES256")]
    [InlineData(KeyType.P384, "ES384")]
    [InlineData(KeyType.Secp256k1, "ES256K")]
    public async Task Signing_with_a_chain_and_verifying_with_the_key_from_the_header_round_trips(KeyType keyType, string alg)
    {
        var leaf = CreateLeaf(keyType);
        var ca = RsaCertificate();
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf, null, ca), typ: "example+jwt");

        var calls = new List<X509CertificateChain>();
        var result = JwsParser.ParseCompactWithCertificateChain(compact, chain => { calls.Add(chain); return true; }, Crypto);

        result.SignatureAlgorithm.Should().Be(alg);
        result.PayloadBytes.Should().Equal(Payload);
        result.Typ.Should().Be("example+jwt");
        calls.Should().ContainSingle().Which.Should().BeSameAs(result.CertificateChain);
        result.CertificateChain!.Certificates.Select(c => c.ToArray()).Should().BeEquivalentTo(
            [leaf.Certificate, ca], o => o.WithStrictOrdering());
    }

    [Fact]
    public async Task The_chain_is_in_the_protected_header_as_padded_standard_base64_DER()
    {
        var pki = CreatePki(KeyType.P256);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, pki.SignerWithChain("did:example:issuer#1"));

        var header = ProtectedHeader(compact);
        header["x5c"]!.AsArray().Select(n => n!.GetValue<string>()).Should().Equal(
            Convert.ToBase64String(pki.Leaf.Certificate), Convert.ToBase64String(pki.Intermediate.RawData));
        header["kid"]!.GetValue<string>().Should().Be("did:example:issuer#1");
        header["alg"]!.GetValue<string>().Should().Be("ES256");
    }

    [Fact]
    public async Task A_platform_validated_chain_to_the_callers_anchor_verifies()
    {
        var pki = CreatePki(KeyType.P384);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, pki.SignerWithChain());

        var result = JwsParser.ParseCompactWithCertificateChain(compact, chain => ValidateWithAnchors(chain, pki.Root), Crypto);

        result.SignatureAlgorithm.Should().Be("ES384");
        result.CertificateChain!.EndEntityPublicKey.X.Should().Be(pki.Leaf.PublicJwk.X);
    }

    [Fact]
    public async Task A_signer_without_a_chain_emits_no_x5c()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);

        var compact = await JwsBuilder.BuildCompactAsync(Payload, new JwsSigner(leaf.Signer.Signer, "k"));

        ProtectedHeader(compact).Select(m => m.Key).Should().BeEquivalentTo(["alg", "kid"]);
        new JwsSigner(leaf.Signer.Signer).CertificateChain.Should().BeNull();
    }

    // ------------------------------------------------------------------ Done when 2: the signature must match the end-entity key

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    public async Task A_JWS_whose_signature_does_not_match_the_end_entity_key_fails(KeyType keyType)
    {
        // The header carries A's certificate; B signs. Same alg, so only the key differs.
        var a = CreateLeaf(keyType);
        var b = CreateLeaf(keyType);
        var compact = await SignWithHeader(new JsonObject { ["alg"] = b.Signer.Algorithm, ["x5c"] = X5c(a.Certificate) }, b.Signer);

        var hookCalls = 0;
        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => { hookCalls++; return true; }, Crypto);

        act.Should().Throw<JoseCryptoException>().Which.Message.Should().Contain("did not verify");
        hookCalls.Should().Be(0, "the hook only ever sees a chain whose end-entity key verified the signature");
    }

    [Theory]
    [InlineData("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")] // y = p + 1: RFC 8032 §5.1.3 step 1 fails
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")] // the identity, a small-order point
    public async Task An_Ed25519_end_entity_key_that_is_no_point_fails_closed_at_the_signature(string keyHex)
    {
        // Ed25519 keys are length-checked only, as an Ed25519 JWK is; the point is decoded by signature verification
        // (RFC 8032 §5.1.7), which refuses it before any hook runs.
        var signer = CreateLeaf(KeyType.Ed25519);
        var certificate = Assemble(Spki(Ed25519Oid, null, Convert.FromHexString(keyHex)));
        X509CertificateChain.Create([certificate]).Certificates.Should().ContainSingle();
        var compact = await SignWithHeader(new JsonObject { ["alg"] = "EdDSA", ["x5c"] = X5c(certificate) }, signer.Signer);

        var hookCalls = 0;
        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => { hookCalls++; return true; }, Crypto);

        act.Should().Throw<JoseCryptoException>().Which.Message.Should().Contain("did not verify");
        hookCalls.Should().Be(0);
    }

    [Fact]
    public async Task A_later_certificates_key_is_never_used()
    {
        // B signs and B's certificate is second: the end-entity key (A's) is the only key tried.
        var a = CreateLeaf(KeyType.P256);
        var b = CreateLeaf(KeyType.P256);
        var compact = await SignWithHeader(new JsonObject { ["alg"] = "ES256", ["x5c"] = X5c(a.Certificate, b.Certificate) }, b.Signer);

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public async Task A_tampered_payload_fails()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf));
        var segments = compact.Split('.');
        var tampered = segments[0] + "." + Base64Url.Encode("""{"iss":"https://attacker.example","n":1}"""u8.ToArray()) + "." + segments[2];

        var act = () => JwsParser.ParseCompactWithCertificateChain(tampered, _ => true, Crypto);

        act.Should().Throw<JoseCryptoException>();
    }

    // ------------------------------------------------------------------ the hook is the trust decision

    [Fact]
    public async Task A_hook_that_returns_false_fails_with_X5C_UNTRUSTED()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf));

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => false, Crypto);

        act.Should().Throw<JoseCryptoException>().Which.Message.Should().StartWith("X5C_UNTRUSTED: ");
    }

    [Fact]
    public async Task A_hook_exception_propagates()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf));

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => throw new TimeoutException("anchor store"), Crypto);

        act.Should().Throw<TimeoutException>();
    }

    [Fact]
    public async Task A_self_signed_end_entity_is_not_its_own_anchor_under_the_recommended_hook()
    {
        // The issuer sends its own root inside x5c; the verifier's anchor is a different root.
        var pki = CreatePki(KeyType.P256, "Issuer");
        var other = CreatePki(KeyType.P256, "Verifier");
        var signer = new JwsSigner(pki.Leaf.Signer.Signer)
        {
            CertificateChain = X509CertificateChain.Create([pki.Leaf.Certificate, pki.Intermediate.RawData, pki.Root.RawData]),
        };
        var compact = await JwsBuilder.BuildCompactAsync(Payload, signer);

        var untrusted = () => JwsParser.ParseCompactWithCertificateChain(compact, chain => ValidateWithAnchors(chain, other.Root), Crypto);
        var noAnchor = () => JwsParser.ParseCompactWithCertificateChain(compact, chain => ValidateWithAnchors(chain), Crypto);

        untrusted.Should().Throw<JoseCryptoException>().Which.Message.Should().StartWith("X5C_UNTRUSTED");
        noAnchor.Should().Throw<JoseCryptoException>().Which.Message.Should().StartWith("X5C_UNTRUSTED");
        JwsParser.ParseCompactWithCertificateChain(compact, chain => ValidateWithAnchors(chain, pki.Root), Crypto)
            .CertificateChain.Should().NotBeNull();
    }

    [Fact]
    public async Task An_expired_end_entity_is_refused_by_the_recommended_hook_not_by_the_library()
    {
        var pki = CreatePki(KeyType.P256, leafNotAfter: DateTimeOffset.UtcNow.AddMinutes(-5));
        var compact = await JwsBuilder.BuildCompactAsync(Payload, pki.SignerWithChain());

        JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto).CertificateChain.Should().NotBeNull();
        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, chain => ValidateWithAnchors(chain, pki.Root), Crypto);
        act.Should().Throw<JoseCryptoException>().Which.Message.Should().StartWith("X5C_UNTRUSTED");
    }

    [Fact]
    public async Task Changing_the_key_the_chain_hands_out_changes_nothing()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var other = CreateLeaf(KeyType.P256);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf));

        var result = JwsParser.ParseCompactWithCertificateChain(compact, chain =>
        {
            var key = chain.EndEntityPublicKey;
            key.X = other.PublicJwk.X;
            key.Y = other.PublicJwk.Y;
            return true;
        }, Crypto);

        result.CertificateChain!.EndEntityPublicKey.X.Should().Be(leaf.PublicJwk.X);
    }

    // ------------------------------------------------------------------ kid and x5c

    [Fact]
    public async Task A_kid_beside_x5c_is_not_reported_and_selects_nothing()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf, "did:example:victim#key-1"));

        var result = JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        ProtectedHeader(compact)["kid"]!.GetValue<string>().Should().Be("did:example:victim#key-1");
        result.SignerKid.Should().BeEmpty();
        result.SignerKidIsProtected.Should().BeFalse();
        result.CertificateChain.Should().NotBeNull();
    }

    [Fact]
    public async Task The_kid_path_never_reads_x5c()
    {
        // A kid resolver verifies as before; the chain in the header plays no part, and is not reported.
        var leaf = CreateLeaf(KeyType.Ed25519);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf, "k1"));

        var result = JwsParser.ParseCompact(compact, kid => kid == "k1" ? leaf.PublicJwk : null, Crypto);

        result.SignerKid.Should().Be("k1");
        result.SignerKidIsProtected.Should().BeTrue();
        result.CertificateChain.Should().BeNull();
    }

    [Fact]
    public async Task The_kid_path_accepts_a_malformed_x5c_as_it_always_did()
    {
        // Pins the unchanged accept-set: before issue #46 an x5c of any shape was an ignored extension member.
        var leaf = CreateLeaf(KeyType.Ed25519);
        var compact = await SignWithHeader(new JsonObject { ["alg"] = "EdDSA", ["kid"] = "k1", ["x5c"] = 42 }, leaf.Signer);

        JwsParser.ParseCompact(compact, _ => leaf.PublicJwk, Crypto).PayloadBytes.Should().Equal(Payload);
    }

    // ------------------------------------------------------------------ alg versus the certificate's key

    [Theory]
    [InlineData(KeyType.P256, KeyType.Ed25519)]
    [InlineData(KeyType.Ed25519, KeyType.P256)]
    [InlineData(KeyType.P256, KeyType.P384)]
    [InlineData(KeyType.P384, KeyType.P256)]
    [InlineData(KeyType.P256, KeyType.Secp256k1)]
    [InlineData(KeyType.Secp256k1, KeyType.P256)]
    public async Task An_alg_that_does_not_match_the_certificate_key_type_fails(KeyType signingKey, KeyType certificateKey)
    {
        // The JWS is honestly signed by a key of one type and says so in 'alg'; the certificate holds another type.
        var signer = CreateLeaf(signingKey);
        var certified = CreateLeaf(certificateKey);
        var compact = await SignWithHeader(
            new JsonObject { ["alg"] = signer.Signer.Algorithm, ["x5c"] = X5c(certified.Certificate) }, signer.Signer);

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<JoseCryptoException>().Which.Message.Should().Contain("does not match the public key's curve");
    }

    [Fact]
    public async Task An_alg_relabelled_to_the_certificates_curve_fails()
    {
        // ES256 bytes under an EdDSA label beside an Ed25519 certificate: the label matches, the signature does not.
        var p256 = CreateLeaf(KeyType.P256);
        var ed = CreateLeaf(KeyType.Ed25519);
        var compact = await SignWithHeader(new JsonObject { ["alg"] = "EdDSA", ["x5c"] = X5c(ed.Certificate) }, p256.Signer);

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public async Task An_RSA_end_entity_is_X5C_UNSUPPORTED_KEY()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var compact = await SignWithHeader(new JsonObject { ["alg"] = "RS256", ["x5c"] = X5c(RsaCertificate("RSA leaf")) }, leaf.Signer);

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<JoseCryptoException>().Which.Message.Should().StartWith("X5C_UNSUPPORTED_KEY: ");
    }

    [Theory]
    [InlineData("none")]
    [InlineData("")]
    public async Task An_unsigned_alg_is_refused_even_with_a_chain(string alg)
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var compact = await SignWithHeader(new JsonObject { ["alg"] = alg, ["x5c"] = X5c(leaf.Certificate) }, leaf.Signer);

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<MalformedJoseException>();
    }

    [Fact]
    public async Task A_crit_header_is_refused_even_with_a_chain()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var compact = await SignWithHeader(
            new JsonObject { ["alg"] = "EdDSA", ["crit"] = new JsonArray((JsonNode)"x5c"), ["x5c"] = X5c(leaf.Certificate) }, leaf.Signer);

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<MalformedJoseException>().Which.Message.Should().Contain("crit");
    }

    // ------------------------------------------------------------------ Done when 3: a malformed x5c is X5C_MALFORMED

    public static TheoryData<string, string> MalformedX5cValues()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var der = leaf.Certificate;
        var b64 = Convert.ToBase64String(der);
        // A DER length that is a multiple of 3 has no padding, so give the unpadded case its own certificate.
        var padded = Enumerable.Range(0, 8).Select(_ => CreateLeaf(KeyType.P256).Certificate).First(c => c.Length % 3 != 0);
        var paddedB64 = Convert.ToBase64String(padded);
        var pem = string.Join("\n", Enumerable.Range(0, (b64.Length + 63) / 64).Select(i => b64.Substring(i * 64, Math.Min(64, b64.Length - (i * 64)))));
        var nonCanonical = NonCanonicalPadBits(paddedB64);
        var tooMany = new JsonArray(Enumerable.Range(0, X509CertificateChain.MaxCertificates + 1)
            .Select(i => (JsonNode?)JsonValue.Create(Convert.ToBase64String(i == 0 ? der : Assemble(Spki(new DefaultKeyGenerator().Generate(KeyType.Ed25519)), $"CA {i}"))))
            .ToArray());

        return new TheoryData<string, string>
        {
            { "a string", $"\"{b64}\"" },
            { "an object", $"{{\"0\":\"{b64}\"}}" },
            { "a number", "1" },
            { "true", "true" },
            { "null", "null" },
            { "an empty array", "[]" },
            { "a number element", "[1]" },
            { "a null element", "[null]" },
            { "an array element", $"[[\"{b64}\"]]" },
            { "an object element", "[{}]" },
            { "a non-string second element", $"[\"{b64}\",false]" },
            { "an empty string", "[\"\"]" },
            { "the base64url form", $"[\"{Base64Url.Encode(padded)}\"]" },
            { "a base64url character", $"[\"-{b64[1..]}\"]" },
            { "padding removed", $"[\"{paddedB64.TrimEnd('=')}\"]" },
            { "padding added", $"[\"{b64}====\"]" },
            { "PEM line breaks", $"[\"{pem.Replace("\n", "\\n")}\"]" },
            { "a leading space", $"[\" {b64}\"]" },
            { "a trailing space", $"[\"{b64} \"]" },
            { "an inner space", $"[\"{b64[..8]} {b64[8..]}\"]" },
            { "non-zero pad bits", $"[\"{nonCanonical}\"]" },
            { "PEM armour", $"[\"-----BEGIN CERTIFICATE-----{b64}-----END CERTIFICATE-----\"]" },
            { "base64 of a non-certificate", $"[\"{Convert.ToBase64String("not a certificate"u8.ToArray())}\"]" },
            { "base64 of a certificate with a trailing byte", $"[\"{Convert.ToBase64String([.. der, 0x00])}\"]" },
            { "base64 of a truncated certificate", $"[\"{Convert.ToBase64String(der[..^4])}\"]" },
            { "a repeated certificate", $"[\"{b64}\",\"{b64}\"]" },
            { "too many certificates", tooMany.ToJsonString() },
        };
    }

    [Theory]
    [MemberData(nameof(MalformedX5cValues))]
    public async Task A_malformed_x5c_is_a_parse_failure_with_a_stable_code(string shape, string x5cJson)
    {
        _ = shape;
        var leaf = CreateLeaf(KeyType.P256);
        var header = new JsonObject { ["alg"] = "ES256", ["x5c"] = JsonNode.Parse(x5cJson) };
        var compact = await SignWithHeader(header, leaf.Signer);

        var hookCalls = 0;
        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => { hookCalls++; return true; }, Crypto);

        act.Should().Throw<MalformedJoseException>().Which.Message.Should().StartWith("X5C_MALFORMED: ");
        hookCalls.Should().Be(0);
    }

    [Fact]
    public async Task No_x5c_is_X5C_MISSING()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, new JwsSigner(leaf.Signer.Signer, "k1"));

        var act = () => JwsParser.ParseCompactWithCertificateChain(compact, _ => true, Crypto);

        act.Should().Throw<JoseCryptoException>().Which.Message.Should().StartWith("X5C_MISSING: ");
    }

    [Fact]
    public void Null_and_empty_arguments_are_argument_errors()
    {
        ((Action)(() => JwsParser.ParseCompactWithCertificateChain(null!, _ => true, Crypto))).Should().Throw<ArgumentException>();
        ((Action)(() => JwsParser.ParseCompactWithCertificateChain("a.b.c", null!, Crypto))).Should().Throw<ArgumentNullException>();
        ((Action)(() => JwsParser.ParseCompactWithCertificateChain("a.b.c", _ => true, null!))).Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task A_detached_payload_compact_JWS_is_refused_on_the_x5c_path()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var detached = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf), detachedPayload: true);

        var act = () => JwsParser.ParseCompactWithCertificateChain(detached, _ => true, Crypto);

        act.Should().Throw<MalformedJoseException>().Which.Message.Should().Contain("detached");
    }

    // ------------------------------------------------------------------ the signer side

    [Fact]
    public void A_chain_whose_end_entity_key_is_not_the_signers_is_refused()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var other = CreateLeaf(KeyType.P256);
        var ed = CreateLeaf(KeyType.Ed25519);

        var wrongKey = () => new JwsSigner(other.Signer.Signer) { CertificateChain = X509CertificateChain.Create([leaf.Certificate]) };
        var wrongType = () => new JwsSigner(ed.Signer.Signer) { CertificateChain = X509CertificateChain.Create([leaf.Certificate]) };

        wrongKey.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("CertificateChain");
        wrongType.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task A_compressed_point_certificate_matches_the_signers_key()
    {
        var leaf = CreateLeaf(KeyType.P256, compressedPoint: true);

        var compact = await JwsBuilder.BuildCompactAsync(Payload, WithChain(leaf));

        JwsParser.ParseCompactWithCertificateChain(compact, chain => Pinned(chain, leaf.Certificate), Crypto)
            .SignatureAlgorithm.Should().Be("ES256");
    }

    [Fact]
    public async Task JSON_serializations_carry_x5c_in_the_protected_header_only()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var signer = WithChain(leaf, "did:example:alice#1");

        foreach (var json in new[]
                 {
                     await JwsBuilder.BuildJsonAsync(Payload, [signer]),
                     await JwsBuilder.BuildJsonAsync(Payload, [signer], "application/didcomm-signed+json"),
                 })
        {
            using var document = JsonDocument.Parse(json);
            var entry = document.RootElement.TryGetProperty("signatures", out var signatures) ? signatures[0] : document.RootElement;
            var protectedHeader = JsonNode.Parse(Base64Url.Decode(entry.GetProperty("protected").GetString()!))!.AsObject();
            protectedHeader.ContainsKey("x5c").Should().BeTrue();
            if (entry.TryGetProperty("header", out var unprotectedHeader))
                unprotectedHeader.TryGetProperty("x5c", out _).Should().BeFalse();
        }
    }

    [Fact]
    public async Task An_unprotected_x5c_in_a_JSON_JWS_is_never_honoured()
    {
        // The only x5c is in the unprotected header, with a chain whose key did not sign. JwsParser.Parse uses the kid
        // and reports no chain; nothing in the package reads an unprotected x5c.
        var signer = CreateLeaf(KeyType.Ed25519);
        var stranger = CreateLeaf(KeyType.Ed25519);
        var protectedB64u = Base64Url.Encode("""{"alg":"EdDSA"}"""u8.ToArray());
        var payloadB64u = Base64Url.Encode(Payload);
        var signature = await signer.Signer.SignAsync(Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u), CancellationToken.None);
        var json = new JsonObject
        {
            ["payload"] = payloadB64u,
            ["protected"] = protectedB64u,
            ["header"] = new JsonObject { ["kid"] = "k1", ["x5c"] = X5c(stranger.Certificate) },
            ["signature"] = Base64Url.Encode(signature),
        }.ToJsonString();

        var result = JwsParser.Parse(json, kid => kid == "k1" ? signer.PublicJwk : null, Crypto);

        result.CertificateChain.Should().BeNull();
        var withStrangersKey = () => JwsParser.Parse(json, _ => stranger.PublicJwk, Crypto);
        withStrangersKey.Should().Throw<JoseCryptoException>();
    }

    [Fact]
    public async Task JWTs_and_VC_JOSE_envelopes_carry_the_signers_chain()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var signer = WithChain(leaf, "k1");

        var jwt = await JwtHandler.SignAsync(new JwtClaims(issuer: "https://issuer.example"), signer);
        var vc = await VcJose.EnvelopeCredentialAsync("""{"@context":["https://www.w3.org/ns/credentials/v2"]}"""u8.ToArray(), signer);

        foreach (var compact in new[] { jwt, vc })
        {
            ProtectedHeader(compact)["x5c"]!.AsArray().Should().ContainSingle();
            JwsParser.ParseCompactWithCertificateChain(compact, chain => Pinned(chain, leaf.Certificate), Crypto)
                .CertificateChain.Should().NotBeNull();
        }
    }

    // ------------------------------------------------------------------ interop with jose-jwt and the platform X.509 parser

    [Fact]
    public async Task Our_x5c_JWS_verifies_in_jose_jwt_with_the_key_the_platform_reads_from_x5c()
    {
        var pki = CreatePki(KeyType.P256);
        var compact = await JwsBuilder.BuildCompactAsync(Payload, pki.SignerWithChain());

        var first = OracleJwt.Headers(compact)["x5c"] switch
        {
            JsonElement element => element[0].GetString()!,
            System.Collections.IEnumerable list => list.Cast<object>().First().ToString()!,
            var other => throw new InvalidOperationException($"unexpected x5c shape {other?.GetType()}"),
        };
        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(first));
        using var key = certificate.GetECDsaPublicKey()!;

        OracleJwt.Decode(compact, key).Should().Be(Encoding.UTF8.GetString(Payload));
    }

    [Fact]
    public void A_jose_jwt_x5c_JWS_verifies_here()
    {
        var pki = CreatePki(KeyType.P256);
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=jose-jwt issuer", issuerKey, HashAlgorithmName.SHA256);
        // A fresh leaf for the platform key, issued by the PKI's root (which CreatePki keeps with its private key).
        using var leaf = request.Create(pki.Root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), [0x42]);
        var token = OracleJwt.Encode(
            Encoding.UTF8.GetString(Payload), issuerKey, OracleJwsAlgorithm.ES256,
            extraHeaders: new Dictionary<string, object> { ["x5c"] = new[] { Convert.ToBase64String(leaf.RawData) } });

        var result = JwsParser.ParseCompactWithCertificateChain(token, chain => ValidateWithAnchors(chain, pki.Root), Crypto);

        result.PayloadBytes.Should().Equal(Payload);
        result.CertificateChain!.EndEntityCertificate.ToArray().Should().Equal(leaf.RawData);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>The same bytes in base64 with a non-zero bit in the last character's unused bits.</summary>
    private static string NonCanonicalPadBits(string padded)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var lastData = padded.TrimEnd('=').Length - 1;
        var index = alphabet.IndexOf(padded[lastData], StringComparison.Ordinal);
        return padded[..lastData] + alphabet[index | 1] + padded[(lastData + 1)..];
    }
}
