using System.Text.Json;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// Issue #25 — where the signer <c>kid</c> is written, and what the emitted envelope therefore
/// looks like.
/// <para>
/// RFC 7515 imposes no placement rule: <c>kid</c> is a hint (§4.1.4), and §6 states that such
/// parameters "need not be integrity protected" when the only information used in the trust
/// decision is a key, "since changing them in a way that causes a different key to be used will
/// cause the validation to fail". What is fixed is §7.2.1 disjointness — the kid lives in exactly
/// one of the two headers, never both (issue #17) — and §7.1, under which compact serialization
/// has no unprotected header at all.
/// </para>
/// <para>
/// DIDComm v2.1 pins the shape by example rather than by MUST. Every signed envelope in its
/// Appendix C.2 — and every one emitted by the two SICPA reference implementations — is
/// <c>protected = {typ, alg}</c> with <c>header = {kid}</c>. didcomm-jvm 0.3.2 raises
/// <c>MalformedMessageException: JWS Unprotected Per-Signature header must be present</c> without
/// it, and didcomm-python 0.3.2 reads <c>signatures[0].header.kid</c> unconditionally. These tests
/// pin that shape for the DIDComm media type, and pin the protected-only shape everywhere else.
/// </para>
/// </summary>
public sealed class DidCommKidPlacementTests
{
    private const string DidCommSigned = "application/didcomm-signed+json";
    private const string AliceKey1 = "did:example:alice#key-1";
    private const string AliceKey2 = "did:example:alice#key-2";

    private static readonly JoseCryptoProvider Jose = new();
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("""{"id":"1234567890"}""");

    // ---------------------------------------------------------------------------------------
    // Auto + the DIDComm signed media type -> unprotected per-signature header.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task SingleSigner_WithDidCommSignedTyp_MatchesTheSpecShape_AndRoundTrips()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], DidCommSigned);

        using var doc = JsonDocument.Parse(packed);
        AssertDidCommSignatureShape(OnlySignature(doc.RootElement), AliceKey1, "EdDSA");

        var result = JwsParser.Parse(packed, KidResolver(alice), Jose);
        result.SignerKid.Should().Be(AliceKey1);
        result.Typ.Should().Be(DidCommSigned);
        result.PayloadBytes.Should().Equal(Payload);
    }

    [Fact]
    public async Task SingleSigner_WithDidCommSignedTyp_UsesTheGeneralFormNotTheFlattenedOne()
    {
        // DIDComm v2.1 §Message Signing allows either form and requires recipients to process
        // both, but didcomm-python 0.3.2 does not: unpack_sign runs validate_jws over the RAW
        // envelope dict, which rejects anything lacking a `signatures` array before authlib
        // normalizes the serialization. Every Appendix C.2 example is General for this reason.
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], DidCommSigned);

        using var doc = JsonDocument.Parse(packed);
        doc.RootElement.EnumerateObject().Select(p => p.Name)
            .Should().BeEquivalentTo(["payload", "signatures"]);
        doc.RootElement.GetProperty("signatures").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task SingleSigner_WithoutTheDidCommTyp_StillFlattens()
    {
        // The General-form accommodation is scoped to the media type that needs it: every other
        // envelope keeps the RFC 7515 §7.2.2 flattened form, which is also what the RFC 7520
        // cookbook json_flat byte-compare pins.
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], "application/example+json");

        using var doc = JsonDocument.Parse(packed);
        doc.RootElement.TryGetProperty("signatures", out _).Should().BeFalse();
        doc.RootElement.TryGetProperty("signature", out _).Should().BeTrue();
    }

    [Theory]
    // The exact media type, plus the prefix-omitted form DIDComm v2.1 §Message Formats permits:
    // "IANA types for DIDComm messages MAY omit the application/ prefix". Media types are
    // case-insensitive (RFC 6838 §4.2), so a differently-cased declaration is the same type.
    [InlineData("application/didcomm-signed+json")]
    [InlineData("didcomm-signed+json")]
    [InlineData("Application/DIDComm-Signed+JSON")]
    public async Task Auto_RecognizesEverySpellingOfTheDidCommSignedMediaType(string typ)
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], typ);

        using var doc = JsonDocument.Parse(packed);
        var signature = OnlySignature(doc.RootElement);
        ProtectedMemberNames(signature).Should().NotContain("kid");
        UnprotectedKid(signature).Should().Be(AliceKey1);
    }

    [Fact]
    public async Task General_MultiSigner_WithDidCommSignedTyp_PutsEveryKidInItsOwnUnprotectedHeader()
    {
        var ed = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);
        var p256 = TestKeyMaterial.Generate(KeyType.P256, AliceKey2);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [ed.Signer, p256.Signer], DidCommSigned);

        using var doc = JsonDocument.Parse(packed);
        var signatures = doc.RootElement.GetProperty("signatures").EnumerateArray().ToArray();
        signatures.Should().HaveCount(2);
        AssertDidCommSignatureShape(signatures[0], AliceKey1, "EdDSA");
        AssertDidCommSignatureShape(signatures[1], AliceKey2, "ES256");

        // Each signature verifies on its own, resolved solely from its unprotected kid.
        JwsParser.Parse(packed, KidResolver(ed), Jose).SignerKid.Should().Be(AliceKey1);
        JwsParser.Parse(packed, KidResolver(p256), Jose).SignerKid.Should().Be(AliceKey2);
    }

    [Fact]
    public async Task DetachedPayload_BothSerializations_CarryTheKidUnprotected_AndRoundTrip()
    {
        var ed = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);
        var p256 = TestKeyMaterial.Generate(KeyType.P256, AliceKey2);

        var single = await JwsBuilder.BuildJsonAsync(
            Payload, [ed.Signer], DidCommSigned, detachedPayload: true);
        using (var doc = JsonDocument.Parse(single))
        {
            doc.RootElement.TryGetProperty("payload", out _).Should().BeFalse("detached form omits 'payload'");
            AssertDidCommSignatureShape(OnlySignature(doc.RootElement), AliceKey1, "EdDSA");
        }

        var fromSingle = JwsParser.Parse(single, Payload, KidResolver(ed), Jose);
        fromSingle.SignerKid.Should().Be(AliceKey1);
        fromSingle.PayloadBytes.Should().Equal(Payload);

        var general = await JwsBuilder.BuildJsonAsync(
            Payload, [ed.Signer, p256.Signer], DidCommSigned, detachedPayload: true);
        using (var doc = JsonDocument.Parse(general))
        {
            doc.RootElement.TryGetProperty("payload", out _).Should().BeFalse("detached form omits 'payload'");
            var signatures = doc.RootElement.GetProperty("signatures").EnumerateArray().ToArray();
            signatures.Should().HaveCount(2);
            AssertDidCommSignatureShape(signatures[0], AliceKey1, "EdDSA");
            AssertDidCommSignatureShape(signatures[1], AliceKey2, "ES256");
        }

        var fromGeneral = JwsParser.Parse(general, Payload, KidResolver(p256), Jose);
        fromGeneral.SignerKid.Should().Be(AliceKey2);
        fromGeneral.PayloadBytes.Should().Equal(Payload);
    }

    // ---------------------------------------------------------------------------------------
    // Auto everywhere else -> unchanged from 1.2.x (kid stays under the signature).
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("JWT")]
    [InlineData("application/vc+jwt")]
    // Neighbouring DIDComm media types are NOT the signed one: an encrypted or plaintext typ on a
    // JWS is not the Appendix C.2 shape, so nothing about its kid placement should change.
    [InlineData("application/didcomm-encrypted+json")]
    [InlineData("application/didcomm-plain+json")]
    public async Task Auto_WithAnyOtherTyp_KeepsTheKidProtected(string? typ)
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], typ);

        using var doc = JsonDocument.Parse(packed);
        doc.RootElement.TryGetProperty("header", out _).Should().BeFalse(
            "a non-DIDComm-signed envelope emits no unprotected header at all (issue #17)");
        ProtectedMemberNames(doc.RootElement).Should().Contain("kid");
        JwsParser.Parse(packed, KidResolver(alice), Jose).SignerKid.Should().Be(AliceKey1);
    }

    // ---------------------------------------------------------------------------------------
    // Explicit placement overrides the media-type default in both directions.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task ExplicitUnprotected_MovesTheKid_EvenWithoutADidCommTyp()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(
            Payload, [alice.SignerWith(JwsKidPlacement.Unprotected)], typ: null);

        using var doc = JsonDocument.Parse(packed);
        ProtectedMemberNames(doc.RootElement).Should().BeEquivalentTo(["alg"]);
        UnprotectedKid(doc.RootElement).Should().Be(AliceKey1);
        JwsParser.Parse(packed, KidResolver(alice), Jose).SignerKid.Should().Be(AliceKey1);
    }

    [Fact]
    public async Task ExplicitProtected_KeepsTheKidSigned_EvenUnderTheDidCommTyp()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(
            Payload, [alice.SignerWith(JwsKidPlacement.Protected)], DidCommSigned);

        using var doc = JsonDocument.Parse(packed);
        var signature = OnlySignature(doc.RootElement);
        signature.TryGetProperty("header", out _).Should().BeFalse();
        ProtectedMemberNames(signature).Should().BeEquivalentTo(["alg", "kid", "typ"]);
        JwsParser.Parse(packed, KidResolver(alice), Jose).SignerKid.Should().Be(AliceKey1);
    }

    [Fact]
    public async Task MixedPlacementsAcrossSigners_StayDisjointAndBothVerify()
    {
        var ed = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);
        var p256 = TestKeyMaterial.Generate(KeyType.P256, AliceKey2);

        var packed = await JwsBuilder.BuildJsonAsync(
            Payload,
            [ed.SignerWith(JwsKidPlacement.Unprotected), p256.SignerWith(JwsKidPlacement.Protected)],
            DidCommSigned);

        using var doc = JsonDocument.Parse(packed);
        var signatures = doc.RootElement.GetProperty("signatures").EnumerateArray().ToArray();
        signatures.Should().HaveCount(2);

        ProtectedMemberNames(signatures[0]).Should().BeEquivalentTo(["alg", "typ"]);
        UnprotectedKid(signatures[0]).Should().Be(AliceKey1);

        signatures[1].TryGetProperty("header", out _).Should().BeFalse();
        ProtectedMemberNames(signatures[1]).Should().BeEquivalentTo(["alg", "kid", "typ"]);

        JwsParser.Parse(packed, KidResolver(ed), Jose).SignerKid.Should().Be(AliceKey1);
        JwsParser.Parse(packed, KidResolver(p256), Jose).SignerKid.Should().Be(AliceKey2);
    }

    // ---------------------------------------------------------------------------------------
    // Compact serialization: no unprotected header exists (RFC 7515 §7.1).
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Compact_WithDidCommTyp_KeepsTheKidProtected_BecauseThereIsNowhereElse()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var compact = await JwsBuilder.BuildCompactAsync(Payload, alice.Signer, DidCommSigned);

        using var header = JsonDocument.Parse(Base64Url.Decode(compact.Split('.')[0]));
        header.RootElement.GetProperty("kid").GetString().Should().Be(AliceKey1);
        JwsParser.ParseCompact(compact, KidResolver(alice), Jose).SignerKid.Should().Be(AliceKey1);
    }

    [Fact]
    public async Task Compact_WithExplicitUnprotected_ThrowsRatherThanSigningAKidTheCallerWantedUnsigned()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var act = async () => await JwsBuilder.BuildCompactAsync(
            Payload, alice.SignerWith(JwsKidPlacement.Unprotected));

        (await act.Should().ThrowAsync<ArgumentException>())
            .WithMessage("*no unprotected header*")
            .And.ParamName.Should().Be("signer");
    }

    // ---------------------------------------------------------------------------------------
    // Degenerate inputs.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(JwsKidPlacement.Auto)]
    [InlineData(JwsKidPlacement.Protected)]
    [InlineData(JwsKidPlacement.Unprotected)]
    public async Task AKidlessSigner_EmitsNoUnprotectedHeader_WhateverThePlacement(JwsKidPlacement placement)
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);
        var kidless = new JwsSigner(alice.KidlessSigner.Signer, kid: null, placement);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [kidless], DidCommSigned);

        using var doc = JsonDocument.Parse(packed);
        var signature = OnlySignature(doc.RootElement);
        signature.TryGetProperty("header", out _).Should().BeFalse(
            "an empty 'header' object would add a member with nothing in it");
        ProtectedMemberNames(signature).Should().BeEquivalentTo(["alg", "typ"]);
    }

    [Fact]
    public void AnUndefinedPlacementIsRejectedAtConstruction()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var act = () => new JwsSigner(alice.Signer.Signer, AliceKey1, (JwsKidPlacement)42);

        act.Should().Throw<ArgumentOutOfRangeException>().And.ParamName.Should().Be("kidPlacement");
    }

    [Fact]
    public void PlacementIsExposedOnTheSigner()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        alice.Signer.KidPlacement.Should().Be(JwsKidPlacement.Auto);
        alice.SignerWith(JwsKidPlacement.Unprotected).KidPlacement.Should().Be(JwsKidPlacement.Unprotected);
    }

    // ---------------------------------------------------------------------------------------
    // Adversarial-review follow-ups (2026-08-05).
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task SignerKidIsProtected_DistinguishesTheTwoPlacements_SoAVerifierCanRequireASignedKid()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var unprotected = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], DidCommSigned);
        JwsParser.Parse(unprotected, KidResolver(alice), Jose)
            .SignerKidIsProtected.Should().BeFalse("the DIDComm shape carries the kid unsigned");

        var signedKid = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], typ: null);
        JwsParser.Parse(signedKid, KidResolver(alice), Jose)
            .SignerKidIsProtected.Should().BeTrue();

        var compact = await JwsBuilder.BuildCompactAsync(Payload, alice.Signer);
        JwsParser.ParseCompact(compact, KidResolver(alice), Jose)
            .SignerKidIsProtected.Should().BeTrue("compact can only carry a protected kid");
    }

    [Fact]
    public async Task SignerKidIsProtected_IsFalseWhenNoKidWasCarriedAtAll_SoThePolicyCheckFailsClosed()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.KidlessSigner]);

        var result = JwsParser.Parse(packed, _ => alice.PublicJwk, Jose);
        result.SignerKid.Should().BeEmpty();
        result.SignerKidIsProtected.Should().BeFalse(
            "a verifier requiring a signed kid must also reject an envelope that has none");
    }

    /// <summary>
    /// An unprotected <c>kid</c> is a key <em>hint</em>: rewriting it is only harmless while the
    /// verifier's resolver is injective. It is not, for instance, when one DID document lists the
    /// same key under two verification-method ids — an ordinary arrangement. The signature still
    /// verifies under the relabeled id, so <c>SignerKid</c> alone must not drive a proof-purpose
    /// decision. This pins the exposure so it stays a documented, detectable property rather than
    /// a surprise: the relabel succeeds, and <see cref="JwsParseResult.SignerKidIsProtected"/> is
    /// what lets a verifier refuse it.
    /// </summary>
    [Fact]
    public async Task ARelabeledUnprotectedKid_ResolvingToTheSameKey_StillVerifies_ButIsFlaggedUnprotected()
    {
        const string AssertionKid = "did:example:alice#assert-1";
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);
        // One DID document, one key, two verification-method ids.
        Func<string, Jwk?> didDocument = kid =>
            kid == AliceKey1 || kid == AssertionKid ? alice.PublicJwk : null;

        var packed = await JwsBuilder.BuildJsonAsync(Payload, [alice.Signer], DidCommSigned);
        JwsParser.Parse(packed, didDocument, Jose).SignerKid.Should().Be(AliceKey1);

        var tampered = System.Text.Json.Nodes.JsonNode.Parse(packed)!;
        tampered["signatures"]![0]!["header"]!["kid"] = AssertionKid;

        var result = JwsParser.Parse(tampered.ToJsonString(), didDocument, Jose);
        result.SignerKid.Should().Be(AssertionKid, "the rewritten hint resolved the same key");
        result.SignerKidIsProtected.Should().BeFalse(
            "which is precisely the signal a proof-purpose check must consult before trusting the kid");

        // The same tamper against a protected kid cannot even be attempted: adding an unprotected
        // 'kid' beside a protected one breaks RFC 7515 §5.2 step 4 disjointness (issue #19).
        var control = await JwsBuilder.BuildJsonAsync(
            Payload, [alice.SignerWith(JwsKidPlacement.Protected)], DidCommSigned);
        var controlTampered = System.Text.Json.Nodes.JsonNode.Parse(control)!;
        controlTampered["signatures"]![0]!["header"] =
            new System.Text.Json.Nodes.JsonObject { ["kid"] = AssertionKid };

        var act = () => JwsParser.Parse(controlTampered.ToJsonString(), didDocument, Jose);
        act.Should().Throw<MalformedJoseException>().WithMessage("*disjoint*");
    }

    [Theory]
    [InlineData("""{"alg":"EdDSA","kid":null}""")]
    [InlineData("""{"alg":"EdDSA","kid":42}""")]
    [InlineData("""{"alg":"EdDSA","kid":{"a":1}}""")]
    [InlineData("""{"alg":"EdDSA","kid":["a"]}""")]
    public void ANonStringProtectedKid_IsMalformed_AndNeverReachesTheCallersResolver(string protectedHeaderJson)
    {
        // RFC 7515 §4.1.4: the kid value MUST be a string. Before this check, a JSON null was
        // deserialized onto the model and handed to the caller's resolver — which JwsParser invokes
        // OUTSIDE its try block — so a resolver that dereferenced its argument threw
        // NullReferenceException (or ArgumentNullException from a dictionary lookup) straight
        // through the parser's documented MalformedJoseException/JoseCryptoException contract.
        // This is the protected-header half of the issue #15 check.
        var protectedB64u = Base64Url.Encode(Encoding.UTF8.GetBytes(protectedHeaderJson));
        var signature = Base64Url.Encode(new byte[64]);
        var payloadB64u = Base64Url.Encode(Payload);
        var resolverWasCalled = false;
        Func<string, Jwk?> hostileResolver = kid =>
        {
            resolverWasCalled = true;
            _ = kid.Length; // Would throw NullReferenceException on a null kid.
            return null;
        };

        var parseCompact = () => JwsParser.ParseCompact(
            $"{protectedB64u}.{payloadB64u}.{signature}", hostileResolver, Jose);
        parseCompact.Should().Throw<MalformedJoseException>().WithMessage("*'kid' must be a string*");

        var json = JsonSerializer.Serialize(new
        {
            payload = payloadB64u,
            @protected = protectedB64u,
            signature,
        });
        var parseJson = () => JwsParser.Parse(json, hostileResolver, Jose);
        parseJson.Should().Throw<MalformedJoseException>().WithMessage("*'kid' must be a string*");

        resolverWasCalled.Should().BeFalse("the header is rejected before any key resolution");
    }

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("\"hello\"")]
    [InlineData("123")]
    [InlineData("true")]
    [InlineData("null")]
    public void ANonObjectProtectedHeaderRoot_IsMalformed_NotAnInvalidOperationException(string headerJson)
    {
        // Every JsonElement member accessor — TryGetProperty, EnumerateObject — throws
        // InvalidOperationException rather than JsonException when the root is not an object, so a
        // member check placed ahead of deserialization escapes the parser's documented contract.
        // (Caught by the adversarial second pass: the first cut of the 'kid' string check above
        // regressed exactly this, on every path including compact and VcJose.)
        var protectedB64u = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));
        var signature = Base64Url.Encode(new byte[64]);
        var payloadB64u = Base64Url.Encode(Payload);

        var parseCompact = () => JwsParser.ParseCompact(
            $"{protectedB64u}.{payloadB64u}.{signature}", _ => null, Jose);
        parseCompact.Should().Throw<MalformedJoseException>();

        var json = JsonSerializer.Serialize(new
        {
            payload = payloadB64u,
            @protected = protectedB64u,
            signature,
        });
        var parseJson = () => JwsParser.Parse(json, _ => null, Jose);
        parseJson.Should().Throw<MalformedJoseException>();
    }

    /// <summary>
    /// <see cref="JwsParseResult.SignerKidIsProtected"/> describes the signature that actually
    /// verified — first-verifying-signature-wins — so in a mixed-placement envelope the reported
    /// value follows whichever entry the resolver could satisfy, not the array order alone. Pinned
    /// because a verifier enforcing "the kid must be signed" needs to know this is per-signature:
    /// reordering `signatures[]` can flip the flag and make such a policy reject an envelope that
    /// does contain a valid protected-kid signature. That direction is safe (reject, never trust),
    /// but it must not silently invert.
    /// </summary>
    [Fact]
    public async Task SignerKidIsProtected_TracksTheSignatureThatVerified_InMixedPlacementEnvelopes()
    {
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, AliceKey1);
        var bob = TestKeyMaterial.Generate(KeyType.P256, AliceKey2);

        var packed = await JwsBuilder.BuildJsonAsync(
            Payload,
            [alice.SignerWith(JwsKidPlacement.Unprotected), bob.SignerWith(JwsKidPlacement.Protected)],
            typ: null);

        // Only Alice resolvable -> the unprotected-kid entry verifies.
        var viaAlice = JwsParser.Parse(packed, KidResolver(alice), Jose);
        viaAlice.SignerKid.Should().Be(AliceKey1);
        viaAlice.SignerKidIsProtected.Should().BeFalse();

        // Only Bob resolvable -> the protected-kid entry verifies, even though it is second.
        var viaBob = JwsParser.Parse(packed, KidResolver(bob), Jose);
        viaBob.SignerKid.Should().Be(AliceKey2);
        viaBob.SignerKidIsProtected.Should().BeTrue();
    }

    [Theory]
    [InlineData("did:example:alice#a+b")]
    [InlineData("did:example:alice#unicode-ü")]
    [InlineData("did:example:alice#<a&b>")]
    public async Task BothHeadersEncodeAKidIdentically(string kid)
    {
        // The protected header is written by DeterministicJsonWriter with the relaxed encoder
        // (JoseJson.Default) so '+' in media types survives literally. The unprotected header must
        // use the same encoder, or one envelope renders the same kid two different ways.
        var alice = TestKeyMaterial.Generate(KeyType.Ed25519, kid);

        var unprotected = await JwsBuilder.BuildJsonAsync(
            Payload, [alice.SignerWith(JwsKidPlacement.Unprotected)]);
        var packedProtected = await JwsBuilder.BuildJsonAsync(
            Payload, [alice.SignerWith(JwsKidPlacement.Protected)]);

        using var unprotectedDoc = JsonDocument.Parse(unprotected);
        using var protectedDoc = JsonDocument.Parse(packedProtected);

        // Raw text, not the parsed value, so a difference in escaping is visible.
        var rawUnprotectedKid = unprotectedDoc.RootElement
            .GetProperty("header").GetProperty("kid").GetRawText();
        using var decodedProtected = JsonDocument.Parse(
            Base64Url.Decode(protectedDoc.RootElement.GetProperty("protected").GetString()!));
        var rawProtectedKid = decodedProtected.RootElement.GetProperty("kid").GetRawText();

        rawUnprotectedKid.Should().Be(rawProtectedKid);
        rawUnprotectedKid.Should().Contain(kid[(kid.IndexOf('#') + 1)..], "the relaxed encoder emits the literal character");

        // And it still round-trips.
        JwsParser.Parse(unprotected, KidResolver(alice), Jose).SignerKid.Should().Be(kid);
    }

    // ---------------------------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Asserts one signature object is exactly the DIDComm v2.1 Appendix C.2 shape:
    /// <c>protected</c> holding precisely <c>{typ, alg}</c> with the DIDComm signed media type,
    /// and an unprotected <c>header</c> holding precisely <c>{kid}</c>. Member-set equality (not
    /// containment) is the point — a stray <c>kid</c> left in the protected header would break
    /// RFC 7515 §7.2.1 disjointness, and a stray member in <c>header</c> would be a parameter no
    /// verifier agreed to honor.
    /// </summary>
    private static void AssertDidCommSignatureShape(JsonElement signatureObject, string expectedKid, string expectedAlg)
    {
        using var protectedHeader = JsonDocument.Parse(
            Base64Url.Decode(signatureObject.GetProperty("protected").GetString()!));

        var protectedNames = protectedHeader.RootElement.EnumerateObject().Select(p => p.Name).ToArray();
        protectedNames.Should().BeEquivalentTo(["typ", "alg"]);
        protectedHeader.RootElement.GetProperty("typ").GetString().Should().Be(DidCommSigned);
        protectedHeader.RootElement.GetProperty("alg").GetString().Should().Be(expectedAlg);

        var unprotected = signatureObject.GetProperty("header");
        unprotected.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo(["kid"]);
        unprotected.GetProperty("kid").GetString().Should().Be(expectedKid);
    }

    /// <summary>
    /// The single signature object of a JWS, whichever serialization carries it: the sole entry of
    /// a General <c>signatures</c> array, or the root itself when Flattened. Lets a test assert the
    /// signature's shape without also asserting which form it arrived in — the form is pinned
    /// separately by its own tests.
    /// </summary>
    private static JsonElement OnlySignature(JsonElement root)
    {
        if (!root.TryGetProperty("signatures", out var signatures))
            return root;
        signatures.GetArrayLength().Should().Be(1);
        return signatures[0];
    }

    private static string[] ProtectedMemberNames(JsonElement signatureObject)
    {
        using var protectedHeader = JsonDocument.Parse(
            Base64Url.Decode(signatureObject.GetProperty("protected").GetString()!));
        return protectedHeader.RootElement.EnumerateObject().Select(p => p.Name).ToArray();
    }

    private static string? UnprotectedKid(JsonElement signatureObject)
        => signatureObject.GetProperty("header").GetProperty("kid").GetString();

    private static Func<string, Jwk?> KidResolver(TestKeyMaterial key)
        => kid => kid == key.PublicJwk.Kid ? key.PublicJwk : null;
}
