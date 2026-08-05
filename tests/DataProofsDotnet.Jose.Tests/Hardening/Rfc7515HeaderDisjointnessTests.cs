using System.Text.Json;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Regression tests for issue #17: <see cref="JwsBuilder"/> emitted the signer <c>kid</c> in
/// BOTH the integrity-protected header and the per-signature unprotected <c>header</c> object.
/// RFC 7515 §7.2 requires the two header parameter-name sets to be disjoint, so strict
/// verifiers (nimbus-jose-jwt, used by didcomm-jvm) rejected every such JWS. The fix keeps the
/// <c>kid</c> protected-only; these tests pin the disjointness invariant for both JSON
/// serializations so it cannot regress.
/// </summary>
public class Rfc7515HeaderDisjointnessTests
{
    private static readonly JoseCryptoProvider Jose = new();

    [Fact]
    public async Task Flattened_SingleSigner_HeaderParameterSetsAreDisjoint_AndKidIsProtected()
    {
        var signer = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#key-1");

        var packed = await JwsBuilder.BuildJsonAsync(
            Encoding.UTF8.GetBytes("hello"), new[] { signer.Signer });

        using var doc = JsonDocument.Parse(packed);
        AssertDisjointAndProtectedKid(doc.RootElement, "did:example:alice#key-1");

        // The RFC-conformant envelope still round-trips: the parser resolves the signer from
        // the protected kid and surfaces it as the verified identity.
        var result = JwsParser.Parse(packed,
            kid => kid == signer.PublicJwk.Kid ? signer.PublicJwk : null, Jose);
        result.SignerKid.Should().Be("did:example:alice#key-1");
    }

    [Fact]
    public async Task General_MultiSigner_HeaderParameterSetsAreDisjoint_AndKidsAreProtected()
    {
        var signerA = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#ed");
        var signerB = TestKeyMaterial.Generate(KeyType.P256, "did:example:alice#p256");

        var packed = await JwsBuilder.BuildJsonAsync(
            Encoding.UTF8.GetBytes("hello"), new[] { signerA.Signer, signerB.Signer });

        using var doc = JsonDocument.Parse(packed);
        var signatures = doc.RootElement.GetProperty("signatures").EnumerateArray().ToArray();
        signatures.Should().HaveCount(2);
        AssertDisjointAndProtectedKid(signatures[0], "did:example:alice#ed");
        AssertDisjointAndProtectedKid(signatures[1], "did:example:alice#p256");

        // Each signature still verifies with the kid resolvable from the protected header only.
        var resultB = JwsParser.Parse(packed,
            kid => kid == signerB.PublicJwk.Kid ? signerB.PublicJwk : null, Jose);
        resultB.SignerKid.Should().Be("did:example:alice#p256");
    }

    // The detached-payload renders are separate object literals in JwsBuilder, so cover them
    // too — a regression could reintroduce the unprotected 'header' in the detached branch only.
    [Fact]
    public async Task DetachedPayload_BothSerializations_AreDisjoint_AndRoundTripWithTheSuppliedPayload()
    {
        var signerA = TestKeyMaterial.Generate(KeyType.Ed25519, "did:example:alice#ed");
        var signerB = TestKeyMaterial.Generate(KeyType.P256, "did:example:alice#p256");
        var payload = Encoding.UTF8.GetBytes("hello");

        var flattened = await JwsBuilder.BuildJsonAsync(payload, new[] { signerA.Signer }, detachedPayload: true);
        using (var doc = JsonDocument.Parse(flattened))
        {
            doc.RootElement.TryGetProperty("payload", out _).Should().BeFalse("detached form omits 'payload'");
            AssertDisjointAndProtectedKid(doc.RootElement, "did:example:alice#ed");
        }

        var detachedFlattened = JwsParser.Parse(flattened, payload,
            kid => kid == signerA.PublicJwk.Kid ? signerA.PublicJwk : null, Jose);
        detachedFlattened.SignerKid.Should().Be("did:example:alice#ed");
        // Byte equality, not a UTF-8 round-trip: the parser must hand back exactly the payload it
        // was given. Asserting the identity alone would miss a parser that verifies and reports
        // the right signer while returning the wrong bytes (issue #21).
        detachedFlattened.PayloadBytes.Should().Equal(payload);

        var general = await JwsBuilder.BuildJsonAsync(payload, new[] { signerA.Signer, signerB.Signer }, detachedPayload: true);
        using (var doc = JsonDocument.Parse(general))
        {
            doc.RootElement.TryGetProperty("payload", out _).Should().BeFalse("detached form omits 'payload'");

            var expectedKids = new[] { "did:example:alice#ed", "did:example:alice#p256" };
            var signatures = doc.RootElement.GetProperty("signatures").EnumerateArray().ToArray();
            // Assert the count before pairing — Zip truncates silently, so a dropped signature
            // entry would otherwise leave its disjointness unchecked.
            signatures.Should().HaveCount(expectedKids.Length);
            foreach (var (signature, kid) in signatures.Zip(expectedKids))
                AssertDisjointAndProtectedKid(signature, kid);
        }

        var detachedGeneral = JwsParser.Parse(general, payload,
            kid => kid == signerB.PublicJwk.Kid ? signerB.PublicJwk : null, Jose);
        detachedGeneral.SignerKid.Should().Be("did:example:alice#p256");
        detachedGeneral.PayloadBytes.Should().Equal(payload);
    }

    /// <summary>
    /// Asserts RFC 7515 §7.2 disjointness for one signature object: the protected and
    /// unprotected header parameter-name sets share no member, and the <c>kid</c> lives in
    /// the protected header. (The current builder omits the unprotected <c>header</c> object
    /// entirely; the intersection check keeps the test valid even if a future change emits
    /// other, non-duplicated unprotected members.)
    /// </summary>
    private static void AssertDisjointAndProtectedKid(JsonElement signatureObject, string expectedKid)
    {
        using var protectedHeader = JsonDocument.Parse(
            Base64Url.Decode(signatureObject.GetProperty("protected").GetString()!));
        var protectedNames = protectedHeader.RootElement.EnumerateObject()
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

        protectedNames.Should().Contain("kid", "the signer kid must stay under the signature");
        protectedHeader.RootElement.GetProperty("kid").GetString().Should().Be(expectedKid);

        if (signatureObject.TryGetProperty("header", out var unprotectedHeader))
        {
            var unprotectedNames = unprotectedHeader.EnumerateObject()
                .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
            unprotectedNames.Intersect(protectedNames).Should().BeEmpty(
                "RFC 7515 §7.2 requires the protected and unprotected header parameter-name sets to be disjoint");
        }
    }
}
