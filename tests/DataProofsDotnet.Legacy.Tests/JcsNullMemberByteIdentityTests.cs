using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Cross-stack byte-identity for explicit JSON <c>null</c>s (adversarial finding #1). zcap-dotnet's
/// JCS canonicalizer drops null <em>object members</em> before signing (preserving null array
/// elements), so a wire <see cref="JsonElement"/> canonicalizes identically to a
/// <c>WhenWritingNull</c>-serialized model. The legacy JCS suite must do the same, or its bytes
/// diverge from zcap for any document/proof carrying explicit nulls.
/// </summary>
public class JcsNullMemberByteIdentityTests
{
    private static DataIntegrityProof Options(string methodId) => new()
    {
        Type = Ed25519Signature2020Cryptosuite.ProofType,
        VerificationMethod = methodId,
        ProofPurpose = ProofPurposes.AssertionMethod,
        Created = "2026-06-14T00:00:00.000000Z",
    };

    [Fact]
    public async Task Jcs_StripsNullObjectMembers_YieldingByteIdenticalSignatures()
    {
        var keyPair = Fx.GoldenSeedKey(); // deterministic Ed25519 → reproducible proofValue
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var suite = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";

        var withoutNull = JsonSerializer.Deserialize<JsonElement>("""
            { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:nulltest" }
            """);
        var withNull = JsonSerializer.Deserialize<JsonElement>("""
            { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:nulltest", "note": null }
            """);

        var fromClean = await suite.CreateProofAsync(withoutNull, Options(methodId), signer);
        var fromNull = await suite.CreateProofAsync(withNull, Options(methodId), signer);

        // The null object member is stripped before JCS, so both documents share one signing input.
        fromNull.ProofValue.Should().Be(fromClean.ProofValue);

        // And a proof made over either representation verifies against the other (null-insensitive).
        suite.VerifyProof(withoutNull, fromNull, publicKey).Verified.Should().BeTrue();
        suite.VerifyProof(withNull, fromClean, publicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task Jcs_NullInsideProofExtension_IsStripped_NotBoundAsPresent()
    {
        var keyPair = Fx.GoldenSeedKey();
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var suite = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";

        var document = JsonSerializer.Deserialize<JsonElement>("""
            { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:proofnull" }
            """);

        var plain = Options(methodId);
        var withNullExtension = Options(methodId) with
        {
            AdditionalProperties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["optionalNote"] = JsonSerializer.Deserialize<JsonElement>("null"),
            },
        };

        var proofPlain = await suite.CreateProofAsync(document, plain, signer);
        var proofWithNull = await suite.CreateProofAsync(document, withNullExtension, signer);

        // An explicit-null proof member contributes nothing to the signed bytes (it is stripped).
        proofWithNull.ProofValue.Should().Be(proofPlain.ProofValue);
    }
}
