using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// CHARACTERIZATION of a DOCUMENTED limitation (adversarial findings #4 / #5): the RDFC variant
/// binds only terms defined in the active JSON-LD <c>@context</c>. Members not defined there — e.g.
/// <c>capabilityChain</c> under the credentials/v2 context — are dropped during RDF expansion and
/// are NOT cryptographically bound. This is inherent to JSON-LD/RDFC and shared by the conformant
/// <c>rdfc-*</c> suites. The <see cref="LegacyCanonicalization.Jcs"/> default binds every member
/// verbatim (asserted here for contrast). These tests pin the security boundary so it cannot change
/// silently and so the JCS guarantee is never mistaken for an RDFC one.
/// </summary>
public class RdfcExtensionBindingCharacterizationTests
{
    // credentials/v2 deliberately does NOT define capabilityChain.
    private const string Ctx = "https://www.w3.org/ns/credentials/v2";

    private static JsonElement Document() => JsonSerializer.Deserialize<JsonElement>($$"""
        {
          "@context": "{{Ctx}}",
          "id": "urn:uuid:rdfc-ext",
          "type": "ExampleCredential",
          "issuer": "did:example:issuer",
          "credentialSubject": { "id": "did:example:subject", "claim": "value" }
        }
        """);

    private static DataIntegrityProof Options(string methodId) => new()
    {
        Type = Ed25519Signature2020Cryptosuite.ProofType,
        Cryptosuite = Ed25519Signature2020Cryptosuite.ProofType,
        VerificationMethod = methodId,
        ProofPurpose = ProofPurposes.AssertionMethod,
        Created = "2026-06-14T00:00:00.000000Z",
        AdditionalProperties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["capabilityChain"] = JsonSerializer.Deserialize<JsonElement>("""["urn:zcap:root:resource"]"""),
        },
    };

    private static (DataIntegrityProofPipeline Pipeline, KeyPairSigner Signer, PublicKeyMaterial PublicKey, string MethodId)
        Setup(LegacyCanonicalization variant)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new Ed25519Signature2020Cryptosuite(variant));
        var pipeline = new DataIntegrityProofPipeline(registry);

        var keyPair = Fx.SeedKey(0x21, KeyType.Ed25519);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        return (pipeline, signer, publicKey, methodId);
    }

    private static JsonElement TamperCapabilityChain(JsonElement secured) => Fx.Mutate(secured, node =>
        ((JsonObject)node["proof"]!)["capabilityChain"] = new JsonArray("urn:zcap:root:ATTACKER"));

    [Fact]
    public async Task Jcs_BindsContextUndefinedExtension_TamperFailsClosed()
    {
        var (pipeline, signer, publicKey, methodId) = Setup(LegacyCanonicalization.Jcs);
        var secured = await pipeline.AddProofAsync(Document(), Options(methodId), signer);

        pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();
        pipeline.Verify(TamperCapabilityChain(secured), publicKey).Verified
            .Should().BeFalse("JCS binds every proof member verbatim");
    }

    [Fact]
    public async Task Rdfc_DoesNotBindContextUndefinedExtension_DocumentedLimitation()
    {
        var (pipeline, signer, publicKey, methodId) = Setup(LegacyCanonicalization.Rdfc);
        var secured = await pipeline.AddProofAsync(Document(), Options(methodId), signer);

        // capabilityChain is undefined in credentials/v2, so RDF expansion drops it from BOTH the
        // signed bytes and the verifier's recomputation. Tampering it therefore does NOT break the
        // signature: a DOCUMENTED limitation of the RDFC variant (use JCS, or a @context that
        // defines the term). Pinning it here prevents the boundary from shifting unnoticed.
        pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();
        pipeline.Verify(TamperCapabilityChain(secured), publicKey).Verified
            .Should().BeTrue("RDFC binds only context-defined terms; capabilityChain is not in credentials/v2");
    }
}
