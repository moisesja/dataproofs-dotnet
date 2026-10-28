using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using DataProofsDotnet.Rdfc;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// The security boundary for members the active JSON-LD <c>@context</c> does not define, e.g.
/// <c>capabilityChain</c> under the credentials/v2 context (adversarial findings #4 / #5). RDF
/// expansion would drop such a member, so the RDFC variant cannot sign it and fails closed: create
/// throws and a proof with such a member injected does not verify (issue #36; until 1.5.0 it was
/// silently left unsigned). The <see cref="LegacyCanonicalization.Jcs"/> default binds every member
/// verbatim. These tests pin both, so the boundary cannot shift unnoticed and the JCS guarantee is
/// never mistaken for an RDFC one.
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

    // Every term defined (ed25519-2020/v1 supplies the proof's), so only an undefined extension
    // in the proof can make RDFC drop data.
    private static JsonElement Ed25519Document() => JsonSerializer.Deserialize<JsonElement>($$"""
        {
          "@context": ["{{Ctx}}", "https://w3id.org/security/suites/ed25519-2020/v1"],
          "id": "urn:uuid:rdfc-ext",
          "type": "VerifiableCredential",
          "issuer": "did:example:issuer",
          "credentialSubject": { "id": "did:example:subject", "name": "value" }
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
    public async Task Rdfc_RefusesToSignContextUndefinedExtension()
    {
        var (pipeline, signer, _, methodId) = Setup(LegacyCanonicalization.Rdfc);

        var act = () => pipeline.AddProofAsync(Ed25519Document(), Options(methodId), signer);

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>()
            .WithMessage("*uses a term that its @context does not define*");
    }

    [Fact]
    public async Task Rdfc_InjectedContextUndefinedExtension_DoesNotVerify()
    {
        // Signed without the extension under contexts that define every term, then the undefined
        // member injected: RDF expansion would drop it, so verification refuses the document.
        var (pipeline, signer, publicKey, methodId) = Setup(LegacyCanonicalization.Rdfc);
        var secured = await pipeline.AddProofAsync(
            Ed25519Document(), Options(methodId) with { AdditionalProperties = null }, signer);

        pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();
        pipeline.Verify(TamperCapabilityChain(secured), publicKey).Verified
            .Should().BeFalse("capabilityChain is not defined by the contexts, so RDFC could not have signed it");
    }
}
