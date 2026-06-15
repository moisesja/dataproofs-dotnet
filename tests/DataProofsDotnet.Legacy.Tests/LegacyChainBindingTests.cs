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
/// The JCS 2020-era convention nests only the single current proof and has no representation for a
/// W3C proof chain. The pipeline injects predecessor proofs under the document's <c>proof</c> member
/// for <c>previousProof</c> chains, so a JCS sign/verify over such a document would silently DROP
/// those bytes. These tests pin the fail-closed behavior (adversarial findings #0 / #3): create
/// throws, verify does not pass — never a silent signature over an unbound chain.
/// </summary>
public class LegacyChainBindingTests
{
    private static DataIntegrityProof Options(string methodId) => new()
    {
        Type = Ed25519Signature2020Cryptosuite.ProofType,
        VerificationMethod = methodId,
        ProofPurpose = ProofPurposes.AssertionMethod,
        Created = "2026-06-14T00:00:00.000000Z",
    };

    private static (Ed25519Signature2020Cryptosuite Suite, KeyPairSigner Signer, PublicKeyMaterial PublicKey, string MethodId) Jcs(byte seed)
    {
        var keyPair = Fx.SeedKey(seed, KeyType.Ed25519);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        return (new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs), signer, publicKey, methodId);
    }

    [Fact]
    public async Task Jcs_Create_OnDocumentCarryingProofMember_FailsClosed()
    {
        var (suite, signer, _, methodId) = Jcs(0x11);
        var documentWithChain = JsonSerializer.Deserialize<JsonElement>("""
            {
              "@context": "https://www.w3.org/ns/credentials/v2",
              "id": "urn:uuid:chained",
              "proof": [
                { "type": "Ed25519Signature2020", "verificationMethod": "did:key:zPrev#zPrev",
                  "proofPurpose": "assertionMethod", "proofValue": "zPrevValue" }
              ]
            }
            """);

        var act = async () => await suite.CreateProofAsync(documentWithChain, Options(methodId), signer);

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("*proof*chain*");
    }

    [Fact]
    public async Task Jcs_Verify_OnDocumentStillCarryingProofMember_FailsClosed_NoThrow()
    {
        var (suite, signer, publicKey, methodId) = Jcs(0x12);

        var clean = JsonSerializer.Deserialize<JsonElement>("""
            { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:clean" }
            """);
        var proof = await suite.CreateProofAsync(clean, Options(methodId), signer);

        // Hand verification a document that still carries a (foreign) proof member — what a chain
        // looks like to the suite. JCS cannot bind it, so verification must fail closed, not throw.
        var withForeignChain = Fx.Mutate(clean, node =>
            node["proof"] = JsonNode.Parse("""[ { "type":"Ed25519Signature2020","proofValue":"zPrevValue" } ]"""));

        var verify = () => suite.VerifyProof(withForeignChain, proof, publicKey);
        verify.Should().NotThrow().Which.Verified.Should().BeFalse();
    }
}
