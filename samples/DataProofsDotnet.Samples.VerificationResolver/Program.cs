using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — Verification-method resolver
// ============================================================
// FR-3 / FR-7: the resolver path runs the FULL Data Integrity verify algorithm — including
// CONTROLLER AUTHORIZATION. A signature can be cryptographically valid yet still fail to
// verify because the method that signed it is not AUTHORIZED for the asserted proofPurpose:
// the resolved controller document must list the method under the verification relationship
// matching the purpose (assertionMethod proofs need the method under assertionMethod, etc.),
// and the named controller must actually control the method.
//
// Core ships no DID-aware resolver. This sample IMPLEMENTS IVerificationMethodResolver over a
// tiny in-memory "controller document" store to show:
//   * an AUTHORIZED method verifies, and
//   * a method with a perfectly valid signature but NOT listed under the required relationship
//     fails with INVALID_VERIFICATION_METHOD — distinct from a proofPurpose-field mismatch.
// It also contrasts with the bundled StaticVerificationMethodResolver.
//
// Constructed by hand (no DI package).

var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault());
var crypto = new DefaultCryptoProvider();
var keyGen = new DefaultKeyGenerator();

// One key, used to sign an assertionMethod proof.
KeyPair key = keyGen.Generate(KeyType.Ed25519);
string controller = $"did:example:issuer";
string vm = $"{controller}#assertion-key";
ISigner signer = new KeyPairSigner(key, crypto);

JsonElement Unsigned() => JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer",
      "credentialSubject": { "id": "did:example:subject", "name": "Alice Example" }
    }
    """);

JsonElement secured = await pipeline.AddProofAsync(
    Unsigned(),
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = vm,
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer);

Console.WriteLine("=== Resolver-driven verification with controller authorization ===");
var purpose = new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod };

// ----------------------------------------------------------- 1. AUTHORIZED method
// The controller document lists `vm` under assertionMethod (the purpose the proof asserts).
var authorizedResolver = new ControllerDocumentResolver(new ControllerDocument
{
    MethodId = vm,
    Controller = controller,
    Multikey = key.MultibasePublicKey,
    Relationships = [ProofPurposes.AssertionMethod, ProofPurposes.Authentication],
    ControllerControlsMethod = true,
});

DocumentVerificationResult ok = await pipeline.VerifyAsync(secured, authorizedResolver, purpose);
Console.WriteLine($"  authorized (vm under assertionMethod): verified={ok.Verified}");
Check(ok.Verified, "an authorized method verifies on the resolver path");
Check(authorizedResolver.ResolveCount == 1, "the pipeline drove our custom resolver exactly once");

// ----------------------------------------------------------- 2. UNAUTHORIZED method
// Same valid key/signature, but the controller doc lists the method ONLY under keyAgreement —
// NOT under assertionMethod. The signature is fine; authorization is not. This is the
// INVALID_VERIFICATION_METHOD failure, and it is DISTINCT from a proofPurpose-field mismatch.
var unauthorizedResolver = new ControllerDocumentResolver(new ControllerDocument
{
    MethodId = vm,
    Controller = controller,
    Multikey = key.MultibasePublicKey,
    Relationships = [ProofPurposes.KeyAgreement], // method is NOT authorized for assertionMethod
    ControllerControlsMethod = true,
});

DocumentVerificationResult unauthorized = await pipeline.VerifyAsync(secured, unauthorizedResolver, purpose);
Console.WriteLine($"  unauthorized (vm only under keyAgreement): verified={unauthorized.Verified}");
PrintProblems(unauthorized);
Check(!unauthorized.Verified, "a valid signature whose method is not authorized for the purpose fails");
Check(
    unauthorized.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.InvalidVerificationMethod),
    "the failure code is INVALID_VERIFICATION_METHOD (authorization, not signature)");

// ----------------------------------------------------------- 3. Controller does not control method
// The method's signature is valid and it is listed under assertionMethod, but the controller
// document does not actually control the method -> still fails.
var notControlledResolver = new ControllerDocumentResolver(new ControllerDocument
{
    MethodId = vm,
    Controller = controller,
    Multikey = key.MultibasePublicKey,
    Relationships = [ProofPurposes.AssertionMethod],
    ControllerControlsMethod = false, // controller does NOT control this method
});

DocumentVerificationResult notControlled = await pipeline.VerifyAsync(secured, notControlledResolver, purpose);
Console.WriteLine($"  controller does not control method: verified={notControlled.Verified}");
Check(!notControlled.Verified, "a method whose controller does not control it fails");

// ----------------------------------------------------------- 4. Unknown method -> resolver returns null
var emptyResolver = new ControllerDocumentResolver(/* no documents */);
DocumentVerificationResult unknown = await pipeline.VerifyAsync(secured, emptyResolver, purpose);
Console.WriteLine($"  unknown verification method (resolver returns null): verified={unknown.Verified}");
Check(!unknown.Verified, "an unresolvable verification method fails verification");
Check(await emptyResolver.ResolveAsync("did:example:nobody#k") is null, "the resolver returns null for an unknown method");

// ----------------------------------------------------------- 5. The bundled StaticVerificationMethodResolver
// For tests and simple compositions, Core ships a dictionary-backed resolver carrying explicit
// per-method relationship sets — the same data our custom resolver materializes from a doc.
var staticResolver = new StaticVerificationMethodResolver(
[
    new ResolvedVerificationMethod
    {
        Id = vm,
        Controller = controller,
        PublicKey = PublicKeyMaterial.FromMultikey(key.MultibasePublicKey),
        Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
        ControllerControlsMethod = true,
    },
]);
DocumentVerificationResult viaStatic = await pipeline.VerifyAsync(secured, staticResolver, purpose);
Console.WriteLine($"  via bundled StaticVerificationMethodResolver: verified={viaStatic.Verified}");
Check(viaStatic.Verified, "the bundled static resolver authorizes and verifies");

ResolvedVerificationMethod? resolved = await staticResolver.ResolveAsync(vm);
Check(resolved is not null && resolved.Id == vm && resolved.Controller == controller, "ResolveAsync returns the method record");
Check(resolved!.Relationships.Contains(ProofPurposes.AssertionMethod), "the resolved method carries its relationship set");
Check(resolved.ControllerControlsMethod, "the resolved method carries the controller-controls flag");
Check(resolved.PublicKey.KeyType == KeyType.Ed25519, "the resolved method carries the public key material");

Console.WriteLine();

// ----------------------------------------------------------- 6. Challenge / domain binding
// An authentication proof can bind a challenge + domain (replay protection). The verifier supplies
// the expected values via ProofVerificationOptions; a mismatch fails with the matching problem code.
Console.WriteLine("--- challenge / domain binding (and the full ProofProblemCodes vocabulary) ---");
const string challenge = "c0ffee-2026";
const string domain = "https://verifier.example.org";
string authVm = $"{controller}#auth-key";
KeyPair authKey = keyGen.Generate(KeyType.Ed25519);
JsonElement boundProof = await pipeline.AddProofAsync(
    Unsigned(),
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = authVm,
        ProofPurpose = ProofPurposes.Authentication,
        Challenge = challenge,
        Domain = domain,
        // Additional, non-modeled proof members round-trip through AdditionalProperties.
        AdditionalProperties = new Dictionary<string, JsonElement>
        {
            ["note"] = JsonSerializer.SerializeToElement("issued for the verifier demo"),
        },
    },
    new KeyPairSigner(authKey, crypto));

var authResolver = new ControllerDocumentResolver(new ControllerDocument
{
    MethodId = authVm,
    Controller = controller,
    Multikey = authKey.MultibasePublicKey,
    Relationships = [ProofPurposes.Authentication],
    ControllerControlsMethod = true,
});

DocumentVerificationResult boundOk = await pipeline.VerifyAsync(boundProof, authResolver, new ProofVerificationOptions
{
    ExpectedProofPurpose = ProofPurposes.Authentication,
    ExpectedChallenge = challenge,
    ExpectedDomain = domain,
    VerificationTime = new DateTimeOffset(2026, 1, 2, 1, 0, 0, TimeSpan.Zero),
});
Console.WriteLine($"  matching challenge+domain: verified={boundOk.Verified}");
Check(boundOk.Verified, "an authentication proof verifies with the expected challenge + domain");

DocumentVerificationResult wrongChallenge = await pipeline.VerifyAsync(boundProof, authResolver, new ProofVerificationOptions
{
    ExpectedProofPurpose = ProofPurposes.Authentication,
    ExpectedChallenge = "wrong",
    ExpectedDomain = domain,
});
Check(!wrongChallenge.Verified, "a challenge mismatch fails verification");
Check(wrongChallenge.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.InvalidChallengeError),
    "a challenge mismatch reports INVALID_CHALLENGE_ERROR");

DocumentVerificationResult wrongDomain = await pipeline.VerifyAsync(boundProof, authResolver, new ProofVerificationOptions
{
    ExpectedProofPurpose = ProofPurposes.Authentication,
    ExpectedChallenge = challenge,
    ExpectedDomain = "https://evil.example",
});
Check(!wrongDomain.Verified, "a domain mismatch fails verification");
Check(wrongDomain.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.InvalidDomainError),
    "a domain mismatch reports INVALID_DOMAIN_ERROR");

// The full processing-error vocabulary (VC Data Integrity) and the ZCAP proof purposes.
Console.WriteLine($"  problem codes: {ProofProblemCodes.ProofVerificationError}, {ProofProblemCodes.ProofTransformationError}, {ProofProblemCodes.ProofGenerationError}, {ProofProblemCodes.InvalidChallengeError}, {ProofProblemCodes.InvalidDomainError}, {ProofProblemCodes.InvalidVerificationMethod}");
Console.WriteLine($"  ZCAP proof purposes also defined: {ProofPurposes.CapabilityInvocation}, {ProofPurposes.CapabilityDelegation}");
Check(ProofProblemCodes.ProofTransformationError == "PROOF_TRANSFORMATION_ERROR", "PROOF_TRANSFORMATION_ERROR is defined");
Check(ProofProblemCodes.ProofGenerationError == "PROOF_GENERATION_ERROR", "PROOF_GENERATION_ERROR is defined");
Check(ProofPurposes.CapabilityInvocation == "capabilityInvocation" && ProofPurposes.CapabilityDelegation == "capabilityDelegation", "ZCAP proof purposes are defined");

// ProofVerificationResult exposes Success/Failure factories for building results directly.
ProofVerificationResult manualSuccess = ProofVerificationResult.Success();
ProofVerificationResult manualFailure = ProofVerificationResult.Failure(ProofProblemCodes.ProofVerificationError, "demo");
Check(manualSuccess.Verified && !manualFailure.Verified, "ProofVerificationResult.Success/Failure build results directly");
Check(boundProof.GetProperty("proof").GetProperty("challenge").GetString() == challenge, "the proof carries the bound challenge");
Check(boundProof.GetProperty("proof").GetProperty("note").GetString() == "issued for the verifier demo", "AdditionalProperties round-trip into the proof");

Console.WriteLine();
Console.WriteLine("Done! Verification-resolver example completed successfully.");
return 0;

static void PrintProblems(DocumentVerificationResult result)
{
    foreach (ProofProblem problem in result.ProofResults.SelectMany(r => r.Problems))
        Console.WriteLine($"    problem: {problem.Code} — {problem.Message}");
}

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}

// ------------------------------------------------------------------------------------------
// A minimal controller-document model and a custom IVerificationMethodResolver implementation.
// A real adapter (e.g. net-did) would parse did:key / did:web documents into exactly this shape.
// ------------------------------------------------------------------------------------------

internal sealed class ControllerDocument
{
    public required string MethodId { get; init; }
    public required string Controller { get; init; }
    public required string Multikey { get; init; }
    public required string[] Relationships { get; init; }
    public bool ControllerControlsMethod { get; init; } = true;
}

internal sealed class ControllerDocumentResolver : IVerificationMethodResolver
{
    private readonly Dictionary<string, ControllerDocument> _byMethodId;

    public ControllerDocumentResolver(params ControllerDocument[] documents)
        => _byMethodId = documents.ToDictionary(d => d.MethodId, StringComparer.Ordinal);

    /// <summary>Counts how many times the pipeline invoked us (illustrative).</summary>
    public int ResolveCount { get; private set; }

    public Task<ResolvedVerificationMethod?> ResolveAsync(string verificationMethodUrl, CancellationToken cancellationToken = default)
    {
        ResolveCount++;
        if (!_byMethodId.TryGetValue(verificationMethodUrl, out ControllerDocument? doc))
            return Task.FromResult<ResolvedVerificationMethod?>(null);

        var resolved = new ResolvedVerificationMethod
        {
            Id = doc.MethodId,
            Controller = doc.Controller,
            PublicKey = PublicKeyMaterial.FromMultikey(doc.Multikey),
            Relationships = new HashSet<string>(doc.Relationships, StringComparer.Ordinal),
            ControllerControlsMethod = doc.ControllerControlsMethod,
        };
        return Task.FromResult<ResolvedVerificationMethod?>(resolved);
    }
}
