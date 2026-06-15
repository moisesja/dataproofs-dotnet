using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — Legacy Linked-Data-Signature suites
// ============================================================
// The pre–Data-Integrity suites Ed25519Signature2020 and EcdsaSecp256r1Signature2019
// (DataProofsDotnet.Legacy). These name their algorithm by proof `type` and carry NO
// `cryptosuite` member on the wire — the 2020-era convention deployed corpora (e.g. ZCAP-LD)
// still emit. They are OPT-IN: NOT registered by CryptosuiteRegistry.CreateDefault(); a consumer
// registers them explicitly. Verification then dispatches by `type`
// (ICryptosuite.SupportedProofTypes + CryptosuiteRegistry.GetByProofType); creation dispatches by
// `cryptosuite` naming the suite, but the emitted proof omits cryptosuite.
//
// Use these ONLY for interop with existing corpora; prefer the 2022/2019 Data Integrity suites
// for new proofs. This sample constructs everything by hand (no DI package), FR-22.

var crypto = new DefaultCryptoProvider();
var keyGen = new DefaultKeyGenerator();

// --- Register the legacy suites EXPLICITLY (not via CreateDefault). JCS is the back-compat default. ---
var registry = CryptosuiteRegistry.CreateDefault();
registry.Register(new Ed25519Signature2020Cryptosuite());        // JCS variant
registry.Register(new EcdsaSecp256r1Signature2019Cryptosuite()); // JCS variant
var pipeline = new DataIntegrityProofPipeline(registry);

Console.WriteLine("=== Legacy LD-Signature suites (sign + verify; opt-in) ===");
Console.WriteLine($"Registered suites: {string.Join(", ", registry.RegisteredNames)}");

// Each legacy suite declares the proof `type`(s) it verifies via SupportedProofTypes; the registry
// indexes those so a cryptosuite-less legacy proof resolves by `type` through GetByProofType.
ICryptosuite ed = new Ed25519Signature2020Cryptosuite();
Console.WriteLine($"Ed25519Signature2020 SupportedProofTypes: {string.Join(",", ed.SupportedProofTypes)}");
Check(
    ed.SupportedProofTypes.Contains(Ed25519Signature2020Cryptosuite.ProofType),
    "Ed25519Signature2020 declares its proof type in SupportedProofTypes");

ICryptosuite? resolvedByType = registry.GetByProofType(Ed25519Signature2020Cryptosuite.ProofType);
Check(resolvedByType is not null, "GetByProofType resolves the registered legacy suite by its type");
Check(
    registry.GetByProofType("DataIntegrityProof") is null,
    "GetByProofType never resolves the default DataIntegrityProof type (those stay name-dispatched)");
Console.WriteLine();

// An unsecured VCDM 2.0 credential (treated as an arbitrary JSON-LD document, FR-2).
JsonElement UnsignedCredential() => JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer",
      "credentialSubject": { "id": "did:example:subject", "name": "Alice Example" }
    }
    """);

(string ProofType, KeyType KeyType, string Label)[] cases =
[
    (Ed25519Signature2020Cryptosuite.ProofType, KeyType.Ed25519, "Ed25519Signature2020 (Ed25519, JCS)"),
    (EcdsaSecp256r1Signature2019Cryptosuite.ProofType, KeyType.P256, "EcdsaSecp256r1Signature2019 (P-256, JCS)"),
];

foreach (var (proofType, keyType, label) in cases)
{
    Console.WriteLine($"--- {label} ---");

    // --- 1. Key material; the verification method is a did:key whose fragment is the Multikey. ---
    KeyPair keyPair = keyGen.Generate(keyType);
    string publicKeyMultibase = keyPair.MultibasePublicKey;
    string verificationMethod = $"did:key:{publicKeyMultibase}#{publicKeyMultibase}";
    ISigner signer = new KeyPairSigner(keyPair, crypto); // never raw key bytes (AC-8)

    // --- 2. Sign. Type is the legacy type; Cryptosuite NAMES the suite only so AddProofAsync's ---
    //         GetByName dispatch resolves it — the emitted wire proof carries NO cryptosuite.
    var proofOptions = new DataIntegrityProof
    {
        Type = proofType,
        Cryptosuite = proofType,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = verificationMethod,
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    JsonElement secured = await pipeline.AddProofAsync(UnsignedCredential(), proofOptions, signer);
    JsonElement proof = secured.GetProperty("proof");
    Check(proof.GetProperty("type").GetString() == proofType, $"{label} emits type:\"{proofType}\"");
    Check(!proof.TryGetProperty("cryptosuite", out _), $"{label} emits no cryptosuite member");
    string proofValue = proof.GetProperty("proofValue").GetString()!;
    Check(proofValue.StartsWith('z'), $"{label} proofValue is base58-btc multibase");
    Console.WriteLine($"  proof: type={proofType}, no cryptosuite, proofValue={proofValue[..Math.Min(20, proofValue.Length)]}...");

    // --- 3. Verify on the raw-key path. Dispatch is by `type` (no cryptosuite) via GetByProofType. ---
    PublicKeyMaterial rawKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase);
    Check(pipeline.Verify(secured, rawKey).Verified, $"{label} verifies on the raw-key path (type-dispatched)");

    // --- 4. Verify on the resolver path (full algorithm incl. proofPurpose authorization). ---
    var resolver = new StaticVerificationMethodResolver(
    [
        new ResolvedVerificationMethod
        {
            Id = verificationMethod,
            Controller = $"did:key:{publicKeyMultibase}",
            PublicKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase),
            Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
            ControllerControlsMethod = true,
        },
    ]);
    DocumentVerificationResult resolverResult = await pipeline.VerifyAsync(
        secured, resolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });
    Check(resolverResult.Verified, $"{label} verifies on the resolver path");

    // --- 5. Negative: tamper the document — must fail closed (a result, never a throw). ---
    var tamperedNode = System.Text.Json.Nodes.JsonObject.Create(secured)!;
    tamperedNode["credentialSubject"] = new System.Text.Json.Nodes.JsonObject { ["name"] = "Mallory" };
    JsonElement tampered = JsonSerializer.SerializeToElement(tamperedNode, DataProofsJsonOptions.Default);
    DocumentVerificationResult tamperedResult = pipeline.Verify(tampered, rawKey);
    Check(!tamperedResult.Verified, $"{label} rejects a tampered document");
    Check(
        tamperedResult.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.ProofVerificationError),
        $"{label} reports PROOF_VERIFICATION_ERROR on tamper");

    Console.WriteLine();
}

// --- The RDFC variant. A single proof `type` may be signed over JCS or RDFC depending on the ---
//     issuer; choose the canonicalization the corpus uses at construction (LegacyCanonicalization).
//     Only one variant per `type` can be registered, so the RDFC variant uses its own registry.
Console.WriteLine("--- Ed25519Signature2020 (Ed25519, RDFC-1.0 variant) ---");
var rdfcRegistry = CryptosuiteRegistry.CreateDefault();
rdfcRegistry.Register(new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc));
var rdfcPipeline = new DataIntegrityProofPipeline(rdfcRegistry);

KeyPair rdfcKey = keyGen.Generate(KeyType.Ed25519);
string rdfcVm = $"did:key:{rdfcKey.MultibasePublicKey}#{rdfcKey.MultibasePublicKey}";
var rdfcOptions = new DataIntegrityProof
{
    Type = Ed25519Signature2020Cryptosuite.ProofType,
    Cryptosuite = Ed25519Signature2020Cryptosuite.ProofType,
    Created = "2026-01-02T00:00:00Z",
    VerificationMethod = rdfcVm,
    ProofPurpose = ProofPurposes.AssertionMethod,
};
JsonElement rdfcSecured = await rdfcPipeline.AddProofAsync(
    UnsignedCredential(), rdfcOptions, new KeyPairSigner(rdfcKey, crypto));
Check(
    rdfcPipeline.Verify(rdfcSecured, PublicKeyMaterial.FromMultikey(rdfcKey.MultibasePublicKey)).Verified,
    "Ed25519Signature2020 (RDFC variant) create→verify round-trips");
Console.WriteLine("  RDFC variant create→verify OK");
Console.WriteLine();

Console.WriteLine("Done! All legacy LD-Signature examples completed successfully.");
return 0;

// Halt with a non-zero exit code on any failed expectation so an automated run (CI) is marked failed.
static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
