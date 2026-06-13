using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — Data Integrity (JCS cryptosuites)
// ============================================================
// FR-5: the JCS cryptosuites eddsa-jcs-2022 and ecdsa-jcs-2019 (P-256 / P-384).
// Each secures an arbitrary JSON-LD document by canonicalizing the document and
// the proof configuration with JCS (via NetCid), hashing each, concatenating the
// two hashes, signing through NetCrypto, and base58-btc multibase-encoding the
// signature into proof.proofValue. We then verify two ways:
//   * the resolver path (full algorithm incl. proofPurpose authorization), and
//   * the raw-key path (signature only).
//
// This sample constructs everything by hand (no DI package) — that is the FR-22
// intent: every feature is reachable without AddDataProofs.

// The cryptosuite-agnostic engine. CreateDefault() registers the Core JCS suites.
var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault());

// Software crypto + key generation backends (swap for an HSM-backed ICryptoProvider in prod).
var crypto = new DefaultCryptoProvider();
var keyGen = new DefaultKeyGenerator();

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

Console.WriteLine("=== Data Integrity — JCS cryptosuites (sign + verify) ===");
Console.WriteLine($"Registered suites: {string.Join(", ", pipeline.Suites.RegisteredNames)}");
Console.WriteLine();

// Exercise every JCS suite/curve combination the v1 set covers.
(string Suite, KeyType KeyType, string Label)[] cases =
[
    (EddsaJcs2022Cryptosuite.CryptosuiteName, KeyType.Ed25519, "eddsa-jcs-2022 (Ed25519)"),
    (EcdsaJcs2019Cryptosuite.CryptosuiteName, KeyType.P256, "ecdsa-jcs-2019 (P-256)"),
    (EcdsaJcs2019Cryptosuite.CryptosuiteName, KeyType.P384, "ecdsa-jcs-2019 (P-384)"),
];

foreach (var (suiteName, keyType, label) in cases)
{
    Console.WriteLine($"--- {label} ---");

    // --- 1. Key material. The verification method is a did:key whose fragment is the Multikey. ---
    KeyPair keyPair = keyGen.Generate(keyType);
    string publicKeyMultibase = keyPair.MultibasePublicKey;
    string verificationMethod = $"did:key:{publicKeyMultibase}#{publicKeyMultibase}";
    Console.WriteLine($"  verificationMethod: {verificationMethod[..Math.Min(48, verificationMethod.Length)]}...");

    // --- 2. Sign: feed the unsecured document + proof options through the pipeline. ---
    // A NetCrypto ISigner is the only signing entry point — never raw key bytes (AC-8).
    ISigner signer = new KeyPairSigner(keyPair, crypto);
    var proofOptions = new DataIntegrityProof
    {
        Cryptosuite = suiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = verificationMethod,
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    JsonElement secured = await pipeline.AddProofAsync(UnsignedCredential(), proofOptions, signer);
    string proofValue = secured.GetProperty("proof").GetProperty("proofValue").GetString()!;
    Console.WriteLine($"  proof embedded — proofValue: {proofValue[..Math.Min(24, proofValue.Length)]}... ({proofValue.Length} chars)");
    Check(proofValue.StartsWith('z'), $"{label} proofValue is base58-btc multibase ('z' prefix)");

    // --- 3a. Verify on the resolver path (full algorithm). The static resolver carries the ---
    //         public key, the controller, and the relationship set proofPurpose is checked against.
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
        secured,
        resolver,
        new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });
    Console.WriteLine($"  resolver-path verified: {resolverResult.Verified}");
    Check(resolverResult.Verified, $"{label} verifies on the resolver path");
    Check(resolverResult.ProofResults.Count == 1, $"{label} produced exactly one proof result");

    // --- 3b. Verify on the raw-key path (signature only; no controller authorization). ---
    PublicKeyMaterial rawKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase);
    DocumentVerificationResult rawResult = pipeline.Verify(secured, rawKey);
    Console.WriteLine($"  raw-key-path verified:  {rawResult.Verified}");
    Check(rawResult.Verified, $"{label} verifies on the raw-key path");

    // PublicKeyMaterial also round-trips to/from a JWK and exposes its key type + bytes.
    Check(rawKey.KeyType == keyType, $"{label} public key material reports the right key type");
    Check(rawKey.ToMultikey() == publicKeyMultibase, $"{label} ToMultikey round-trips");
    Check(rawKey.KeyBytes.Length > 0, $"{label} exposes raw public key bytes");
    var jwk = rawKey.ToJsonWebKey();
    Check(PublicKeyMaterial.FromJsonWebKey(jwk).KeyType == keyType, $"{label} JWK round-trips back to PublicKeyMaterial");

    // --- 4. Negative: tamper the document — verification must FAIL with a result, not throw. ---
    var tamperedNode = System.Text.Json.Nodes.JsonObject.Create(secured)!;
    tamperedNode["credentialSubject"] = new System.Text.Json.Nodes.JsonObject { ["name"] = "Mallory" };
    JsonElement tampered = JsonSerializer.SerializeToElement(tamperedNode, DataProofsJsonOptions.Default);
    DocumentVerificationResult tamperedResult = pipeline.Verify(tampered, rawKey);
    Console.WriteLine($"  tampered document verified: {tamperedResult.Verified} (expected False)");
    Check(!tamperedResult.Verified, $"{label} rejects a tampered document");
    Check(
        tamperedResult.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.ProofVerificationError),
        $"{label} reports PROOF_VERIFICATION_ERROR on tamper");

    // --- 5. Negative: a wrong proofPurpose expectation must also fail. ---
    DocumentVerificationResult wrongPurpose = pipeline.Verify(
        secured, rawKey, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication });
    Check(!wrongPurpose.Verified, $"{label} rejects a proofPurpose mismatch");

    Console.WriteLine();
}

// Looking up an unregistered suite returns null (the registry is open and forgiving).
Check(pipeline.Suites.GetByName("ecdsa-sd-2023") is null, "an unregistered suite name resolves to null");
Check(pipeline.Suites.GetByName(EddsaJcs2022Cryptosuite.CryptosuiteName) is not null, "a registered suite resolves");

Console.WriteLine("Done! All JCS Data Integrity examples completed successfully.");
return 0;

// Halt with a non-zero exit code on any failed expectation so an automated run of this
// sample (e.g. in CI) is marked as failed.
static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
