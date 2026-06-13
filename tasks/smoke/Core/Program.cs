// ============================================================
// AC-10 smoke — DataProofsDotnet.Core
// ============================================================
// JCS Data Integrity proof round-trip: generate an Ed25519 key in a non-exporting NetCrypto
// key store, add an `eddsa-jcs-2022` proof to a JSON-LD document through the pipeline, and verify
// it with the public key. Prints OK and exits 0 on success; any failed expectation exits non-zero.

using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

Console.WriteLine("=== DataProofsDotnet.Core smoke — eddsa-jcs-2022 proof round-trip ===");

// 1. A non-exporting key store (NetCrypto): generate the signing key, take an ISigner + public key.
var store = new InMemoryKeyStore(new DefaultKeyGenerator(), new DefaultCryptoProvider());
var keyInfo = await store.GenerateAsync("smoke-key", KeyType.Ed25519);
var signer = await store.CreateSignerAsync("smoke-key");
Console.WriteLine($"  generated Ed25519 key ({keyInfo.PublicKey.Length}-byte public key)");

// 2. An unsecured JSON-LD document.
var document = JsonSerializer.SerializeToElement(new Dictionary<string, object>
{
    ["@context"] = new[] { "https://www.w3.org/ns/credentials/v2" },
    ["type"] = "VerifiableCredential",
    ["issuer"] = "did:example:issuer",
    ["credentialSubject"] = new Dictionary<string, object> { ["id"] = "did:example:subject" },
});

// 3. Add the proof through the cryptosuite-agnostic pipeline.
var pipeline = new DataIntegrityProofPipeline();
var secured = await pipeline.AddProofAsync(
    document,
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:issuer#smoke-key",
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer);

Check(secured.TryGetProperty("proof", out var proof), "secured document carries a proof block");
Check(proof.GetProperty("cryptosuite").GetString() == EddsaJcs2022Cryptosuite.CryptosuiteName,
    "proof.cryptosuite is eddsa-jcs-2022");
Console.WriteLine("  added eddsa-jcs-2022 proof");

// 4. Verify with the public key (raw-key overload — signature-only, no resolver).
var result = pipeline.Verify(secured, PublicKeyMaterial.FromRaw(keyInfo.KeyType, keyInfo.PublicKey));
Check(result.Verified, "proof verifies against the signing public key");

// 5. Tamper → must fail (verification returns a result, never throws on invalid proofs).
var tampered = JsonSerializer.SerializeToElement(JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(secured)!
    .ToDictionary(kv => kv.Key, kv => kv.Key == "issuer"
        ? JsonSerializer.SerializeToElement("did:example:ATTACKER")
        : kv.Value));
var tamperedResult = pipeline.Verify(tampered, PublicKeyMaterial.FromRaw(keyInfo.KeyType, keyInfo.PublicKey));
Check(!tamperedResult.Verified, "tampered document fails verification");

Console.WriteLine("OK — DataProofsDotnet.Core smoke passed.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.Error.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
