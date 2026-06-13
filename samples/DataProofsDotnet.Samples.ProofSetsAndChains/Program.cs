using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — Proof Sets and Proof Chains
// ============================================================
// FR-6: a document may carry MORE than one proof.
//   * A proof SET is two (or more) independent proofs over the same document — e.g. two
//     issuers co-signing. Each verifies on its own; tampering with one fails only that one.
//   * A proof CHAIN orders proofs with `previousProof`: a later proof signs the document
//     INCLUDING the earlier referenced proof, so its signing input embeds those bytes.
//     Tampering with a referenced proof breaks every proof that depends on it.
//
// AddProofAsync handles the set/chain bookkeeping: adding a proof to an already-proofed
// document promotes the single `proof` object into a `proof` array (set semantics), and a
// proof whose options carry a `previousProof` reference is verified as a chain link.
//
// Constructed by hand (no DI package). Uses the deterministic eddsa-jcs-2022 suite so output
// is byte-stable (NFR-5).

var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault());
var crypto = new DefaultCryptoProvider();
var keyGen = new DefaultKeyGenerator();

// Two distinct signers (two issuers co-signing the same credential).
KeyPair key1 = keyGen.Generate(KeyType.Ed25519);
KeyPair key2 = keyGen.Generate(KeyType.Ed25519);
string vm1 = $"did:key:{key1.MultibasePublicKey}#{key1.MultibasePublicKey}";
string vm2 = $"did:key:{key2.MultibasePublicKey}#{key2.MultibasePublicKey}";
ISigner signer1 = new KeyPairSigner(key1, crypto);
ISigner signer2 = new KeyPairSigner(key2, crypto);

// A resolver carrying both methods under assertionMethod (full resolver-path verification).
var resolver = new StaticVerificationMethodResolver(
[
    Method(vm1, key1.MultibasePublicKey, "did:example:issuer-1"),
    Method(vm2, key2.MultibasePublicKey, "did:example:issuer-2"),
]);

JsonElement Unsigned() => JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer-1",
      "credentialSubject": { "id": "did:example:subject", "name": "Alice Example" }
    }
    """);

var verifyOptions = new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod };

// ----------------------------------------------------------- 1. Proof SET
Console.WriteLine("=== Proof set (two independent proofs) ===");

// First proof (a single `proof` object).
JsonElement signedOnce = await pipeline.AddProofAsync(
    Unsigned(),
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = vm1,
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer1);
Console.WriteLine($"  after 1st proof: proof is a {signedOnce.GetProperty("proof").ValueKind}");
Check(signedOnce.GetProperty("proof").ValueKind == JsonValueKind.Object, "first proof is a single object");

// Second proof added to the already-proofed document -> promotes to a `proof` array (a set).
JsonElement signedSet = await pipeline.AddProofAsync(
    signedOnce,
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:01Z",
        VerificationMethod = vm2,
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer2);
Console.WriteLine($"  after 2nd proof: proof is a {signedSet.GetProperty("proof").ValueKind} of {signedSet.GetProperty("proof").GetArrayLength()}");
Check(signedSet.GetProperty("proof").ValueKind == JsonValueKind.Array, "second proof promotes to a set (array)");

DocumentVerificationResult setResult = await pipeline.VerifyAsync(signedSet, resolver, verifyOptions);
Console.WriteLine($"  whole set verified: {setResult.Verified}; proof results: {setResult.ProofResults.Count}");
Check(setResult.Verified, "the proof set verifies");
Check(setResult.ProofResults.Count == 2, "the set yields two proof results");
Check(setResult.ProofResults.All(r => r.Verified), "both proofs in the set verify");

// Tamper ONLY the first proof's proofValue: in a set, the other proof still verifies.
JsonElement setTampered = MutateProofValue(signedSet, proofIndex: 0);
DocumentVerificationResult setTamperResult = await pipeline.VerifyAsync(setTampered, resolver, verifyOptions);
Console.WriteLine($"  tampering proof[0]: overall={setTamperResult.Verified}, proof[0]={setTamperResult.ProofResults[0].Verified}, proof[1]={setTamperResult.ProofResults[1].Verified}");
Check(!setTamperResult.Verified, "a tampered set fails overall");
Check(!setTamperResult.ProofResults[0].Verified, "the tampered proof fails");
Check(setTamperResult.ProofResults[1].Verified, "the untouched proof in the set still verifies (independence)");
Check(
    setTamperResult.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.ProofVerificationError),
    "the failed set proof reports PROOF_VERIFICATION_ERROR");
Console.WriteLine();

// ----------------------------------------------------------- 2. Proof CHAIN
Console.WriteLine("=== Proof chain (ordered via previousProof) ===");

// The first chain proof carries an `id` so a later proof can reference it.
const string firstProofId = "urn:proof:chain-1";
JsonElement chainOne = await pipeline.AddProofAsync(
    Unsigned(),
    new DataIntegrityProof
    {
        Id = firstProofId,
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = vm1,
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer1);

// The second proof references the first via previousProof. PreviousProofReference accepts a
// single id (implicit from string) or a set of ids (FromValues). Its signing input embeds the
// referenced proof, so the chain is order-dependent.
PreviousProofReference single = firstProofId; // implicit string -> single reference
PreviousProofReference asSet = PreviousProofReference.FromValues([firstProofId]);
PreviousProofReference asSingle = PreviousProofReference.FromSingle(firstProofId);
Console.WriteLine($"  previousProof: single.IsArrayForm={single.IsArrayForm}, set.IsArrayForm={asSet.IsArrayForm}, values=[{string.Join(",", single.Values)}]");
Check(!single.IsArrayForm && asSet.IsArrayForm, "single vs array previousProof forms are distinguished");
PreviousProofReference fromImplicit = firstProofId;
Check(single.Equals(asSingle) && single.Equals(fromImplicit), "PreviousProofReference equality holds for the same id");
Check(single.Equals((object)asSingle), "PreviousProofReference object-Equals override agrees");
Check(single.GetHashCode() == asSingle.GetHashCode(), "equal references hash equally");

JsonElement chainTwo = await pipeline.AddProofAsync(
    chainOne,
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:01Z",
        VerificationMethod = vm2,
        ProofPurpose = ProofPurposes.AssertionMethod,
        PreviousProof = single,
    },
    signer2);

var proofs = chainTwo.GetProperty("proof");
Console.WriteLine($"  chain length: {proofs.GetArrayLength()}; proof[1].previousProof = {proofs[1].GetProperty("previousProof").GetString()}");
Check(proofs.GetArrayLength() == 2, "the chain has two links");
Check(proofs[1].GetProperty("previousProof").GetString() == firstProofId, "proof[1] references proof[0] by id");

DocumentVerificationResult chainResult = await pipeline.VerifyAsync(chainTwo, resolver, verifyOptions);
Console.WriteLine($"  chain verified: {chainResult.Verified}");
Check(chainResult.Verified, "the proof chain verifies when the dependency order holds");

// Tamper the FIRST (referenced) proof: the chain property means BOTH links now fail, because
// proof[1]'s signing input embedded proof[0]'s bytes.
JsonElement chainTampered = MutateProofValue(chainTwo, proofIndex: 0);
DocumentVerificationResult chainTamperResult = await pipeline.VerifyAsync(chainTampered, resolver, verifyOptions);
Console.WriteLine($"  tampering proof[0]: overall={chainTamperResult.Verified}, proof[0]={chainTamperResult.ProofResults[0].Verified}, proof[1]={chainTamperResult.ProofResults[1].Verified}");
Check(!chainTamperResult.Verified, "a tampered chain fails overall");
Check(!chainTamperResult.ProofResults[0].Verified && !chainTamperResult.ProofResults[1].Verified,
    "tampering the referenced proof breaks the dependent proof too (chain property)");

// A dangling previousProof (referencing a proof id that isn't present) is a generation error.
bool threw;
try
{
    await pipeline.AddProofAsync(
        Unsigned(),
        new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            Created = "2026-01-02T00:00:02Z",
            VerificationMethod = vm2,
            ProofPurpose = ProofPurposes.AssertionMethod,
            PreviousProof = "urn:proof:does-not-exist",
        },
        signer2);
    threw = false;
}
catch (ProofGenerationException)
{
    threw = true;
}
Console.WriteLine($"  dangling previousProof throws ProofGenerationException: {threw}");
Check(threw, "a dangling previousProof on add throws ProofGenerationException");

// ProofGenerationException derives from the library-base DataProofsException, so callers can catch
// the whole family (malformed input / misconfiguration) at one level (FR-23).
bool caughtAsBase;
try
{
    await pipeline.AddProofAsync(
        Unsigned(),
        new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = vm1,
            ProofPurpose = ProofPurposes.AssertionMethod,
            PreviousProof = "urn:proof:also-missing",
        },
        signer1);
    caughtAsBase = false;
}
catch (DataProofsException)
{
    caughtAsBase = true;
}
Check(caughtAsBase, "the same failure is catchable as the base DataProofsException");

Console.WriteLine();
Console.WriteLine("Done! All proof set / chain examples completed successfully.");
return 0;

// --- helpers ---

static ResolvedVerificationMethod Method(string id, string multibase, string controller) => new()
{
    Id = id,
    Controller = controller,
    PublicKey = PublicKeyMaterial.FromMultikey(multibase),
    Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
    ControllerControlsMethod = true,
};

// Flip the last base58 char of the proofValue at proof[proofIndex], invalidating that signature.
static JsonElement MutateProofValue(JsonElement secured, int proofIndex)
{
    var node = System.Text.Json.Nodes.JsonObject.Create(secured)!;
    var proofArray = (System.Text.Json.Nodes.JsonArray)node["proof"]!;
    var proof = (System.Text.Json.Nodes.JsonObject)proofArray[proofIndex]!;
    string pv = proof["proofValue"]!.GetValue<string>();
    proof["proofValue"] = pv[..^1] + (pv[^1] == 'z' ? 'y' : 'z');
    return JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);
}

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
