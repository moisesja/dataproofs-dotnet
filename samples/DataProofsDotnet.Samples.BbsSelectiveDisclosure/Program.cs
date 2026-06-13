using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — bbs-2023 selective disclosure
// ============================================================
// FR-12: the BBS Data Integrity lifecycle — three distinct roles.
//   1. ISSUER creates a BASE proof over the document with a set of MANDATORY JSON pointers
//      (RFC 6901) that must always be revealed, plus an HMAC key that pseudonymizes blank
//      nodes. The base proof's proofValue is the W3C base wire form (multibase 'u', CBOR
//      header u2V0C) and carries everything a holder needs to derive.
//   2. HOLDER derives a DERIVED proof revealing only the mandatory fields plus a chosen set of
//      SELECTIVE pointers — a zero-knowledge BBS proof, no issuer interaction. The derived
//      proofValue is the W3C derived wire form (CBOR header u2V0D).
//   3. VERIFIER verifies the derived proof; withheld fields are absent from the reveal document.
//
// BBS uses pairing-friendly BLS12-381 G2 keys and rides NetCrypto's IBbsCryptoProvider, which
// has a documented capability model: registration always succeeds, but USE throws
// BbsUnavailableException when the native binaries are absent. This host ships them, so the
// live path runs; the calls are wrapped so a binary-less CI leg still exits 0 (FR-12 posture).
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var suite = new Bbs2023Cryptosuite();

Console.WriteLine("=== bbs-2023 selective disclosure (issuer -> holder -> verifier) ===");
Console.WriteLine($"suite name: {suite.Name}; native BBS available on this host: {suite.IsAvailable}");
Console.WriteLine();

// A credential whose @context entries are all in the offline bundle (incl. the BBS context),
// so RDFC expansion succeeds with no network I/O.
JsonElement Unsigned() => JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "type": ["VerifiableCredential", "AlumniCredential"],
      "issuer": "https://vc.example/issuers/5678",
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:abcdefgh",
        "alumniOf": "The School of Examples",
        "gpa": "4.0",
        "favoriteColor": "purple"
      }
    }
    """);

// The issuer always reveals the credential type and the subject id (mandatory pointers).
string[] mandatoryPointers = ["/issuer", "/credentialSubject/id"];

try
{
    // --- 1. ISSUER: base proof ---
    KeyPair bbsKey = keyGen.Generate(KeyType.Bls12381G2);
    byte[] hmacKey = new byte[32];
    new Random(42).NextBytes(hmacKey); // a sample HMAC key (use NetCrypto randomness in production)

    var baseOptions = new DataIntegrityProof
    {
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = $"did:key:{bbsKey.MultibasePublicKey}#{bbsKey.MultibasePublicKey}",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    DataIntegrityProof baseProof = await suite.CreateBaseProofAsync(
        Unsigned(), baseOptions, bbsKey.PrivateKey, hmacKey, mandatoryPointers);

    // Embed the base proof to form the secured base document the holder receives.
    JsonElement securedBase = Embed(Unsigned(), baseProof);
    string baseProofValue = baseProof.ProofValue!;
    Console.WriteLine($"  ISSUER  base proofValue: {baseProofValue[..12]}... ({baseProofValue.Length} chars)");
    Check(baseProofValue.StartsWith("u2V0C", StringComparison.Ordinal), "base proof is the W3C base wire form (u2V0C)");

    PublicKeyMaterial issuerPublicKey = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, bbsKey.PublicKey);

    // --- 2. HOLDER: derive a proof revealing gpa but withholding favoriteColor ---
    string[] selectivePointers = ["/credentialSubject/gpa"];
    byte[] presentationHeader = [0x11, 0x33, 0x77, 0xaa];

    JsonElement reveal = suite.DeriveProof(securedBase, selectivePointers, presentationHeader);
    DataIntegrityProof derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
    string derivedProofValue = derivedProof.ProofValue!;
    Console.WriteLine($"  HOLDER  derived proofValue: {derivedProofValue[..12]}... ({derivedProofValue.Length} chars)");
    Check(derivedProofValue.StartsWith("u2V0D", StringComparison.Ordinal), "derived proof is the W3C derived wire form (u2V0D)");

    // The reveal carries the mandatory + selected fields; the withheld field is gone.
    var subject = reveal.GetProperty("credentialSubject");
    Console.WriteLine($"  reveal subject keys: {string.Join(", ", subject.EnumerateObject().Select(p => p.Name))}");
    Check(subject.TryGetProperty("id", out _), "mandatory subject id is revealed");
    Check(subject.TryGetProperty("gpa", out _), "selected gpa is revealed");
    Check(!subject.TryGetProperty("favoriteColor", out _), "withheld favoriteColor is absent from the reveal");

    // --- 3. VERIFIER: verify the derived proof ---
    ProofVerificationResult verified = VerifyReveal(suite, reveal, derivedProof, issuerPublicKey);
    Console.WriteLine($"  VERIFIER derived proof verified: {verified.Verified}");
    Check(verified.Verified, "the derived proof verifies against the issuer's BBS public key");

    // Derive a SECOND presentation revealing favoriteColor instead — different disclosure, same base.
    JsonElement reveal2 = suite.DeriveProof(securedBase, ["/credentialSubject/favoriteColor"], presentationHeader);
    DataIntegrityProof derived2 = reveal2.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
    Check(VerifyReveal(suite, reveal2, derived2, issuerPublicKey).Verified, "a second selective disclosure from the same base verifies");
    Check(reveal2.GetProperty("credentialSubject").TryGetProperty("favoriteColor", out _), "second reveal discloses favoriteColor");
    Console.WriteLine("  a second, different disclosure derived from the SAME base proof also verifies");

    // --- Negatives (results, not exceptions) ---
    // Wrong verification key fails closed.
    var wrongKey = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, keyGen.Generate(KeyType.Bls12381G2).PublicKey);
    Check(!VerifyReveal(suite, reveal, derivedProof, wrongKey).Verified, "a wrong BBS key fails verification");

    // Tampering a disclosed mandatory value fails closed.
    JsonElement tampered = Mutate(reveal, o => o["issuer"] = "https://evil.example/");
    ProofVerificationResult tamperResult = VerifyReveal(suite, tampered, derivedProof, issuerPublicKey);
    Check(!tamperResult.Verified, "tampering a disclosed value fails verification");
    Check(tamperResult.Problems.Any(p => p.Code == ProofProblemCodes.ProofVerificationError),
        "BBS tamper reports PROOF_VERIFICATION_ERROR");
    Console.WriteLine("  wrong-key and tampered-value negatives both fail closed (results, never exceptions)");

    // The generic ICryptosuite.CreateProofAsync(ISigner) entry point is NOT how BBS is used —
    // BBS needs the HMAC key + mandatory pointers, so the generic signer path is unsupported.
    bool genericUnsupported;
    try
    {
        var generic = (ICryptosuite)suite;
        await generic.CreateProofAsync(Unsigned(), baseOptions, new KeyPairSigner(keyGen.Generate(KeyType.Ed25519), new DefaultCryptoProvider()));
        genericUnsupported = false;
    }
    catch (NotSupportedException)
    {
        genericUnsupported = true;
    }
    Check(genericUnsupported, "the generic ICryptosuite signer path is unsupported for BBS (needs CreateBaseProofAsync)");
    Console.WriteLine("  the generic ICryptosuite.CreateProofAsync path throws NotSupportedException (BBS needs the base-proof API)");
}
catch (BbsUnavailableException)
{
    // CI-portable fallback: a host without the BBS native binaries reports cleanly and still exits 0.
    Console.WriteLine("  NOTE: BBS native binaries not available on this host — skipping the live lifecycle.");
    Console.WriteLine("  (Suite registration still succeeds per NetCrypto's documented capability model; only USE throws.)");
}

Console.WriteLine();
Console.WriteLine("Done! bbs-2023 selective-disclosure example completed successfully.");
return 0;

// --- helpers ---

static JsonElement Embed(JsonElement unsecured, DataIntegrityProof proof)
{
    var node = JsonObject.Create(unsecured)!;
    node["proof"] = JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.Default);
    return JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);
}

static ProofVerificationResult VerifyReveal(Bbs2023Cryptosuite suite, JsonElement reveal, DataIntegrityProof proof, PublicKeyMaterial pk)
{
    var unsecured = JsonObject.Create(reveal)!;
    unsecured.Remove("proof");
    return suite.VerifyProof(JsonSerializer.SerializeToElement(unsecured, DataProofsJsonOptions.Default), proof, pk);
}

static JsonElement Mutate(JsonElement source, Action<JsonObject> mutate)
{
    var node = JsonObject.Create(source)!;
    mutate(node);
    return JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);
}

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
