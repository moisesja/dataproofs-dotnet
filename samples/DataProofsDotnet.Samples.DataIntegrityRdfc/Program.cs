using System.Text;
using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc;
using DataProofsDotnet.Rdfc.DataIntegrity;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — Data Integrity (RDFC cryptosuites)
// ============================================================
// FR-11: the RDF-Dataset-Canonicalization cryptosuites eddsa-rdfc-2022 and
// ecdsa-rdfc-2019 (P-256 / P-384). Unlike the JCS suites (which canonicalize the
// raw JSON), the RDFC suites first expand the JSON-LD document to RDF and run
// RDFC-1.0 (URDNA2015) before hashing — so every @context the document cites must
// be resolvable. FR-10's posture is OFFLINE-BY-DEFAULT: the OfflineDocumentLoader
// serves version-pinned, provenance-tracked copies of the core W3C contexts as
// assembly resources and FAILS CLOSED on anything outside the bundled set; network
// retrieval is opt-in via CachingNetworkDocumentLoader (never the default).
//
// Everything is constructed by hand (no DI package) — the FR-22 intent that every
// feature is reachable without AddDataProofs.

// The RDFC suites' parameterless ctors wire up the OfflineDocumentLoader for us.
// To make the offline posture explicit we build the canonicalizer ourselves over
// OfflineDocumentLoader.Instance and register the suites against it. CreateWithRdfcSuites
// hands back a registry preloaded with eddsa-rdfc-2022 + ecdsa-rdfc-2019.
IRdfCanonicalizer canonicalizer = new RdfcDocumentCanonicalizer(OfflineDocumentLoader.Instance);
CryptosuiteRegistry registry = RdfcCryptosuiteRegistration.CreateWithRdfcSuites(canonicalizer);
var pipeline = new DataIntegrityProofPipeline(registry);

var crypto = new DefaultCryptoProvider();
var keyGen = new DefaultKeyGenerator();

Console.WriteLine("=== Data Integrity — RDFC cryptosuites (sign + verify, offline loader) ===");
Console.WriteLine($"Registered suites: {string.Join(", ", pipeline.Suites.RegisteredNames)}");
Console.WriteLine($"Offline loader bundles {OfflineDocumentLoader.BundledContextUrls.Count} core contexts; the document below only cites bundled ones.");
Console.WriteLine();

// A VCDM 2.0 document whose @context entries are all in the offline bundle, so the
// RDFC expansion succeeds with zero network I/O. (examples/v2 carries AlumniCredential.)
JsonElement UnsignedCredential() => JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
      "type": ["VerifiableCredential", "AlumniCredential"],
      "issuer": "https://vc.example/issuers/5678",
      "validFrom": "2023-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:abcdefgh",
        "alumniOf": "The School of Examples"
      }
    }
    """);

// Exercise each RDFC suite/curve combination the v1 set covers. eddsa-rdfc-2022 is
// deterministic (Ed25519); ecdsa-rdfc-2019 covers P-256 and P-384.
(string Suite, KeyType KeyType, string Label)[] cases =
[
    (EddsaRdfc2022Cryptosuite.CryptosuiteName, KeyType.Ed25519, "eddsa-rdfc-2022 (Ed25519)"),
    (EcdsaRdfc2019Cryptosuite.CryptosuiteName, KeyType.P256, "ecdsa-rdfc-2019 (P-256)"),
    (EcdsaRdfc2019Cryptosuite.CryptosuiteName, KeyType.P384, "ecdsa-rdfc-2019 (P-384)"),
];

foreach (var (suiteName, keyType, label) in cases)
{
    Console.WriteLine($"--- {label} ---");

    KeyPair keyPair = keyGen.Generate(keyType);
    string publicKeyMultibase = keyPair.MultibasePublicKey;
    string verificationMethod = $"did:key:{publicKeyMultibase}#{publicKeyMultibase}";

    // Sign through the pipeline; a NetCrypto ISigner is the only signing entry point (AC-8).
    ISigner signer = new KeyPairSigner(keyPair, crypto);
    var proofOptions = new DataIntegrityProof
    {
        Cryptosuite = suiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = verificationMethod,
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    JsonElement secured = await pipeline.AddProofAsync(UnsignedCredential(), proofOptions, signer);
    DataIntegrityProof embedded = secured.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
    string proofValue = embedded.ProofValue!;
    Console.WriteLine($"  proof.type        : {embedded.Type}");
    Console.WriteLine($"  proof.cryptosuite : {embedded.Cryptosuite}");
    Console.WriteLine($"  proofValue        : {proofValue[..Math.Min(24, proofValue.Length)]}... ({proofValue.Length} chars)");
    Check(embedded.Type == DataIntegrityProof.DataIntegrityProofType, $"{label} emits type=DataIntegrityProof");
    Check(proofValue.StartsWith('z'), $"{label} proofValue is base58-btc multibase");

    // Resolver-path verification (full algorithm incl. proofPurpose authorization).
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
    Console.WriteLine($"  resolver-path verified: {resolverResult.Verified}");
    Check(resolverResult.Verified, $"{label} verifies on the resolver path");

    // Raw-key-path verification (signature only).
    PublicKeyMaterial rawKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase);
    DocumentVerificationResult rawResult = pipeline.Verify(secured, rawKey);
    Console.WriteLine($"  raw-key-path verified:  {rawResult.Verified}");
    Check(rawResult.Verified, $"{label} verifies on the raw-key path");

    // Negative: tamper the document. RDFC re-canonicalizes the tampered graph -> hash differs -> fail.
    var tamperedNode = System.Text.Json.Nodes.JsonObject.Create(secured)!;
    tamperedNode["issuer"] = "https://evil.example/";
    JsonElement tampered = JsonSerializer.SerializeToElement(tamperedNode, DataProofsJsonOptions.Default);
    DocumentVerificationResult tamperedResult = pipeline.Verify(tampered, rawKey);
    Console.WriteLine($"  tampered document verified: {tamperedResult.Verified} (expected False)");
    Check(!tamperedResult.Verified, $"{label} rejects a tampered document");

    Console.WriteLine();
}

// --- Data the canonical form would drop is refused, not silently left unsigned (issue #36). ---
//     JSON-LD processing drops a term no @context defines, and an IRI that is not well formed.
//     Whatever is dropped would not be signed, so the RDFC suites fail closed: creation throws,
//     and verification reports DATA_LOSS_DETECTION_ERROR (VC Data Integrity 1.0 §2.4.3).
Console.WriteLine("--- Data loss fails closed ---");
KeyPair lossKey = keyGen.Generate(KeyType.Ed25519);
ISigner lossSigner = new KeyPairSigner(lossKey, crypto);
var lossOptions = new DataIntegrityProof
{
    Cryptosuite = EddsaRdfc2022Cryptosuite.CryptosuiteName,
    Created = "2026-01-02T00:00:00Z",
    VerificationMethod = $"did:key:{lossKey.MultibasePublicKey}#{lossKey.MultibasePublicKey}",
    ProofPurpose = ProofPurposes.AssertionMethod,
};
JsonElement CustomClaimCredential(bool undefinedTermsContext) => JsonSerializer.Deserialize<JsonElement>(
    $$"""
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"{{(undefinedTermsContext ? ", \"https://www.w3.org/ns/credentials/undefined-terms/v2\"" : "")}}],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer",
      "credentialSubject": { "id": "did:example:subject", "clearanceLevel": "viewer" }
    }
    """);

// credentials/v2 does not define "clearanceLevel", so RDFC would drop it: signing refuses.
try
{
    await pipeline.AddProofAsync(CustomClaimCredential(false), lossOptions, lossSigner);
    Check(false, "a credential with an undefined claim is refused");
}
catch (ProofGenerationException ex) when (ex.InnerException is JsonLdDataLossException loss)
{
    Console.WriteLine($"  undefined claim refused: {loss.Message}");
}

// VCDM 2.0 §5.2: list undefined-terms/v2 last and the claim is signed (bundled offline).
JsonElement customSecured = await pipeline.AddProofAsync(CustomClaimCredential(true), lossOptions, lossSigner);
PublicKeyMaterial lossKeyMaterial = PublicKeyMaterial.FromMultikey(lossKey.MultibasePublicKey);
Check(pipeline.Verify(customSecured, lossKeyMaterial).Verified, "undefined-terms/v2 makes the custom claim signable");
Console.WriteLine("  with undefined-terms/v2 the claim is signed and verifies");

// A verifier refuses content the canonical form would drop, e.g. a node whose id is malformed.
var injected = System.Text.Json.Nodes.JsonObject.Create(customSecured)!;
injected["refreshService"] = new System.Text.Json.Nodes.JsonObject { ["id"] = "https://evil.example/r?u[0]=1", ["type"] = "Refresh" };
DocumentVerificationResult injectedResult = pipeline.Verify(
    JsonSerializer.SerializeToElement(injected, DataProofsJsonOptions.Default), lossKeyMaterial);
Check(
    !injectedResult.Verified
        && injectedResult.ProofResults[0].Problems.Any(p => p.Code == ProofProblemCodes.DataLossDetectionError),
    "an injected node the canonical form would drop is DATA_LOSS_DETECTION_ERROR");
Console.WriteLine("  injected malformed-IRI node: DATA_LOSS_DETECTION_ERROR");
Console.WriteLine();

// --- A string's base direction is signed, not refused (issue #40). ---
//     The JSON-LD default conversion to RDF drops @direction, so "ltr" and "rtl" would sign the same
//     bytes. The canonicalizer runs with JSON-LD 1.1 rdfDirection: i18n-datatype instead, the
//     representation the reference Data Integrity implementations sign with: the direction goes into
//     the literal's datatype IRI, and flipping it breaks the proof.
Console.WriteLine("--- Base direction is signed ---");
JsonElement DirectionalCredential(string direction) => JsonSerializer.Deserialize<JsonElement>(
    $$"""
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer",
      "name": { "@value": "شهادة", "@language": "ar", "@direction": "{{direction}}" },
      "credentialSubject": { "id": "did:example:subject" }
    }
    """);

string directionalNQuads = Encoding.UTF8.GetString(canonicalizer.CanonicalizeJsonLd(DirectionalCredential("rtl")));
Console.WriteLine($"  canonical literal: {directionalNQuads.Split('\n').First(line => line.Contains("i18n#"))}");
Check(directionalNQuads.Contains("^^<https://www.w3.org/ns/i18n#ar_rtl>"), "the direction is carried in the i18n datatype");

JsonElement directionalSecured = await pipeline.AddProofAsync(DirectionalCredential("rtl"), lossOptions, lossSigner);
Check(pipeline.Verify(directionalSecured, lossKeyMaterial).Verified, "a direction-bearing credential signs and verifies");

var flipped = System.Text.Json.Nodes.JsonObject.Create(directionalSecured)!;
flipped["name"]!["@direction"] = "ltr";
DocumentVerificationResult flippedResult = pipeline.Verify(
    JsonSerializer.SerializeToElement(flipped, DataProofsJsonOptions.Default), lossKeyMaterial);
Console.WriteLine($"  flipped direction verified: {flippedResult.Verified} (expected False)");
Check(!flippedResult.Verified, "flipping @direction breaks the proof");
Console.WriteLine();

// --- The canonicalizer is itself a first-class, reusable component. Show its three forms ---
// and prove RDFC-1.0 is order-independent: two documents with re-ordered members canonicalize
// to byte-identical N-Quads (the whole point of canonicalization).
Console.WriteLine("--- RDFC-1.0 canonicalizer directly ---");

JsonElement DocA() => JsonSerializer.Deserialize<JsonElement>(
    """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:1"}""");
JsonElement DocB() => JsonSerializer.Deserialize<JsonElement>(
    """{"issuer":"did:example:1","type":["VerifiableCredential"],"@context":["https://www.w3.org/ns/credentials/v2"]}""");

// CanonicalizeJsonLd returns the canonical N-Quads (URDNA2015) as UTF-8 bytes. The hash-algorithm
// argument selects the blank-node labeling hash the algorithm uses internally; for a document with
// no blank nodes the canonical output is identical either way. Two member-reordered documents
// canonicalize to byte-identical N-Quads — exactly what a Data Integrity hash is computed over.
byte[] canonA = canonicalizer.CanonicalizeJsonLd(DocA());
byte[] canonB = canonicalizer.CanonicalizeJsonLd(DocB(), RdfCanonicalizationHashAlgorithm.Sha256);
byte[] canon384 = canonicalizer.CanonicalizeJsonLd(DocA(), RdfCanonicalizationHashAlgorithm.Sha384);
Console.WriteLine($"  member order independence: canonA == canonB -> {canonA.AsSpan().SequenceEqual(canonB)}");
Console.WriteLine($"  canonical N-Quads: {Encoding.UTF8.GetString(canonA).Trim()}");
Check(canonA.AsSpan().SequenceEqual(canonB), "RDFC-1.0 is member-order independent");
Check(canon384.AsSpan().SequenceEqual(canonA), "no-blank-node canonical form is stable across the hash-algorithm selector");

// The N-Quads string form and the per-quad blank-node map are also exposed.
string nquads =
    "<did:example:1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n";
string canonNquads = canonicalizer.CanonicalizeNQuads(nquads);
IReadOnlyDictionary<string, string> blankMap = canonicalizer.CanonicalizeNQuadsToMap(nquads, RdfCanonicalizationHashAlgorithm.Sha256);
Console.WriteLine($"  CanonicalizeNQuads -> {canonNquads.Length} chars; blank-node map has {blankMap.Count} entries");
Check(canonNquads.Length > 0, "CanonicalizeNQuads returns canonical N-Quads");

// --- The opt-in network loader (FR-10) ships but is never the default. Show it composes over ---
//     the offline loader and still serves the bundled contexts locally (no network in this run).
//     Both loaders are IDocumentLoader implementations, so they are interchangeable behind the hook.
var networkLoader = new CachingNetworkDocumentLoader(OfflineDocumentLoader.Instance);
IDocumentLoader asInterface = networkLoader;
LoadedContextDocument loaded = asInterface.Load(new Uri("https://www.w3.org/ns/credentials/v2"));
Console.WriteLine($"  CachingNetworkDocumentLoader served {loaded.DocumentUrl} locally: {loaded.Content.Length} chars of context JSON");
Check(loaded.Content.Length > 0, "the opt-in caching loader serves bundled contexts from the offline cache");
networkLoader.Dispose(); // the caching loader owns an HttpClient, so it is IDisposable

// The bare offline loader fails closed on an un-bundled context (no ambient network I/O).
IDocumentLoader bareLoader = new OfflineDocumentLoader();
LoadedContextDocument offlineHit = bareLoader.Load(new Uri("https://w3id.org/security/multikey/v1"));
Check(offlineHit.Content.Length > 0, "the offline loader serves a bundled context");
bool failedClosed;
try
{
    bareLoader.Load(new Uri("https://example.com/not-bundled"));
    failedClosed = false;
}
catch (RdfCanonicalizationException)
{
    failedClosed = true;
}
Console.WriteLine($"  offline loader fails closed on an un-bundled context: {failedClosed}");
Check(failedClosed, "the offline loader fails closed (RdfCanonicalizationException) outside the bundle");

Console.WriteLine();
Console.WriteLine("Done! All RDFC Data Integrity examples completed successfully.");
return 0;

// Halt with a non-zero exit code on any failed expectation so an automated run of this
// sample (e.g. in CI) is marked as failed.
static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
