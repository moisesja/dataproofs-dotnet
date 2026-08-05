using System.Text;
using System.Text.Json;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;
// NetCrypto 1.1.0 also ships a Base64Url; alias the one this sample showcases.
using Base64Url = DataProofsDotnet.Jose.Base64Url;

// ============================================================
// DataProofsDotnet Samples — JWS (JSON Web Signature)
// ============================================================
// FR-13: JWS in both serializations.
//   * COMPACT (header.payload.signature) — the ubiquitous single-signature form.
//   * JSON (general / flattened) — one signer flattens; multiple signers produce the
//     general form with a `signatures` array (multi-signature over one payload).
//   * DETACHED payload — the payload bytes are omitted from the wire and supplied again
//     at verification (RFC 7515 Appendix F): useful when the payload travels separately.
//   * KID PLACEMENT — whether the signer `kid` rides in the integrity-protected header or the
//     per-signature unprotected one, defaulted from the declared media type.
// Algorithms here: EdDSA (Ed25519) and ES256K (secp256k1), all signed through NetCrypto ISigner.
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();

// Build a (signer, public-JWK resolver) pair for a given key type.
(JwsSigner Signer, Func<string, Jwk?> Resolve, Jwk PublicJwk) Material(KeyType keyType, string kid)
{
    KeyPair pair = keyGen.Generate(keyType);
    var signer = new JwsSigner(new KeyPairSigner(pair, crypto), kid);
    Jwk publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, kid);
    return (signer, k => k == kid ? publicJwk : null, publicJwk);
}

byte[] payload = Encoding.UTF8.GetBytes("""{"sub":"did:example:subject","scope":"read"}""");

Console.WriteLine("=== JWS — compact + JSON serialization, EdDSA and ES256K, detached ===");

// ----------------------------------------------------------- 1. Compact JWS, two algorithms
(KeyType KeyType, string ExpectedAlg, string Kid)[] algs =
[
    (KeyType.Ed25519, JoseAlgorithms.EdDSA, "did:example:alice#ed25519"),
    (KeyType.Secp256k1, JoseAlgorithms.ES256K, "did:example:alice#secp256k1"),
];

foreach (var (keyType, expectedAlg, kid) in algs)
{
    var (signer, resolve, _) = Material(keyType, kid);
    Console.WriteLine($"--- compact, {expectedAlg} ---");
    Console.WriteLine($"  signer.Algorithm={signer.Algorithm}, signer.Kid={signer.Kid}, signer.Signer.KeyType={signer.Signer.KeyType}");
    Check(signer.Algorithm == expectedAlg, $"{expectedAlg} signer reports its algorithm");

    string compact = await JwsBuilder.BuildCompactAsync(payload, signer, typ: "application/example+json");
    Check(compact.Split('.').Length == 3, "compact JWS has three dot-separated segments");

    JwsParseResult result = JwsParser.ParseCompact(compact, resolve, joseCrypto);
    Console.WriteLine($"  parsed alg={result.SignatureAlgorithm}, kid={result.SignerKid}, payload={result.PayloadBytes.Length} bytes");
    Check(result.SignatureAlgorithm == expectedAlg, $"{expectedAlg} round-trips the algorithm");
    Check(result.SignerKid == kid, $"{expectedAlg} round-trips the kid");
    Check(result.PayloadBytes.AsSpan().SequenceEqual(payload), $"{expectedAlg} round-trips the payload");
}
Console.WriteLine();

// ----------------------------------------------------------- 2. Flattened JSON (single signer)
Console.WriteLine("--- JSON serialization (flattened, single signer) ---");
var (edSigner, edResolve, _) = Material(KeyType.Ed25519, "did:example:alice#ed");
string flattened = await JwsBuilder.BuildJsonAsync(payload, [edSigner]);
using (var doc = JsonDocument.Parse(flattened))
{
    bool hasSignature = doc.RootElement.TryGetProperty("signature", out _);
    bool hasSignatures = doc.RootElement.TryGetProperty("signatures", out _);
    Console.WriteLine($"  flattened: top-level signature={hasSignature}, signatures-array={hasSignatures}");
    Check(hasSignature && !hasSignatures, "a single signer emits the flattened JSON form");
}
Check(JwsParser.Parse(flattened, edResolve, joseCrypto).SignerKid == "did:example:alice#ed", "flattened JSON verifies");
Console.WriteLine();

// ----------------------------------------------------------- 3. General JSON (multiple signers)
Console.WriteLine("--- JSON serialization (general, two signers) ---");
var (edSig, edRes, _) = Material(KeyType.Ed25519, "did:example:alice#ed");
var (kSig, kRes, _) = Material(KeyType.Secp256k1, "did:example:alice#k");
string general = await JwsBuilder.BuildJsonAsync(payload, [edSig, kSig]);
using (var doc = JsonDocument.Parse(general))
{
    Check(doc.RootElement.TryGetProperty("signatures", out _), "multiple signers emit the general JSON form");
    Check(!doc.RootElement.TryGetProperty("signature", out _), "general form has no top-level signature");
}
// Either signer's public key verifies its own signature in the multi-signature JWS.
Check(JwsParser.Parse(general, edRes, joseCrypto).SignerKid == "did:example:alice#ed", "general form verifies with signer A's key");
Check(JwsParser.Parse(general, kRes, joseCrypto).SignerKid == "did:example:alice#k", "general form verifies with signer B's key");
Console.WriteLine("  both signatures in the general-form JWS verify independently");
Console.WriteLine();

// ----------------------------------------------------------- 4. Detached payload
Console.WriteLine("--- detached payload ---");
var (dSigner, dResolve, _) = Material(KeyType.Ed25519, "did:example:alice#detach");

// Compact detached: the payload segment is empty on the wire; bytes are re-supplied at verify.
string detachedCompact = await JwsBuilder.BuildCompactAsync(payload, dSigner, detachedPayload: true);
Console.WriteLine($"  detached compact (empty middle segment): {detachedCompact}");
Check(detachedCompact.Split('.')[1].Length == 0, "detached compact JWS omits the payload segment");

JwsParseResult detachedResult = JwsParser.ParseCompact(detachedCompact, payload, dResolve, joseCrypto);
Check(detachedResult.PayloadBytes.AsSpan().SequenceEqual(payload), "detached compact verifies when the payload is re-supplied");

// Detached JSON form too.
string detachedJson = await JwsBuilder.BuildJsonAsync(payload, [dSigner], detachedPayload: true);
JwsParseResult detachedJsonResult = JwsParser.Parse(detachedJson, payload, dResolve, joseCrypto);
Check(detachedJsonResult.SignerKid == "did:example:alice#detach", "detached JSON verifies when the payload is re-supplied");

// Supplying the WRONG detached payload must fail (the signature was over the original bytes).
bool wrongDetachedFailed;
try
{
    JwsParser.ParseCompact(detachedCompact, Encoding.UTF8.GetBytes("tampered"), dResolve, joseCrypto);
    wrongDetachedFailed = false;
}
catch (JoseCryptoException)
{
    wrongDetachedFailed = true;
}
Console.WriteLine($"  wrong detached payload fails verification: {wrongDetachedFailed}");
Check(wrongDetachedFailed, "the wrong detached payload fails (JoseCryptoException)");
Console.WriteLine();

// ----------------------------------------------------------- 5. Where the `kid` goes
Console.WriteLine("--- kid placement (JwsKidPlacement) ---");
// RFC 7515 puts no rule on this. §4.1.4 calls `kid` a hint, and §6 says such parameters "need not
// be integrity protected" when the only thing they feed is key selection, "since changing them in
// a way that causes a different key to be used will cause the validation to fail". What §7.2.1
// does require is that the protected and unprotected parameter-name sets be DISJOINT — so the kid
// goes in exactly one header, never both.
//
// The default, JwsKidPlacement.Auto, picks the placement the declared media type needs: DIDComm
// v2.1 signed messages carry it in the per-signature unprotected `header` (Appendix C.2, and both
// reference implementations reject an envelope without it); everything else keeps it signed.
KeyPair placementPair = keyGen.Generate(KeyType.Ed25519);
const string PlacementKid = "did:example:alice#key-1";
Jwk placementPublicJwk = JwkConversion.ToPublicJwk(KeyType.Ed25519, placementPair.PublicKey, PlacementKid);
Func<string, Jwk?> placementResolve = k => k == PlacementKid ? placementPublicJwk : null;

JwsSigner autoSigner = new(new KeyPairSigner(placementPair, crypto), PlacementKid);
Console.WriteLine($"  default placement: {autoSigner.KidPlacement}");
Check(autoSigner.KidPlacement == JwsKidPlacement.Auto, "JwsKidPlacement.Auto is the default");

// Auto + the DIDComm signed media type -> unprotected per-signature header, in the General form.
// That media type also pins the serialization: DIDComm v2.1 Appendix C.2 uses the General form
// even for a single signature, and didcomm-python rejects anything without a `signatures` array.
string didcomm = await JwsBuilder.BuildJsonAsync(payload, [autoSigner], "application/didcomm-signed+json");
using (var doc = JsonDocument.Parse(didcomm))
{
    JsonElement signature = doc.RootElement.GetProperty("signatures")[0];
    string protectedJson = Encoding.UTF8.GetString(
        Base64Url.Decode(signature.GetProperty("protected").GetString()!));
    string unprotectedKid = signature.GetProperty("header").GetProperty("kid").GetString()!;
    Console.WriteLine($"  didcomm-signed protected={protectedJson}");
    Console.WriteLine($"  didcomm-signed unprotected header kid={unprotectedKid}");
    Check(!protectedJson.Contains("kid", StringComparison.Ordinal), "the DIDComm shape keeps kid out of the protected header");
    Check(unprotectedKid == PlacementKid, "the DIDComm shape carries kid in the unprotected header");
    Check(doc.RootElement.GetProperty("signatures").GetArrayLength() == 1, "one signer, one entry in the general form");
}
JwsParseResult didcommResult = JwsParser.Parse(didcomm, placementResolve, joseCrypto);
Check(didcommResult.SignerKid == PlacementKid,
    "an unprotected kid still resolves the verifying key and is reported after verification");

// A verifier can tell where the reported kid came from — and must, if it uses the kid for more
// than key selection. RFC 7515 §6 exempts `kid` from integrity protection only when "the only
// information used in the trust decision is a key". An unprotected kid is a safe hint (rewriting
// it selects a key the attacker cannot sign under, so verification fails), but it is NOT a safe
// proof-purpose or authorization input: any id resolving to the same key verifies equally well,
// and one DID document routinely lists a key under several verification-method ids.
Console.WriteLine($"  SignerKidIsProtected (didcomm) = {didcommResult.SignerKidIsProtected}");
Check(!didcommResult.SignerKidIsProtected, "the DIDComm shape reports its kid as unprotected");

// Auto + any other media type -> the kid stays under the signature (no `header` member at all).
string signedKid = await JwsBuilder.BuildJsonAsync(payload, [autoSigner], "application/example+json");
using (var doc = JsonDocument.Parse(signedKid))
{
    Check(!doc.RootElement.TryGetProperty("header", out _), "a non-DIDComm envelope emits no unprotected header");
}
Check(JwsParser.Parse(signedKid, placementResolve, joseCrypto).SignerKidIsProtected,
    "a protected kid is reported as covered by the signature");

// Either placement can be forced explicitly, whatever the media type.
JwsSigner forcedUnprotected = new(new KeyPairSigner(placementPair, crypto), PlacementKid, JwsKidPlacement.Unprotected);
string forced = await JwsBuilder.BuildJsonAsync(payload, [forcedUnprotected]);
using (var doc = JsonDocument.Parse(forced))
{
    Check(doc.RootElement.GetProperty("header").GetProperty("kid").GetString() == PlacementKid,
        "JwsKidPlacement.Unprotected moves the kid without a DIDComm typ");
}

JwsSigner forcedProtected = new(new KeyPairSigner(placementPair, crypto), PlacementKid, JwsKidPlacement.Protected);
string kept = await JwsBuilder.BuildJsonAsync(payload, [forcedProtected], "application/didcomm-signed+json");
using (var doc = JsonDocument.Parse(kept))
{
    Check(!doc.RootElement.GetProperty("signatures")[0].TryGetProperty("header", out _),
        "JwsKidPlacement.Protected keeps the kid signed even for DIDComm");
}

// Compact serialization has no unprotected header (RFC 7515 §7.1), so asking for one is an error
// rather than a silent fallback to signing the kid the caller wanted left unsigned.
bool compactRejected;
try
{
    await JwsBuilder.BuildCompactAsync(payload, forcedUnprotected);
    compactRejected = false;
}
catch (ArgumentException)
{
    compactRejected = true;
}
Check(compactRejected, "compact JWS rejects JwsKidPlacement.Unprotected (no unprotected header exists)");
Console.WriteLine();

// ----------------------------------------------------------- 6. Base64Url helpers (the JOSE encoding)
Console.WriteLine("--- Base64Url ---");
string b64 = Base64Url.Encode(payload);
string b64u = Base64Url.EncodeUtf8("héllo");
Console.WriteLine($"  Encode(payload)={b64[..16]}..., EncodeUtf8(\"héllo\")={b64u}");
Check(Base64Url.Decode(b64).AsSpan().SequenceEqual(payload), "Base64Url Encode/Decode round-trips bytes");
Check(Base64Url.DecodeUtf8(b64u) == "héllo", "Base64Url EncodeUtf8/DecodeUtf8 round-trips a string");

Console.WriteLine();
Console.WriteLine("Done! JWS example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
