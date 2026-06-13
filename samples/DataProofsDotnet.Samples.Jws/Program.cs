using System.Text;
using System.Text.Json;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — JWS (JSON Web Signature)
// ============================================================
// FR-13: JWS in both serializations.
//   * COMPACT (header.payload.signature) — the ubiquitous single-signature form.
//   * JSON (general / flattened) — one signer flattens; multiple signers produce the
//     general form with a `signatures` array (multi-signature over one payload).
//   * DETACHED payload — the payload bytes are omitted from the wire and supplied again
//     at verification (RFC 7515 Appendix F): useful when the payload travels separately.
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

// ----------------------------------------------------------- 5. Base64Url helpers (the JOSE encoding)
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
