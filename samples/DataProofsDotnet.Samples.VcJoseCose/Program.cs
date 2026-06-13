using System.Text;
using DataProofsDotnet.Cose;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — VC-JOSE-COSE
// ============================================================
// FR-18 / FR-19: "Securing Verifiable Credentials using JOSE and COSE" — ENVELOPING a VCDM 2.0
// credential (vs. the embedded Data Integrity proof). The credential travels opaquely inside a
// signed container; what makes it a VC envelope (rather than any JWS/COSE_Sign1) is the spec's
// media types and integrity-protected content-type headers:
//   * JOSE half (VcJose): a compact JWS with typ=vc+jwt and cty=vc; media type application/vc+jwt.
//   * COSE half (VcCose): a COSE_Sign1 with typ(16)=application/vc+cose and content-type(3)=application/vc.
// The verifier returns the exact credential bytes back, and rejects a wrong/absent content type.
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();

// A minimal VCDM 2.0 credential (treated as opaque bytes; data-model validation is out of scope).
byte[] Credential() => Encoding.UTF8.GetBytes(
    """
    {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"https://university.example/issuers/565049","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:example:subject","degree":"Bachelor of Science"}}
    """);

// ----------------------------------------------------------- JOSE half (VcJose)
Console.WriteLine("=== VC-JOSE-COSE — JOSE half (vc+jwt) ===");
Console.WriteLine($"  envelope typ = {VcJose.EnvelopeType}, content type (cty) = {VcJose.CredentialContentType}, media type = {VcJose.MediaType}");
Check(VcJose.MediaType == "application/vc+jwt" && VcJose.MediaType == "application/" + VcJose.EnvelopeType, "VcJose media type is application/vc+jwt");

KeyPair joseKey = keyGen.Generate(KeyType.P256);
var joseSigner = new JwsSigner(new KeyPairSigner(joseKey, crypto), "did:example:issuer#jose");
Jwk josePublicJwk = JwkConversion.ToPublicJwk(joseKey.KeyType, joseKey.PublicKey, "did:example:issuer#jose");

string joseEnvelope = await VcJose.EnvelopeCredentialAsync(Credential(), joseSigner);
byte[] recovered = VcJose.VerifyCredential(joseEnvelope, _ => josePublicJwk, joseCrypto);
Console.WriteLine($"  enveloped + verified; recovered credential bytes match: {recovered.AsSpan().SequenceEqual(Credential())}");
Check(recovered.AsSpan().SequenceEqual(Credential()), "VcJose returns the enveloped credential verbatim");

// The protected header carries the spec's typ and cty.
using (var header = System.Text.Json.JsonDocument.Parse(Base64Url.DecodeUtf8(joseEnvelope.Split('.')[0])))
{
    Console.WriteLine($"  header: typ={header.RootElement.GetProperty("typ").GetString()}, cty={header.RootElement.GetProperty("cty").GetString()}, alg={header.RootElement.GetProperty("alg").GetString()}");
    Check(header.RootElement.GetProperty("typ").GetString() == VcJose.EnvelopeType, "the JOSE envelope produces typ=vc+jwt");
    Check(header.RootElement.GetProperty("cty").GetString() == VcJose.CredentialContentType, "the JOSE envelope produces cty=vc");
}

// A plain JWS (no vc+jwt typ) is NOT a VC envelope — rejected by VcJose.
string plainJws = await JwsBuilder.BuildCompactAsync(Credential(), joseSigner);
bool plainRejected;
try { VcJose.VerifyCredential(plainJws, _ => josePublicJwk, joseCrypto); plainRejected = false; }
catch (MalformedJoseException) { plainRejected = true; }
Console.WriteLine($"  a plain JWS (no vc+jwt typ) is rejected by VcJose: {plainRejected}");
Check(plainRejected, "VcJose rejects a JWS lacking the vc+jwt typ");

// A tampered payload fails the signature check.
string[] seg = joseEnvelope.Split('.');
string tamperedEnvelope = $"{seg[0]}.{Base64Url.Encode(Encoding.UTF8.GetBytes("""{"@context":["x"],"type":["VerifiableCredential"]}"""))}.{seg[2]}";
bool tamperRejected;
try { VcJose.VerifyCredential(tamperedEnvelope, _ => josePublicJwk, joseCrypto); tamperRejected = false; }
catch (JoseCryptoException) { tamperRejected = true; }
Check(tamperRejected, "VcJose rejects a tampered envelope payload");
Console.WriteLine();

// ----------------------------------------------------------- COSE half (VcCose)
Console.WriteLine("=== VC-JOSE-COSE — COSE half (application/vc+cose) ===");
Console.WriteLine($"  envelope typ (16) = {VcCose.EnvelopeType}, content type (3) = {VcCose.CredentialContentType}");
Check(VcCose.EnvelopeType == "application/vc+cose" && VcCose.CredentialContentType == "application/vc", "VcCose media types match the spec");

(CoseAlgorithm Alg, KeyType KeyType)[] coseAlgs =
[
    (CoseAlgorithm.EdDsa, KeyType.Ed25519),
    (CoseAlgorithm.ES256, KeyType.P256),
    (CoseAlgorithm.ES384, KeyType.P384),
    (CoseAlgorithm.ES256K, KeyType.Secp256k1),
];

foreach (var (alg, keyType) in coseAlgs)
{
    KeyPair pair = keyGen.Generate(keyType);
    var signer = new KeyPairSigner(pair, crypto);

    byte[] envelope = await VcCose.EnvelopeCredentialAsync(Credential(), signer, alg, keyId: Encoding.UTF8.GetBytes("issuer-key"));
    CoseSign1VerificationResult result = VcCose.Verify(envelope, keyType, pair.PublicKey);

    Console.WriteLine($"  {alg,-8}: verified={result.Verified}, typ={result.Message!.Type}, cty={result.Message.ContentType}");
    Check(result.Verified, $"{alg} VcCose envelope round-trips");
    Check(result.Message!.Type == VcCose.EnvelopeType, $"{alg} envelope produces typ(16)=application/vc+cose");
    Check(result.Message.ContentType == VcCose.CredentialContentType, $"{alg} envelope produces content-type(3)=application/vc");
    Check(result.Message.Payload!.Value.ToArray().AsSpan().SequenceEqual(Credential()), $"{alg} carries the credential opaquely");
}

// A plain COSE_Sign1 (no VC headers) is NOT a VC envelope — rejected by VcCose.
KeyPair plainKey = keyGen.Generate(KeyType.Ed25519);
byte[] plainCose = await CoseSign1.SignAsync(Credential(), new KeyPairSigner(plainKey, crypto), new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa });
CoseSign1VerificationResult plainCoseResult = VcCose.Verify(plainCose, KeyType.Ed25519, plainKey.PublicKey);
Console.WriteLine($"  a plain COSE_Sign1 (no VC headers) is rejected by VcCose: {!plainCoseResult.Verified} ({plainCoseResult.Failure!.Code})");
Check(!plainCoseResult.Verified && plainCoseResult.Failure!.Code == CoseVerificationErrorCode.InvalidType, "VcCose rejects a COSE_Sign1 lacking the VC typ");

Console.WriteLine();
Console.WriteLine("Done! VC-JOSE-COSE example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
