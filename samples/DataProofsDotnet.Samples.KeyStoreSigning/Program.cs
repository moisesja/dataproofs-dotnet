using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.Cose;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — KeyStore signing (no key surrender)
// ============================================================
// AC-8: a signer backed by a NON-EXPORTING IKeyStore is sufficient for EVERY signature-bearing
// artifact this library produces. NetCrypto's IKeyStore has no key-export method — its only
// key-using operations are SignAsync(alias, …) and CreateSignerAsync(alias), and the ISigner it
// hands back surfaces only the public key and SignAsync. So "no key surrender" is structural:
// there is nothing to export. This sample drives all four families from ONE store-backed signer:
//   * a Data Integrity proof (eddsa-jcs-2022),
//   * a compact JWS,
//   * an SD-JWT with a Key Binding JWT, and
//   * a COSE_Sign1.
//
// Constructed by hand (no DI package).

// The store holds the private key; we only ever ask it to sign or to mint an ISigner.
var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
IKeyStore store = new InMemoryKeyStore(keyGen, crypto);

const string alias = "issuer-key";
StoredKeyInfo info = await store.GenerateAsync(alias, KeyType.Ed25519);
ISigner signer = await store.CreateSignerAsync(alias);

Console.WriteLine("=== KeyStore-backed signing (one non-exporting signer, four artifact families) ===");
Console.WriteLine($"  stored key: alias={info.Alias}, type={info.KeyType}, public={info.MultibasePublicKey[..16]}...");
Console.WriteLine($"  the IKeyStore interface exposes no key-export method — only sign / create-signer / get-info");
Console.WriteLine($"  the ISigner surfaces only the public key ({signer.PublicKey.Length} bytes) + SignAsync");
Console.WriteLine();

string multibase = info.MultibasePublicKey;
string vm = $"did:key:{multibase}#{multibase}";

// ----------------------------------------------------------- 1. Data Integrity proof
var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault());
JsonElement credential = JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer",
      "credentialSubject": { "id": "did:example:subject", "name": "Alice Example" }
    }
    """);

JsonElement secured = await pipeline.AddProofAsync(
    credential,
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = vm,
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer);
PublicKeyMaterial diKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, info.PublicKey);
Console.WriteLine($"  [1] Data Integrity proof  verified: {pipeline.Verify(secured, diKey).Verified}");
Check(pipeline.Verify(secured, diKey).Verified, "store-signed Data Integrity proof verifies");

// ----------------------------------------------------------- 2. Compact JWS
// JwsSigner wraps the store-backed ISigner (plus a kid); the JWS layer never sees private bytes.
var jwsSigner = new JwsSigner(signer, vm);
var joseCrypto = new JoseCryptoProvider();
Jwk publicJwk = JwkConversion.ToPublicJwk(info.KeyType, info.PublicKey, vm);

byte[] jwsPayload = Encoding.UTF8.GetBytes("""{"hello":"jws"}""");
string compactJws = await JwsBuilder.BuildCompactAsync(jwsPayload, jwsSigner);
JwsParseResult jwsResult = JwsParser.ParseCompact(compactJws, _ => publicJwk, joseCrypto);
Console.WriteLine($"  [2] Compact JWS           verified: alg={jwsResult.SignatureAlgorithm}, kid={jwsResult.SignerKid[..16]}...");
Check(jwsResult.SignatureAlgorithm == JoseAlgorithms.EdDSA, "store-signed JWS reports EdDSA");
Check(jwsResult.PayloadBytes.AsSpan().SequenceEqual(jwsPayload), "store-signed JWS round-trips the payload");

// ----------------------------------------------------------- 3. SD-JWT with Key Binding
// Both the issuer JWT and the holder's KB-JWT are signed through store-backed signers.
var holderInfo = await store.GenerateAsync("holder-key", KeyType.Ed25519);
ISigner holderSigner = await store.CreateSignerAsync("holder-key");
var holderJwsSigner = new JwsSigner(holderSigner, "did:example:holder#kb");
Jwk holderPublicJwk = JwkConversion.ToPublicJwk(KeyType.Ed25519, holderInfo.PublicKey, "did:example:holder#kb");

var claims = new JsonObject
{
    ["iss"] = "did:example:issuer",
    ["given_name"] = "Alice",
    ["family_name"] = "Example",
};
var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name");
var issuerOptions = new SdJwtIssuerOptions { HolderConfirmationKey = holderPublicJwk };
SdJwtIssuer.Result issued = await SdJwtIssuer.IssueAsync(claims, frame, jwsSigner, issuerOptions);

const string audience = "https://verifier.example.org";
const string nonce = "n-keystore-1";
string presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
    issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holderJwsSigner, audience, nonce);

SdJwtVerificationResult sdResult = SdJwtVerifier.Verify(
    presentation, _ => publicJwk,
    new SdJwtVerificationOptions { RequireKeyBinding = true, ExpectedAudience = audience, ExpectedNonce = nonce });
Console.WriteLine($"  [3] SD-JWT + KB-JWT       verified: {sdResult.IsValid}, keyBinding={sdResult.KeyBindingVerified}");
Check(sdResult.IsValid && sdResult.KeyBindingVerified, "store-signed SD-JWT + KB-JWT verifies");

// ----------------------------------------------------------- 4. COSE_Sign1
byte[] cosePayload = Encoding.UTF8.GetBytes("""{"hello":"cose"}""");
byte[] coseEncoded = await CoseSign1.SignAsync(
    cosePayload, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, KeyId = Encoding.UTF8.GetBytes(alias) });
CoseSign1VerificationResult coseResult = CoseSign1.Verify(coseEncoded, KeyType.Ed25519, info.PublicKey);
Console.WriteLine($"  [4] COSE_Sign1            verified: {coseResult.Verified}, alg={coseResult.Message!.Algorithm}");
Check(coseResult.Verified, "store-signed COSE_Sign1 verifies");

Console.WriteLine();
Console.WriteLine("All four artifacts were produced WITHOUT the private key ever leaving the IKeyStore.");
Console.WriteLine("Done! KeyStore-signing example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
