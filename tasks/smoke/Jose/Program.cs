// ============================================================
// AC-10 smoke — DataProofsDotnet.Jose
// ============================================================
// JWS round-trip: generate an Ed25519 key in a NetCrypto key store, sign a payload into a compact
// JWS (EdDSA), then parse + verify it with the public JWK. Prints OK and exits 0 on success.

using System.Text;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

Console.WriteLine("=== DataProofsDotnet.Jose smoke — compact JWS (EdDSA) round-trip ===");

// 1. Non-exporting key store: ISigner + public key.
var store = new InMemoryKeyStore(new DefaultKeyGenerator(), new DefaultCryptoProvider());
var keyInfo = await store.GenerateAsync("smoke-key", KeyType.Ed25519);
var signer = await store.CreateSignerAsync("smoke-key");

const string kid = "did:example:issuer#smoke-key";
var jwsSigner = new JwsSigner(signer, kid);
Console.WriteLine($"  JWS signer ready (alg {jwsSigner.Algorithm}, kid {jwsSigner.Kid})");
Check(jwsSigner.Algorithm == JoseAlgorithms.EdDSA, "Ed25519 signer maps to EdDSA");

// 2. Sign a payload into a compact JWS.
byte[] payload = Encoding.UTF8.GetBytes("{\"sub\":\"smoke\",\"msg\":\"data-proofs jose\"}");
string compact = await JwsBuilder.BuildCompactAsync(payload, jwsSigner);
Check(compact.Split('.').Length == 3, "compact JWS has three dot-separated segments");
Console.WriteLine("  built compact JWS");

// 3. The public JWK for verification.
var publicJwk = JwkConversion.ToPublicJwk(keyInfo.KeyType, keyInfo.PublicKey, kid);
var crypto = new JoseCryptoProvider();

// 4. Parse + verify.
var parsed = JwsParser.ParseCompact(compact, k => k == kid ? publicJwk : null, crypto);
Check(parsed.SignatureAlgorithm == JoseAlgorithms.EdDSA, "parsed alg is EdDSA");
Check(parsed.SignerKid == kid, "parsed signer kid round-trips");
Check(parsed.PayloadBytes.AsSpan().SequenceEqual(payload), "payload bytes round-trip exactly");
Console.WriteLine("  parsed + verified compact JWS");

// 5. A wrong-key resolver must reject (verification throws on a bad signature).
var threw = false;
try { JwsParser.ParseCompact(compact, _ => null, crypto); }
catch (JoseException) { threw = true; }
Check(threw, "verification with no matching key is rejected");

Console.WriteLine("OK — DataProofsDotnet.Jose smoke passed.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.Error.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
