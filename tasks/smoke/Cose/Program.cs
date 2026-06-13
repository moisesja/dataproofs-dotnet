// ============================================================
// AC-10 smoke — DataProofsDotnet.Cose
// ============================================================
// COSE_Sign1 round-trip: generate an Ed25519 key in a NetCrypto key store, sign a payload into a
// tagged COSE_Sign1 (EdDSA), then verify it with the public key. Prints OK and exits 0 on success.

using System.Text;
using DataProofsDotnet.Cose;
using NetCrypto;

Console.WriteLine("=== DataProofsDotnet.Cose smoke — COSE_Sign1 (EdDSA) round-trip ===");

// 1. Non-exporting key store: ISigner + public key.
var store = new InMemoryKeyStore(new DefaultKeyGenerator(), new DefaultCryptoProvider());
var keyInfo = await store.GenerateAsync("smoke-key", KeyType.Ed25519);
var signer = await store.CreateSignerAsync("smoke-key");
Console.WriteLine($"  generated Ed25519 key ({keyInfo.PublicKey.Length}-byte public key)");

// 2. Sign a payload into a COSE_Sign1 message.
byte[] payload = Encoding.UTF8.GetBytes("data-proofs cose smoke");
byte[] encoded = await CoseSign1.SignAsync(
    payload,
    signer,
    new CoseSign1SignOptions
    {
        Algorithm = CoseAlgorithm.EdDsa,
        ContentType = "text/plain",
    });
Check(encoded.Length > 0, "COSE_Sign1 message encoded to bytes");
Console.WriteLine($"  signed COSE_Sign1 ({encoded.Length} bytes)");

// 3. Verify with the public key.
var result = CoseSign1.Verify(encoded, keyInfo.KeyType, keyInfo.PublicKey);
Check(result.Verified, "COSE_Sign1 verifies against the signing public key");
Check(result.Message is not null, "verification result carries the decoded message");
Check(result.Message!.Algorithm == CoseAlgorithm.EdDsa, "protected header algorithm is EdDSA");
Check(result.Message.Payload is { } p && p.Span.SequenceEqual(payload), "payload round-trips exactly");
Console.WriteLine("  verified COSE_Sign1");

// 4. Tamper one signature byte → must fail (verification returns a result, not an exception).
var tampered = (byte[])encoded.Clone();
tampered[^1] ^= 0x01;
var tamperedResult = CoseSign1.Verify(tampered, keyInfo.KeyType, keyInfo.PublicKey);
Check(!tamperedResult.Verified, "tampered COSE_Sign1 fails verification");

Console.WriteLine("OK — DataProofsDotnet.Cose smoke passed.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.Error.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
