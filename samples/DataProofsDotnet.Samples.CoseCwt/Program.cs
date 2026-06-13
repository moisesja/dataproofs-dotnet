using System.Text;
using DataProofsDotnet.Cose;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — COSE_Sign1 and CWT
// ============================================================
// FR-19: CBOR Object Signing & Encryption.
//   * COSE_Sign1 (RFC 9052): a single-signer CBOR signature structure with protected and
//     unprotected headers, optional detached payload and external AAD, and tag-emission control.
//   * CWT (RFC 8392): a CBOR Web Token — registered claims (iss/sub/aud/exp/nbf/iat/cti) carried
//     in a COSE_Sign1 payload, with exp/nbf validation under a configurable clock skew.
// Same v1 algorithm set as JWS, mapped to COSE algorithm ids: EdDSA(-8), ES256(-7), ES384(-35),
// ES256K(-47). Signing goes through NetCrypto ISigner; all CBOR via System.Formats.Cbor internally.
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

Console.WriteLine("=== COSE_Sign1 — every v1 algorithm ===");

(CoseAlgorithm Alg, KeyType KeyType)[] algorithms =
[
    (CoseAlgorithm.EdDsa, KeyType.Ed25519),
    (CoseAlgorithm.ES256, KeyType.P256),
    (CoseAlgorithm.ES384, KeyType.P384),
    (CoseAlgorithm.ES256K, KeyType.Secp256k1),
];

byte[] payload = Encoding.UTF8.GetBytes("""{"device":"sensor-7","reading":42}""");

foreach (var (alg, keyType) in algorithms)
{
    KeyPair pair = keyGen.Generate(keyType);
    var signer = new KeyPairSigner(pair, crypto);

    byte[] encoded = await CoseSign1.SignAsync(payload, signer, new CoseSign1SignOptions
    {
        Algorithm = alg,
        KeyId = Encoding.UTF8.GetBytes($"{keyType}-key"),
        ContentType = "application/json",
    });

    CoseSign1VerificationResult result = CoseSign1.Verify(encoded, keyType, pair.PublicKey);
    CoseSign1Message msg = result.Message!;
    Console.WriteLine($"  {alg,-8} ({(int)alg,3}): verified={result.Verified}, sig={msg.Signature.Length}B, tagged={msg.IsTagged}, cty={msg.ContentType}");
    Check(result.Verified, $"{alg} COSE_Sign1 round-trips");
    Check(msg.Algorithm == alg, $"{alg} is reported back");
    Check(msg.KeyId!.Value.ToArray().AsSpan().SequenceEqual(Encoding.UTF8.GetBytes($"{keyType}-key")), $"{alg} carries the kid");
    Check(msg.Payload!.Value.ToArray().AsSpan().SequenceEqual(payload), $"{alg} carries the payload");
    Check(msg.IsTagged, $"{alg} emits the COSE_Sign1 tag (18) by default");
    Check(msg.EncodedProtectedHeaders.Length > 0, $"{alg} exposes its encoded protected headers");
    Check(result.Failure is null, $"{alg} has no failure on success");
}
Console.WriteLine();

// ----------------------------------------------------------- detached payload + external AAD
Console.WriteLine("--- detached payload, external AAD, untagged emission ---");
KeyPair edKey = keyGen.Generate(KeyType.Ed25519);
var edSigner = new KeyPairSigner(edKey, crypto);

// Detached: the payload is omitted from the wire and re-supplied at verification.
byte[] detached = await CoseSign1.SignAsync(payload, edSigner, new CoseSign1SignOptions
{
    Algorithm = CoseAlgorithm.EdDsa,
    DetachedPayload = true,
});
Check(CoseSign1.Decode(detached).Payload is null, "a detached COSE_Sign1 carries no payload on the wire");
Check(CoseSign1.Verify(detached, KeyType.Ed25519, edKey.PublicKey, new CoseSign1VerifyOptions { DetachedPayload = payload }).Verified,
    "a detached payload verifies when re-supplied");
Check(!CoseSign1.Verify(detached, KeyType.Ed25519, edKey.PublicKey).Verified, "a missing detached payload fails");

// External AAD (RFC 9052 §4.4): authenticated but not transmitted.
byte[] aad = Encoding.UTF8.GetBytes("session-1234");
byte[] withAad = await CoseSign1.SignAsync(payload, edSigner, new CoseSign1SignOptions
{
    Algorithm = CoseAlgorithm.EdDsa,
    ExternalData = aad,
    ContentFormat = 50, // CoAP content-format id (mutually exclusive with ContentType)
    Type = "application/example",
});
Check(CoseSign1.Verify(withAad, KeyType.Ed25519, edKey.PublicKey, new CoseSign1VerifyOptions { ExternalData = aad }).Verified,
    "external AAD verifies when matched");
CoseSign1VerificationResult aadMismatch = CoseSign1.Verify(withAad, KeyType.Ed25519, edKey.PublicKey);
Check(!aadMismatch.Verified && aadMismatch.Failure!.Code == CoseVerificationErrorCode.InvalidSignature, "omitting the AAD fails with InvalidSignature");
CoseSign1Message aadMsg = CoseSign1.Decode(withAad);
Console.WriteLine($"  contentFormat={aadMsg.ContentFormat}, typ={aadMsg.Type}");
Check(aadMsg.ContentFormat == 50, "ContentFormat is carried when used instead of ContentType");

// Untagged emission.
byte[] untagged = await CoseSign1.SignAsync(payload, edSigner, new CoseSign1SignOptions
{
    Algorithm = CoseAlgorithm.EdDsa,
    IncludeCoseSign1Tag = false,
});
Check(!CoseSign1.Decode(untagged).IsTagged, "untagged emission omits the COSE_Sign1 tag");
Console.WriteLine($"  untagged round-trips: {CoseSign1.Verify(untagged, KeyType.Ed25519, edKey.PublicKey).Verified}");

// Negative: tampered signature fails with a code, not an exception. The failure is surfaced as a
// CoseVerificationFailure (code + message), never thrown.
byte[] tampered = (byte[])untagged.Clone();
tampered[^1] ^= 0xff;
CoseSign1VerificationResult tamperResult = CoseSign1.Verify(tampered, KeyType.Ed25519, edKey.PublicKey);
CoseVerificationFailure failure = tamperResult.Failure!;
Console.WriteLine($"  tampered signature: verified={tamperResult.Verified}, failure={failure.Code} ({failure.Message})");
Check(!tamperResult.Verified, "a tampered COSE_Sign1 fails (a result, not an exception)");

// Misconfiguration (vs. a verification result) IS an exception: a signing-time algorithm/key-type
// mismatch throws CoseException (FR-23 — exceptions for caller bugs, results for bad signatures).
bool misconfigThrew;
try
{
    await CoseSign1.SignAsync(payload, edSigner, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256 }); // Ed25519 key, ES256 alg
    misconfigThrew = false;
}
catch (CoseException ex)
{
    misconfigThrew = true;
    Console.WriteLine($"  signing with a mismatched algorithm throws CoseException: {ex.GetType().Name}");
}
Check(misconfigThrew, "an algorithm/key-type mismatch at signing throws CoseException (misconfiguration, not a result)");
Console.WriteLine();

// ----------------------------------------------------------- CWT
Console.WriteLine("=== CWT (CBOR Web Token) ===");
KeyPair cwtKey = keyGen.Generate(KeyType.P256);
var cwtSigner = new KeyPairSigner(cwtKey, crypto);
var now = new DateTimeOffset(2026, 6, 12, 12, 0, 0, TimeSpan.Zero);

var claims = new CwtClaims
{
    Issuer = "coap://as.example.com",
    Subject = "device-7",
    Audience = "coap://rs.example.com",
    ExpirationTime = now.AddHours(1),
    NotBefore = now.AddMinutes(-5),
    IssuedAt = now,
    CwtId = new byte[] { 0x0b, 0x71 },
};

byte[] cwt = await Cwt.SignAsync(claims, cwtSigner, new CwtSignOptions
{
    Algorithm = CoseAlgorithm.ES256,
    KeyId = Encoding.UTF8.GetBytes("cwt-key"),
    IncludeCwtTag = true,
});

CwtVerificationResult cwtResult = Cwt.Verify(cwt, KeyType.P256, cwtKey.PublicKey, new CwtValidationOptions
{
    ValidationTime = now,
    ClockSkew = TimeSpan.FromSeconds(60),
});
Console.WriteLine($"  CWT verified={cwtResult.Verified}, iss={cwtResult.Claims!.Issuer}, sub={cwtResult.Claims.Subject}, aud={cwtResult.Claims.Audience}");
Check(cwtResult.Verified, "the CWT round-trips and validates inside its window");
Check(cwtResult.Claims!.Issuer == claims.Issuer && cwtResult.Claims.Subject == claims.Subject, "iss/sub survive");
Check(cwtResult.Claims.ExpirationTime == claims.ExpirationTime && cwtResult.Claims.NotBefore == claims.NotBefore, "exp/nbf survive");
Check(cwtResult.Claims.CwtId!.Value.ToArray().AsSpan().SequenceEqual(new byte[] { 0x0b, 0x71 }), "cti survives");
Check(cwtResult.Failure is null, "a valid CWT has no failure");

// Expired: validating past exp + skew fails with Expired (a result).
CwtVerificationResult expired = Cwt.Verify(cwt, KeyType.P256, cwtKey.PublicKey, new CwtValidationOptions
{
    ValidationTime = now.AddHours(2),
});
Console.WriteLine($"  validated 2h later: verified={expired.Verified}, failure={expired.Failure!.Code}");
Check(!expired.Verified && expired.Failure!.Code == CoseVerificationErrorCode.Expired, "an expired CWT fails with Expired");

// Not-yet-valid.
CwtVerificationResult tooEarly = Cwt.Verify(cwt, KeyType.P256, cwtKey.PublicKey, new CwtValidationOptions
{
    ValidationTime = now.AddMinutes(-30),
});
Check(!tooEarly.Verified && tooEarly.Failure!.Code == CoseVerificationErrorCode.NotYetValid, "a not-yet-valid CWT fails with NotYetValid");

// Decode the bare claims set (without verifying a signature). Use an untagged CWT here so
// CoseSign1.Decode accepts it (the CWT-tagged form above must go through the Cwt API).
byte[] untaggedCwt = await Cwt.SignAsync(claims, cwtSigner, new CwtSignOptions { Algorithm = CoseAlgorithm.ES256 });
byte[] claimsOnly = CoseSign1.Decode(untaggedCwt).Payload!.Value.ToArray();
CwtClaims decoded = Cwt.DecodeClaims(claimsOnly);
Console.WriteLine($"  decoded bare claims: iss={decoded.Issuer}, iat={decoded.IssuedAt}");
Check(decoded.Issuer == claims.Issuer && decoded.IssuedAt == claims.IssuedAt, "Cwt.DecodeClaims decodes a bare claims set");

Console.WriteLine();
Console.WriteLine("Done! COSE_Sign1 / CWT example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
