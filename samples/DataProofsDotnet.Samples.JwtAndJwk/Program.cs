using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — JWT and JWK
// ============================================================
// FR-15: a JWT claims set signed as a JWS, with exp/nbf/iat/iss/aud/sub validation under a
// configurable clock skew (and structured, never-throwing results); plus JWK handling —
// conversion to/from Multikey and NetCrypto keys, and RFC 7638 thumbprints / kid conventions.
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();
var now = new DateTimeOffset(2026, 6, 12, 12, 0, 0, TimeSpan.Zero);

Console.WriteLine("=== JWT claims validation ===");

KeyPair issuerKey = keyGen.Generate(KeyType.Ed25519);
const string kid = "did:example:issuer#jwt-1";
var jwsSigner = new JwsSigner(new KeyPairSigner(issuerKey, crypto), kid);
Jwk issuerPublicJwk = JwkConversion.ToPublicJwk(issuerKey.KeyType, issuerKey.PublicKey, kid);

// A full claims set, including a custom claim alongside the registered ones.
var claims = new JwtClaims(
    issuer: "did:example:issuer",
    subject: "did:example:subject",
    audiences: ["did:example:verifier"],
    expiresAt: now.AddMinutes(10),
    notBefore: now.AddMinutes(-1),
    issuedAt: now,
    jwtId: "jti-2026-001",
    additionalClaims: new Dictionary<string, JsonNode?> { ["scope"] = "credential:read" });

string jwt = await JwtHandler.SignAsync(claims, jwsSigner);
Console.WriteLine($"  signed JWT: {jwt[..32]}... ({jwt.Length} chars)");

// The header typ is JWT.
using (var header = JsonDocument.Parse(Base64Url.Decode(jwt.Split('.')[0])))
{
    Check(header.RootElement.GetProperty("typ").GetString() == "JWT", "the JWT header typ is JWT");
}

// Strict validation passes when every expectation matches.
var strict = new JwtValidationOptions
{
    CurrentTime = now,
    ExpectedIssuer = "did:example:issuer",
    ExpectedAudience = "did:example:verifier",
    ExpectedSubject = "did:example:subject",
    RequireExpirationTime = true,
    ClockSkew = TimeSpan.FromSeconds(30),
    AllowedAlgorithms = [JoseAlgorithms.EdDSA],
    // RFC 8725 §3.11 explicit typing (opt-in): pin the protected 'typ' header so a token minted
    // for a different purpose under the same key cannot be replayed as this JWT. The 'application/'
    // prefix is tolerated, so "JWT" matches a header typ of "JWT" or "application/JWT".
    ExpectedType = "JWT",
};
JwtVerificationResult ok = JwtHandler.Verify(jwt, _ => issuerPublicJwk, strict, joseCrypto);
Console.WriteLine($"  valid: {ok.IsValid}, alg={ok.SignatureAlgorithm}, signerKid={ok.SignerKid}");
Check(ok.IsValid, "a fully matching JWT validates");
Check(ok.SignatureAlgorithm == JoseAlgorithms.EdDSA, "the validated JWT reports its algorithm");
Check(ok.Claims!.Issuer == "did:example:issuer" && ok.Claims.JwtId == "jti-2026-001", "the validated claims are surfaced");
Check(ok.Claims.AdditionalClaims["scope"]!.GetValue<string>() == "credential:read", "custom claims survive");
Check(ok.Claims.Audiences.Contains("did:example:verifier"), "the audience list is surfaced");
Check(ok.Errors.Count == 0, "a valid JWT has no errors");

// Mismatched issuer/audience/subject each produce a distinct error (a result, never an exception).
JwtVerificationResult mismatch = JwtHandler.Verify(jwt, _ => issuerPublicJwk, new JwtValidationOptions
{
    CurrentTime = now,
    ExpectedIssuer = "did:example:other",
    ExpectedAudience = "did:example:other-aud",
    ExpectedSubject = "did:example:other-sub",
});
Console.WriteLine($"  mismatch errors: {string.Join(", ", mismatch.Errors.Select(e => e.Split(':')[0].Split(' ')[0]))}");
Check(!mismatch.IsValid, "mismatched expectations fail");
Check(mismatch.Errors.Any(e => e.StartsWith("ISSUER")), "issuer mismatch is reported");
Check(mismatch.Errors.Any(e => e.StartsWith("AUDIENCE")), "audience mismatch is reported");
Check(mismatch.Errors.Any(e => e.StartsWith("SUBJECT")), "subject mismatch is reported");

// Explicit typing: a token whose 'typ' is not the expected one is rejected (RFC 8725 §3.11).
JwtVerificationResult wrongType = JwtHandler.Verify(
    jwt, _ => issuerPublicJwk, new JwtValidationOptions { CurrentTime = now, ExpectedType = "kb+jwt" });
Check(!wrongType.IsValid, "a JWT whose typ is not the expected type fails");
Check(wrongType.Errors.Any(e => e.StartsWith("TYPE_MISMATCH")), "the typ mismatch is reported");

// Expiry: past the skew it fails; inside the skew it passes.
var expiring = new JwtClaims(expiresAt: now);
string expiringJwt = await JwtHandler.SignAsync(expiring, jwsSigner);
JwtVerificationResult expired = JwtHandler.Verify(expiringJwt, _ => issuerPublicJwk,
    new JwtValidationOptions { CurrentTime = now.AddSeconds(120), ClockSkew = TimeSpan.FromSeconds(60) });
Check(!expired.IsValid && expired.Errors.Any(e => e.StartsWith("EXPIRED")), "an expired token fails with EXPIRED");
JwtVerificationResult inSkew = JwtHandler.Verify(expiringJwt, _ => issuerPublicJwk,
    new JwtValidationOptions { CurrentTime = now.AddSeconds(30), ClockSkew = TimeSpan.FromSeconds(60) });
Check(inSkew.IsValid, "the clock skew absorbs a small expiry overshoot");
Console.WriteLine("  expiry honors the configurable clock skew");

// A wrong key yields SIGNATURE_INVALID without throwing.
KeyPair wrongKey = keyGen.Generate(KeyType.Ed25519);
JwtVerificationResult badSig = JwtHandler.Verify(jwt, _ => JwkConversion.ToPublicJwk(wrongKey.KeyType, wrongKey.PublicKey, kid),
    new JwtValidationOptions { CurrentTime = now });
Check(!badSig.IsValid && badSig.Errors.Any(e => e.StartsWith("SIGNATURE_INVALID")), "a wrong key fails with SIGNATURE_INVALID");

// The claims set round-trips through its own JSON form.
JwtClaims parsed = JwtClaims.Parse(claims.ToJsonBytes());
Check(parsed.Issuer == claims.Issuer && parsed.Subject == claims.Subject, "JwtClaims.Parse round-trips iss/sub");
Check(parsed.ExpiresAt == claims.ExpiresAt && parsed.NotBefore == claims.NotBefore && parsed.IssuedAt == claims.IssuedAt, "JwtClaims.Parse round-trips the time claims");
Console.WriteLine();

// ----------------------------------------------------------- JWK conversion + thumbprints
Console.WriteLine("=== JWK <-> Multikey conversion and thumbprints ===");

foreach (KeyType keyType in new[] { KeyType.Ed25519, KeyType.P256, KeyType.P384, KeyType.Secp256k1 })
{
    KeyPair pair = keyGen.Generate(keyType);
    string multibase = pair.MultibasePublicKey;

    // Multikey -> JWK and back; the kid is optional.
    Jwk fromMk = JwkConversion.FromMultikey(multibase, kid: $"{keyType}-key");
    string backToMk = JwkConversion.ToMultikey(fromMk);
    Console.WriteLine($"  {keyType,-10} kty={fromMk.Kty,-3} crv={fromMk.Crv,-9} multikey-roundtrip={backToMk == multibase}");
    Check(backToMk == multibase, $"{keyType} Multikey -> JWK -> Multikey round-trips");

    // Public/private JWKs from a NetCrypto key pair.
    Jwk publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, $"{keyType}-pub");
    Jwk privateJwk = JwkConversion.ToPrivateJwk(pair, $"{keyType}-priv");
    publicJwk.Use = "sig";
    publicJwk.Alg = keyType == KeyType.Ed25519 ? JoseAlgorithms.EdDSA : null;
    Check(privateJwk.D is not null, $"{keyType} private JWK carries the 'd' parameter");
    Check(publicJwk.D is null, $"{keyType} public JWK omits the private 'd'");
    Check(!string.IsNullOrEmpty(publicJwk.X), $"{keyType} JWK carries the x coordinate");

    // ExtractPublicKey gives back the NetCrypto (KeyType, bytes) pair.
    var (extractedType, extractedBytes) = JwkConversion.ExtractPublicKey(publicJwk);
    Check(extractedType == keyType && extractedBytes.AsSpan().SequenceEqual(pair.PublicKey), $"{keyType} ExtractPublicKey recovers the key");

    // ToJsonWebKey crosses into the Microsoft.IdentityModel boundary type.
    Microsoft.IdentityModel.Tokens.JsonWebKey msJwk = JwkConversion.ToJsonWebKey(publicJwk);
    Check(msJwk.Kty == publicJwk.Kty, $"{keyType} ToJsonWebKey preserves the key type");

    // RFC 7638 thumbprint: stable digest over the canonical required-members JSON.
    byte[] tp = JwkThumbprint.Compute(publicJwk);
    string tpB64 = JwkThumbprint.ComputeBase64Url(publicJwk);
    string tpKid = JwkThumbprint.ComputeKid(publicJwk);
    Check(tp.Length == 32, $"{keyType} thumbprint is a 32-byte SHA-256 digest");
    Check(Base64Url.Encode(tp) == tpB64, $"{keyType} thumbprint base64url matches the raw digest");
    Check(tpKid == tpB64, $"{keyType} thumbprint kid is the base64url thumbprint");
    // Thumbprint is stable across a Multikey round-trip (the public key is the same).
    Check(JwkThumbprint.ComputeBase64Url(JwkConversion.FromMultikey(multibase)) == JwkThumbprint.ComputeBase64Url(publicJwk),
        $"{keyType} thumbprint is stable across JWK<->Multikey");
}

// Jwk also carries arbitrary additional members (e.g. x5t) and 'y' for EC keys.
KeyPair p256 = keyGen.Generate(KeyType.P256);
Jwk ecJwk = JwkConversion.ToPublicJwk(p256.KeyType, p256.PublicKey, "ec-extra");
ecJwk.AdditionalData = new Dictionary<string, JsonElement> { ["x5t"] = JsonSerializer.SerializeToElement("abc123") };
Console.WriteLine($"  EC JWK has y coordinate: {!string.IsNullOrEmpty(ecJwk.Y)}; additional member x5t present: {ecJwk.AdditionalData!.ContainsKey("x5t")}");
Check(!string.IsNullOrEmpty(ecJwk.Y), "an EC JWK carries the y coordinate");
Check(ecJwk.AdditionalData!.ContainsKey("x5t"), "a Jwk carries arbitrary additional members");

// A symmetric (oct) Jwk exposes its K parameter.
var octJwk = new Jwk { Kty = "oct", K = Base64Url.Encode(Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef")) };
Check(octJwk.K is not null && octJwk.Kty == "oct", "an oct Jwk exposes its symmetric key (K)");

Console.WriteLine();
Console.WriteLine("Done! JWT/JWK example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
