using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;
// NetCrypto also ships a Base64Url; alias the one this sample uses.
using Base64Url = DataProofsDotnet.Jose.Base64Url;

// ============================================================
// DataProofsDotnet Samples — X.509 certificate chains (x5c)
// ============================================================
// RFC 7515 §4.1.6 / draft-ietf-oauth-sd-jwt-vc-27 §2.5 ("Inline X.509 Certificates"):
//   * SIGNING — put the issuer's chain on its JwsSigner; every JWS, SD-JWT and SD-JWT VC it signs then carries
//     `x5c` in the PROTECTED header.
//   * VERIFYING — call the *WithCertificateChain method: the key comes from the end-entity certificate (x5c[0]),
//     the signature is checked with it, and then YOUR hook decides whether the chain is trusted.
//   * THE HOOK IS THE TRUST DECISION. The library parses the certificates and validates nothing about them: no
//     certificate signature, validity period, key usage, chain order, revocation or trust anchor. A certificate in
//     x5c is never a trust anchor because it is there. This sample's hook uses the platform's X509Chain against the
//     verifier's own anchor; certificates from x5c go only into ExtraStore.
//
// The PKI here is made on the fly with the platform's CertificateRequest. Signing still goes through NetCrypto.

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();
byte[] payload = Encoding.UTF8.GetBytes("""{"iss":"https://issuer.example","scope":"read"}""");

Console.WriteLine("=== X.509 certificate chains — x5c on JWS, SD-JWT and SD-JWT VC ===");

// ----------------------------------------------------------- 1. A demo PKI: root → intermediate → issuer
var now = DateTimeOffset.UtcNow;
using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var rootRequest = new CertificateRequest("CN=Example Root CA", rootKey, HashAlgorithmName.SHA256);
rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
using X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));

using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var intermediateRequest = new CertificateRequest("CN=Example Issuing CA", intermediateKey, HashAlgorithmName.SHA256);
intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
using X509Certificate2 intermediate = intermediateRequest.Create(root, now.AddDays(-1), now.AddYears(2), [0x01]);

// The issuer's key lives in NetCrypto; the certificate only needs its public half.
KeyPair issuerKey = keyGen.Generate(KeyType.P256);
Jwk issuerJwk = JwkConversion.ToPublicJwk(issuerKey.KeyType, issuerKey.PublicKey);
using var issuerPublic = ECDsa.Create(new ECParameters
{
    Curve = ECCurve.NamedCurves.nistP256,
    Q = new ECPoint { X = Base64Url.Decode(issuerJwk.X!), Y = Base64Url.Decode(issuerJwk.Y!) },
});
var issuerRequest = new CertificateRequest("CN=issuer.example", issuerPublic, HashAlgorithmName.SHA256);
issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
using X509Certificate2 issuerCertificate = issuerRequest.Create(
    intermediate.SubjectName, X509SignatureGenerator.CreateForECDsa(intermediateKey), now.AddDays(-1), now.AddYears(1), [0x02]);
Console.WriteLine($"  PKI: {root.Subject} → {intermediate.Subject} → {issuerCertificate.Subject}");

// The chain the issuer sends: end-entity first, then the intermediate. The root is the VERIFIER's anchor, not sent.
X509CertificateChain chain = X509CertificateChain.Create([issuerCertificate.RawData, intermediate.RawData]);
Console.WriteLine($"  chain.Certificates={chain.Certificates.Count} (at most X509CertificateChain.MaxCertificates={X509CertificateChain.MaxCertificates})");
Check(chain.EndEntityCertificate.Span.SequenceEqual(issuerCertificate.RawData), "x5c[0] is the end-entity certificate");
Check(chain.EndEntityPublicKey.X == issuerJwk.X && chain.EndEntityPublicKey.Crv == "P-256",
    "EndEntityPublicKey is the issuer's key, as a JWK");
Console.WriteLine();

// The verifier's hook: RFC 5280 path validation by the platform, to the verifier's own anchor only.
bool TrustedByExampleRoot(X509CertificateChain presented)
{
    using var platformChain = new X509Chain();
    platformChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    platformChain.ChainPolicy.CustomTrustStore.Add(root);          // the verifier's anchor
    platformChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // a real verifier checks revocation
    platformChain.ChainPolicy.DisableCertificateDownloads = true;
    foreach (var certificate in presented.Certificates.Skip(1))     // x5c certificates: candidates, never anchors
        platformChain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(certificate.Span));
    using var endEntity = X509CertificateLoader.LoadCertificate(presented.EndEntityCertificate.Span);
    return platformChain.Build(endEntity);
}

// ----------------------------------------------------------- 2. Compact JWS with x5c
Console.WriteLine("--- compact JWS ---");
var signer = new JwsSigner(new KeyPairSigner(issuerKey, crypto)) { CertificateChain = chain };
Check(signer.CertificateChain == chain, "JwsSigner.CertificateChain carries the chain");
string compact = await JwsBuilder.BuildCompactAsync(payload, signer, typ: "example+jwt");
var header = JsonNode.Parse(Base64Url.Decode(compact.Split('.')[0]))!.AsObject();
Console.WriteLine($"  protected header members: {string.Join(", ", header.Select(m => m.Key))}");
Check(header["x5c"]!.AsArray().Count == 2, "x5c rides in the protected header");

JwsParseResult verified = JwsParser.ParseCompactWithCertificateChain(compact, TrustedByExampleRoot, joseCrypto);
Console.WriteLine($"  verified alg={verified.SignatureAlgorithm}, signer={X509CertificateLoader.LoadCertificate(verified.CertificateChain!.EndEntityCertificate.Span).Subject}");
Check(verified.PayloadBytes.AsSpan().SequenceEqual(payload), "the key from x5c[0] verifies the JWS, and the hook accepted the chain");

// A chain the hook does not accept fails, though the signature itself is fine.
Check(Throws<JoseCryptoException>(() => JwsParser.ParseCompactWithCertificateChain(compact, _ => false, joseCrypto), "X5C_UNTRUSTED"),
    "a chain the hook refuses is X5C_UNTRUSTED");

// An attacker's own PKI: its root, sent inside x5c, issues a certificate for the attacker's key. The signature
// verifies under that key, and the hook still refuses the chain, because the attacker's root is not the verifier's
// anchor: a certificate in x5c is not a trust anchor because it is there.
using var attackerRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using X509Certificate2 attackerRoot = new CertificateRequest("CN=Example Root CA", attackerRootKey, HashAlgorithmName.SHA256)
    .CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
KeyPair attackerKey = keyGen.Generate(KeyType.P256);
Jwk attackerJwk = JwkConversion.ToPublicJwk(attackerKey.KeyType, attackerKey.PublicKey);
using var attackerPublic = ECDsa.Create(new ECParameters
{
    Curve = ECCurve.NamedCurves.nistP256,
    Q = new ECPoint { X = Base64Url.Decode(attackerJwk.X!), Y = Base64Url.Decode(attackerJwk.Y!) },
});
using X509Certificate2 attackerCertificate = new CertificateRequest("CN=issuer.example", attackerPublic, HashAlgorithmName.SHA256)
    .Create(attackerRoot.SubjectName, X509SignatureGenerator.CreateForECDsa(attackerRootKey), now.AddDays(-1), now.AddDays(1), [0x03]);
var attacker = new JwsSigner(new KeyPairSigner(attackerKey, crypto))
{
    CertificateChain = X509CertificateChain.Create([attackerCertificate.RawData, attackerRoot.RawData]),
};
string forged = await JwsBuilder.BuildCompactAsync(payload, attacker);
Check(Throws<JoseCryptoException>(() => JwsParser.ParseCompactWithCertificateChain(forged, TrustedByExampleRoot, joseCrypto), "X5C_UNTRUSTED"),
    "a root carried in x5c is not a trust anchor");

// A malformed x5c is a parse failure with a stable code.
string badHeader = Base64Url.Encode(Encoding.UTF8.GetBytes("""{"alg":"ES256","x5c":"not-an-array"}"""));
Check(Throws<MalformedJoseException>(() => JwsParser.ParseCompactWithCertificateChain(
        badHeader + "." + compact.Split('.')[1] + "." + compact.Split('.')[2], TrustedByExampleRoot, joseCrypto), "X5C_MALFORMED"),
    "a malformed x5c is X5C_MALFORMED");
Console.WriteLine();

// ----------------------------------------------------------- 3. SD-JWT with x5c
Console.WriteLine("--- SD-JWT ---");
var claims = new JsonObject
{
    ["vct"] = "https://credentials.example.com/identity_credential",
    ["given_name"] = "Erika",
    ["family_name"] = "Mustermann",
};
var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name");
SdJwtIssuer.Result sdJwt = await SdJwtIssuer.IssueAsync(claims, frame, signer, typ: "example+sd-jwt");
SdJwtVerificationResult sdResult = SdJwtVerifier.VerifyWithCertificateChain(sdJwt.Issuance, TrustedByExampleRoot);
Console.WriteLine($"  valid={sdResult.IsValid}, IssuerCertificateChain={sdResult.IssuerCertificateChain?.Certificates.Count} certificates");
Check(sdResult.IsValid && sdResult.IssuerCertificateChain is not null, "an SD-JWT verifies with the issuer key from x5c");
Console.WriteLine();

// ----------------------------------------------------------- 4. SD-JWT VC, the Inline X.509 Certificates mechanism
Console.WriteLine("--- SD-JWT VC ---");
SdJwtIssuer.Result vc = await SdJwtVcIssuer.IssueAsync(claims, frame, signer);
SdJwtVcVerificationResult vcResult = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(vc.Issuance, TrustedByExampleRoot);
Console.WriteLine($"  valid={vcResult.IsValid}, vct={vcResult.Vct}");
Check(vcResult.IsValid, "an SD-JWT VC verifies under the Inline X.509 Certificates mechanism");
// Under this mechanism the Issuer is the end-entity certificate's subject; an `iss` claim is NOT authenticated by it.
using var issuer = X509CertificateLoader.LoadCertificate(vcResult.IssuerCertificateChain!.EndEntityCertificate.Span);
Console.WriteLine($"  the Issuer is the certificate subject: {issuer.Subject}");
Check(issuer.Subject == "CN=issuer.example", "IssuerCertificateChain identifies the Issuer");

SdJwtVcVerificationResult refused = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(vc.Issuance, _ => false);
Console.WriteLine($"  refused by the hook: {refused.Errors[0][..13]}...");
Check(!refused.IsValid && refused.Errors[0].StartsWith("X5C_UNTRUSTED", StringComparison.Ordinal), "the hook's refusal is X5C_UNTRUSTED");

Console.WriteLine();
Console.WriteLine("Done! X.509 certificate chain example completed successfully.");
return 0;

static bool Throws<T>(Action action, string code) where T : Exception
{
    try
    {
        action();
        return false;
    }
    catch (T ex)
    {
        return ex.Message.StartsWith(code, StringComparison.Ordinal);
    }
}

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
