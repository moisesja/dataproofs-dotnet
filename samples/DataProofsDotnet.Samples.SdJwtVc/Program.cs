using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;
// NetCrypto 1.1.0 also ships a Base64Url; alias the one this sample showcases.
using Base64Url = DataProofsDotnet.Jose.Base64Url;

// ============================================================
// DataProofsDotnet Samples — SD-JWT VC profile
// ============================================================
// FR-17 (draft-ietf-oauth-sd-jwt-vc-16): the SD-JWT VC profile layered on generic SD-JWT.
// On top of the disclosure mechanics it adds, end to end:
//   * a required `vct` (verifiable credential type) claim — rejected if missing/blank,
//   * the `dc+sd-jwt` media type (with transitional `vc+sd-jwt` accepted on input),
//   * registered claims that MUST NOT be selectively disclosed (iss/nbf/exp/cnf/vct/...),
//   * offline-by-default Type Metadata (`vct`) resolution via a pluggable resolver hook —
//     LocalCacheTypeMetadataResolver here, never the network (FR-10 posture).
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();

KeyPair issuerPair = keyGen.Generate(KeyType.P256);
var issuerSigner = new JwsSigner(new KeyPairSigner(issuerPair, crypto), "did:example:issuer#vc");
Jwk issuerPublicJwk = JwkConversion.ToPublicJwk(issuerPair.KeyType, issuerPair.PublicKey, "did:example:issuer#vc");
Func<string, Jwk?> resolveIssuer = _ => issuerPublicJwk;

const string vct = "https://credentials.example.com/identity_credential";

JsonObject VcClaims() => new()
{
    ["iss"] = "https://example.com/issuer",
    ["vct"] = vct,
    ["given_name"] = "John",
    ["family_name"] = "Doe",
    ["birthdate"] = "1940-01-01",
    ["address"] = new JsonObject { ["country"] = "US", ["locality"] = "Anytown" },
};

Console.WriteLine("=== SD-JWT VC profile (end to end) ===");
Console.WriteLine($"  media type: {SdJwtVcConstants.MediaType} (transitional input also accepted: {SdJwtVcConstants.TransitionalMediaType})");
Console.WriteLine($"  vct claim: '{SdJwtVcConstants.VctClaim}', integrity: '{SdJwtVcConstants.VctIntegrityClaim}', status: '{SdJwtVcConstants.StatusClaim}'");
Console.WriteLine($"  must-not-be-disclosed: {string.Join(", ", SdJwtVcConstants.MustNotBeSelectivelyDisclosed)}");
Check(SdJwtVcConstants.MediaType == "dc+sd-jwt", "the SD-JWT VC media type is dc+sd-jwt");
Check(SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains("vct"), "vct is in the must-not-disclose set");
Console.WriteLine();

// ----------------------------------------------------------- 1. Issuer + holder + verifier with KB
Console.WriteLine("--- issuer -> holder -> verifier (with key binding) ---");
KeyPair holderPair = keyGen.Generate(KeyType.P256);
var holderSigner = new JwsSigner(new KeyPairSigner(holderPair, crypto), "did:example:holder#kb");
Jwk holderConfirmationKey = JwkConversion.ToPublicJwk(holderPair.KeyType, holderPair.PublicKey, "did:example:holder#kb");

var issuerOptions = new SdJwtIssuerOptions { HolderConfirmationKey = holderConfirmationKey };
var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name").Disclose("birthdate");
SdJwtIssuer.Result issued = await SdJwtVcIssuer.IssueAsync(VcClaims(), frame, issuerSigner, issuerOptions);

// The issuer fixed the typ to dc+sd-jwt (visible in the issuer JWT header).
string issuerHeader = Base64Url.DecodeUtf8(SdJwtComponents.Parse(issued.Issuance).IssuerJwt.Split('.')[0]);
Console.WriteLine($"  issuer JWT typ contains dc+sd-jwt: {issuerHeader.Contains(SdJwtVcConstants.MediaType)}");
Check(issuerHeader.Contains(SdJwtVcConstants.MediaType), "the issuer fixed the dc+sd-jwt media type");

const string audience = "https://verifier.example.org";
const string nonce = "n-vc-2026";
string presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
    issued.Issuance,
    issued.Disclosures.Where(d => d.ClaimName == "given_name").Select(d => d.Encoded), // present only given_name
    holderSigner, audience, nonce);

var verifyOptions = new SdJwtVerificationOptions
{
    RequireKeyBinding = true,
    ExpectedAudience = audience,
    ExpectedNonce = nonce,
};
SdJwtVcVerificationResult result = await SdJwtVcVerifier.VerifyAsync(presentation, resolveIssuer, verifyOptions, cryptoProvider: joseCrypto);
Console.WriteLine($"  valid={result.IsValid}, vct={result.Vct}, keyBinding={result.KeyBindingVerified}");
Check(result.IsValid, "the VC presentation verifies");
Check(result.Vct == vct, "the verifier surfaces the resolved vct");
Check(result.KeyBindingVerified, "the holder's key binding verifies");
Check(result.DisclosedPayload!.ContainsKey("given_name") && !result.DisclosedPayload.ContainsKey("family_name"),
    "only the presented claim is reconstructed");
Console.WriteLine();

// ----------------------------------------------------------- 2. vct rules
Console.WriteLine("--- vct presence + media-type rules ---");

// Missing vct is rejected at issuance.
bool missingVctRejected;
try
{
    var noVct = VcClaims();
    noVct.Remove("vct");
    await SdJwtVcIssuer.IssueAsync(noVct, frame, issuerSigner);
    missingVctRejected = false;
}
catch (MalformedJoseException)
{
    missingVctRejected = true;
}
Console.WriteLine($"  issuance without vct rejected: {missingVctRejected}");
Check(missingVctRejected, "a claims set missing vct is rejected (MalformedJoseException)");

// A generic SD-JWT (no vct) presented to the VC verifier fails on the media-type/profile rule.
KeyPair plainPair = keyGen.Generate(KeyType.P256);
var plainSigner = new JwsSigner(new KeyPairSigner(plainPair, crypto), "plain");
Jwk plainPublic = JwkConversion.ToPublicJwk(plainPair.KeyType, plainPair.PublicKey, "plain");
SdJwtIssuer.Result generic = await SdJwtIssuer.IssueAsync(
    new JsonObject { ["iss"] = "x", ["foo"] = "bar" }, new DisclosureFrame().Disclose("foo"), plainSigner, typ: "example+sd-jwt");
SdJwtVcVerificationResult genericResult = await SdJwtVcVerifier.VerifyAsync(generic.Issuance, _ => plainPublic, cryptoProvider: joseCrypto);
Console.WriteLine($"  generic SD-JWT (no vct) rejected by VC verifier: {!genericResult.IsValid} ({genericResult.Errors.FirstOrDefault()})");
Check(!genericResult.IsValid, "a non-VC SD-JWT is rejected by the VC verifier");

// The transitional vc+sd-jwt typ is still accepted on input.
SdJwtIssuer.Result transitional = await SdJwtIssuer.IssueAsync(
    VcClaims(), frame, issuerSigner, typ: SdJwtVcConstants.TransitionalMediaType);
SdJwtVcVerificationResult transitionalResult = await SdJwtVcVerifier.VerifyAsync(transitional.Issuance, resolveIssuer, cryptoProvider: joseCrypto);
Console.WriteLine($"  transitional vc+sd-jwt accepted on input: {transitionalResult.IsValid}");
Check(transitionalResult.IsValid && transitionalResult.Vct == vct, "the transitional media type is accepted on input");
Console.WriteLine();

// ----------------------------------------------------------- 3. Type Metadata (offline, opt-in)
Console.WriteLine("--- Type Metadata resolution (offline LocalCacheTypeMetadataResolver) ---");

var typeMetadata = new JsonObject
{
    ["vct"] = vct,
    ["name"] = "Identity Credential",
    ["description"] = "An example identity credential type.",
};

// Seed the offline resolver with the vct -> Type Metadata mapping (no network, ever).
ITypeMetadataResolver seeded = new LocalCacheTypeMetadataResolver(new Dictionary<string, JsonObject> { [vct] = typeMetadata });
SdJwtVcVerificationResult withMetadata = await SdJwtVcVerifier.VerifyAsync(
    issued.Issuance, resolveIssuer, typeMetadataResolver: seeded, cryptoProvider: joseCrypto);
Console.WriteLine($"  resolved type metadata name: {withMetadata.TypeMetadata?["name"]?.GetValue<string>()}");
Check(withMetadata.IsValid && withMetadata.TypeMetadata is not null, "Type Metadata is resolved from the local cache");
Check(withMetadata.TypeMetadata!["vct"]!.GetValue<string>() == vct, "the resolved metadata is for the right vct");

// An empty resolver returns null for an unknown vct — fail-closed offline default, no network.
var empty = new LocalCacheTypeMetadataResolver();
Check(await empty.ResolveAsync(vct) is null, "an empty resolver returns null (offline fail-closed)");
SdJwtVcVerificationResult withoutMetadata = await SdJwtVcVerifier.VerifyAsync(
    issued.Issuance, resolveIssuer, typeMetadataResolver: empty, cryptoProvider: joseCrypto);
Console.WriteLine($"  unknown vct -> metadata null, credential still valid: {withoutMetadata is { IsValid: true, TypeMetadata: null }}");
Check(withoutMetadata.IsValid && withoutMetadata.TypeMetadata is null, "an unresolvable vct yields null metadata, never a network call");
Check((await seeded.ResolveAsync(vct))?["vct"]!.GetValue<string>() == vct, "ITypeMetadataResolver.ResolveAsync returns the cached document");

Console.WriteLine();
Console.WriteLine("Done! SD-JWT VC example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
