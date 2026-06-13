using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — SD-JWT (selective disclosure)
// ============================================================
// FR-16 (RFC 9901): the issuer signs a credential where chosen claims are replaced by salted
// hash digests (with optional DECOY digests to hide how many claims exist); the holder later
// presents only the disclosures they choose; the verifier reconstructs exactly the disclosed
// payload. A Key Binding JWT (KB-JWT) lets the holder prove possession of a confirmation key,
// binding the presentation to an audience + nonce with an sd_hash over the presented bytes.
//
// The DisclosureFrame describes WHICH claims are selectively disclosable, in four styles:
// flat (Disclose), structured (DiscloseObjectProperties), recursive (DiscloseRecursively /
// nested frames), and array-element (DiscloseArrayElements).
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();

KeyPair issuerPair = keyGen.Generate(KeyType.Ed25519);
var issuerSigner = new JwsSigner(new KeyPairSigner(issuerPair, crypto), "did:example:issuer#sd");
Jwk issuerPublicJwk = JwkConversion.ToPublicJwk(issuerPair.KeyType, issuerPair.PublicKey, "did:example:issuer#sd");
Func<string, Jwk?> resolveIssuer = _ => issuerPublicJwk;

JsonObject Claims() => new()
{
    ["iss"] = "https://issuer.example",
    ["sub"] = "user-42",
    ["given_name"] = "John",
    ["family_name"] = "Doe",
    ["email"] = "john@example.com",
    ["address"] = new JsonObject
    {
        ["street_address"] = "123 Main St",
        ["locality"] = "Anytown",
        ["country"] = "US",
    },
    ["nationalities"] = new JsonArray("US", "DE", "FR"),
};

Console.WriteLine("=== SD-JWT — issuance, presentation, key binding ===");

// ----------------------------------------------------------- 1. Flat disclosure + decoys
Console.WriteLine("--- flat disclosure with decoy digests ---");
var flatFrame = new DisclosureFrame().Disclose("given_name").Disclose("family_name").Disclose("email");
var issuerOptions = new SdJwtIssuerOptions
{
    HashAlgorithm = SdHashAlgorithm.Sha256,
    DecoyDigestCount = 4,
};
SdJwtIssuer.Result issued = await SdJwtIssuer.IssueAsync(Claims(), flatFrame, issuerSigner, issuerOptions, typ: "example+sd-jwt");
Console.WriteLine($"  issued with {issued.Disclosures.Count} disclosures (+4 decoys hide the real count)");
Check(issued.Disclosures.Count == 3, "three claims were made disclosable");
Check(issued.IssuerJwt.Split('.').Length == 3, "the issuer JWT is a compact JWS");
Check(issued.Issuance.EndsWith('~'), "the issuance form ends with a tilde");

// Full issuance reveals all three.
SdJwtVerificationResult full = SdJwtVerifier.Verify(issued.Issuance, resolveIssuer, cryptoProvider: joseCrypto);
Check(full.IsValid, "the full issuance verifies");
Check(full.DisclosedPayload!.ContainsKey("given_name") && full.DisclosedPayload.ContainsKey("email"), "all disclosed claims reconstruct");
Console.WriteLine($"  full issuance valid={full.IsValid}, alg={full.SignatureAlgorithm}");

// Holder withholds email, presents only given_name + family_name.
var keep = issued.Disclosures.Where(d => d.ClaimName is "given_name" or "family_name").Select(d => d.Encoded);
string presentation = SdJwtHolder.CreatePresentation(issued.Issuance, keep);
SdJwtVerificationResult partial = SdJwtVerifier.Verify(presentation, resolveIssuer, cryptoProvider: joseCrypto);
Console.WriteLine($"  holder presents given_name+family_name; email withheld: {!partial.DisclosedPayload!.ContainsKey("email")}");
Check(partial.IsValid, "the partial presentation verifies");
Check(partial.DisclosedPayload!.ContainsKey("given_name"), "presented claim is reconstructed");
Check(!partial.DisclosedPayload.ContainsKey("email"), "withheld claim is absent");

// Inspect a Disclosure's structure (claim name/value/digest, encoded/parse round-trip).
Disclosure given = issued.Disclosures.Single(d => d.ClaimName == "given_name");
Console.WriteLine($"  disclosure: name={given.ClaimName}, value={given.ClaimValue}, isArrayElement={given.IsArrayElement}");
Check(given.ClaimName == "given_name" && given.ClaimValue!.GetValue<string>() == "John", "a Disclosure exposes its claim name + value");
Check(!given.IsArrayElement, "an object-property Disclosure is not an array element");
Disclosure reparsed = Disclosure.Parse(given.Encoded);
Check(reparsed.ClaimName == given.ClaimName, "Disclosure.Parse round-trips the encoded form");
Check(given.ComputeDigest(SdHashAlgorithm.Sha256) != given.ComputeDigest(SdHashAlgorithm.Sha512), "the digest depends on the sd_alg");
Console.WriteLine();

// ----------------------------------------------------------- 2. Structured, recursive, array, nested
Console.WriteLine("--- structured / recursive / array-element / nested-object frames ---");

// Structured: object stays in clear, each sub-claim individually disclosable.
var structured = new DisclosureFrame().DiscloseObjectProperties("address", "street_address", "locality", "country");
SdJwtIssuer.Result structuredIssued = await SdJwtIssuer.IssueAsync(Claims(), structured, issuerSigner);
Check(structuredIssued.Disclosures.Count == 3, "structured frame yields one Disclosure per sub-claim");

// Recursive: the wrapping object AND its sub-claims are disclosable.
var recursive = new DisclosureFrame().DiscloseRecursively("address", "street_address", "locality", "country");
SdJwtIssuer.Result recursiveIssued = await SdJwtIssuer.IssueAsync(Claims(), recursive, issuerSigner);
Check(recursiveIssued.Disclosures.Count == 4, "recursive frame adds a wrapping Disclosure (3 sub + 1 wrapper)");

// Nested object frame: compose a frame for a nested object explicitly.
var nestedFrame = new DisclosureFrame().DiscloseObject("address", new DisclosureFrame().Disclose("locality"));
SdJwtIssuer.Result nestedIssued = await SdJwtIssuer.IssueAsync(Claims(), nestedFrame, issuerSigner);
Check(nestedIssued.Disclosures.Any(d => d.ClaimName == "locality"), "DiscloseObject applies a nested frame");
SdJwtVerificationResult nestedVerified = SdJwtVerifier.Verify(nestedIssued.Issuance, resolveIssuer, cryptoProvider: joseCrypto);
Check(nestedVerified.IsValid, "the nested-object issuance verifies");

// Recursive nested-object frame.
var recursiveObject = new DisclosureFrame().DiscloseRecursiveObject("address", new DisclosureFrame().Disclose("country"));
SdJwtIssuer.Result recursiveObjectIssued = await SdJwtIssuer.IssueAsync(Claims(), recursiveObject, issuerSigner);
Check(SdJwtVerifier.Verify(recursiveObjectIssued.Issuance, resolveIssuer, cryptoProvider: joseCrypto).IsValid, "the recursive-object issuance verifies");

// Array elements: make nationalities[0] and [2] disclosable.
var arrayFrame = new DisclosureFrame().DiscloseArrayElements("nationalities", 0, 2);
SdJwtIssuer.Result arrayIssued = await SdJwtIssuer.IssueAsync(Claims(), arrayFrame, issuerSigner);
Check(arrayIssued.Disclosures.All(d => d.IsArrayElement), "array-element frame yields array-element Disclosures");
// Reveal only the US element.
var us = arrayIssued.Disclosures.Single(d => d.ClaimValue!.GetValue<string>() == "US").Encoded;
SdJwtVerificationResult arrayResult = SdJwtVerifier.Verify(
    SdJwtHolder.CreatePresentation(arrayIssued.Issuance, [us]), resolveIssuer, cryptoProvider: joseCrypto);
var nats = arrayResult.DisclosedPayload!["nationalities"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
Console.WriteLine($"  nationalities after revealing only US: [{string.Join(", ", nats)}] (DE was always clear)");
Check(nats.Contains("US") && nats.Contains("DE") && !nats.Contains("FR"), "only the selected array element is revealed");

// Build a Disclosure object directly (the primitives the issuer composes internally).
Disclosure obj = Disclosure.ForObjectProperty("salt12345", "nickname", "Johnny");
Disclosure arr = Disclosure.ForArrayElement("salt67890", JsonValue.Create("ES"));
Check(obj.ClaimName == "nickname" && !obj.IsArrayElement, "Disclosure.ForObjectProperty builds an object-property disclosure");
Check(arr.IsArrayElement && arr.ClaimName is null, "Disclosure.ForArrayElement builds an array-element disclosure");
Console.WriteLine();

// ----------------------------------------------------------- 3. Key Binding JWT
Console.WriteLine("--- Key Binding JWT (holder proof of possession) ---");
KeyPair holderPair = keyGen.Generate(KeyType.P256);
var holderSigner = new JwsSigner(new KeyPairSigner(holderPair, crypto), "did:example:holder#kb");
Jwk holderConfirmationKey = JwkConversion.ToPublicJwk(holderPair.KeyType, holderPair.PublicKey, "did:example:holder#kb");

var kbOptions = new SdJwtIssuerOptions { HolderConfirmationKey = holderConfirmationKey };
SdJwtIssuer.Result kbIssued = await SdJwtIssuer.IssueAsync(Claims(), flatFrame, issuerSigner, kbOptions);

const string audience = "https://verifier.example.org";
const string nonce = "n-sd-jwt-2026";
string kbPresentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
    kbIssued.Issuance, kbIssued.Disclosures.Select(d => d.Encoded), holderSigner, audience, nonce);

var verifyOptions = new SdJwtVerificationOptions
{
    RequireKeyBinding = true,
    ExpectedAudience = audience,
    ExpectedNonce = nonce,
    MaxKeyBindingAge = TimeSpan.FromMinutes(5),
    ClockSkew = TimeSpan.FromSeconds(30),
};
SdJwtVerificationResult kbResult = SdJwtVerifier.Verify(kbPresentation, resolveIssuer, verifyOptions, joseCrypto);
Console.WriteLine($"  KB presentation valid={kbResult.IsValid}, keyBindingVerified={kbResult.KeyBindingVerified}");
Check(kbResult.IsValid && kbResult.KeyBindingVerified, "the KB-JWT presentation verifies with audience + nonce");

// The components of a presentation can be parsed apart; the KB-JWT's sd_hash matches the
// recomputed hash over the presented SD-JWT bytes.
SdJwtComponents components = SdJwtComponents.Parse(kbPresentation);
Console.WriteLine($"  components: {components.Disclosures.Count} disclosures, hasKeyBinding={components.HasKeyBinding}");
Check(components.HasKeyBinding && components.KeyBindingJwt is not null, "the parsed components expose the KB-JWT");
Check(components.IssuerJwt == kbIssued.IssuerJwt, "the parsed issuer JWT matches the issued one");
string recomputed = SdHashAlgorithm.ComputeSdHash(SdHashAlgorithm.Sha256, components.SdJwtWithoutKeyBinding);
string kbBody = Base64Url.DecodeUtf8(components.KeyBindingJwt!.Split('.')[1]);
Check(kbBody.Contains(recomputed), "the KB-JWT sd_hash equals the recomputed hash over the presentation");
Check(SdHashAlgorithm.IsSupported(SdHashAlgorithm.Sha256) && !SdHashAlgorithm.IsSupported("md5"), "SdHashAlgorithm.IsSupported gates the digest algorithms");

// A KB-JWT can also be issued standalone (advanced flows compose it separately).
string standaloneKb = await KeyBindingJwt.IssueAsync(
    components.SdJwtWithoutKeyBinding, SdHashAlgorithm.Sha256, "another-nonce", audience, DateTimeOffset.UtcNow, holderSigner);
using (var kbHeader = System.Text.Json.JsonDocument.Parse(Base64Url.Decode(standaloneKb.Split('.')[0])))
{
    Check(kbHeader.RootElement.GetProperty("typ").GetString() == KeyBindingJwt.Type, "a standalone KB-JWT uses the kb+jwt typ");
}

// Verifying WITHOUT key binding when it is required fails (a structured result, not an exception).
SdJwtVerificationResult missingKb = SdJwtVerifier.Verify(kbIssued.Issuance, resolveIssuer, verifyOptions, joseCrypto);
Console.WriteLine($"  requiring KB but presenting none -> valid={missingKb.IsValid}, errors={missingKb.Errors.Count}");
Check(!missingKb.IsValid && missingKb.Errors.Count > 0, "a required-but-absent KB-JWT fails with errors, not an exception");

Console.WriteLine();
Console.WriteLine("Done! SD-JWT example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
