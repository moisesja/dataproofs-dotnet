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
// FR-17 (draft-ietf-oauth-sd-jwt-vc-27): the SD-JWT VC profile layered on generic SD-JWT.
// On top of the disclosure mechanics it adds, end to end:
//   * a required `vct` (verifiable credential type) claim — rejected if missing/blank,
//   * an optional `aka_vcts` claim naming further types — a non-empty array without the vct value,
//   * the `dc+sd-jwt` media type, and only that: the former `vc+sd-jwt` is rejected,
//   * registered claims that MUST NOT be selectively disclosed (iss/nbf/exp/cnf/vct/aka_vcts/...),
//     nor anything inside them, while a nested claim that only shares the name is ordinary,
//   * offline-by-default Type Metadata (`vct`) resolution via a pluggable resolver hook —
//     LocalCacheTypeMetadataResolver here, never the network (FR-10 posture),
//   * Type Metadata processing on request (draft -27 §5.7, issue #47): integrity, the extends chain,
//     merged claim metadata the credential must satisfy, typed display metadata for a wallet,
//   * the validity window: nbf and exp judged at CurrentTime with ClockSkew (issue #45).
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
Console.WriteLine($"  media type: {SdJwtVcConstants.MediaType}");
Console.WriteLine($"  vct claim: '{SdJwtVcConstants.VctClaim}', other types: '{SdJwtVcConstants.AkaVctsClaim}', integrity: '{SdJwtVcConstants.VctIntegrityClaim}', status: '{SdJwtVcConstants.StatusClaim}'");
Console.WriteLine($"  must-not-be-disclosed: {string.Join(", ", SdJwtVcConstants.MustNotBeSelectivelyDisclosed)}");
Check(SdJwtVcConstants.MediaType == "dc+sd-jwt", "the SD-JWT VC media type is dc+sd-jwt");
Check(SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains("vct"), "vct is in the must-not-disclose set");
Check(SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains(SdJwtVcConstants.AkaVctsClaim), "aka_vcts is in the must-not-disclose set");
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

// The former vc+sd-jwt typ is rejected: draft -19 removed its transitional acceptance, and W3C
// VC-JOSE-COSE uses vc+sd-jwt for a different format. The constant stays, marked [Obsolete].
#pragma warning disable CS0618 // TransitionalMediaType is obsolete; this shows that the verifier refuses it.
string formerTyp = SdJwtVcConstants.TransitionalMediaType;
#pragma warning restore CS0618
SdJwtIssuer.Result former = await SdJwtIssuer.IssueAsync(VcClaims(), frame, issuerSigner, typ: formerTyp);
SdJwtVcVerificationResult formerResult = await SdJwtVcVerifier.VerifyAsync(former.Issuance, resolveIssuer, cryptoProvider: joseCrypto);
Console.WriteLine($"  former {formerTyp} typ rejected: {!formerResult.IsValid} ({formerResult.Errors.FirstOrDefault()})");
Check(!formerResult.IsValid, "the former vc+sd-jwt media type is rejected");

// aka_vcts: further types the credential also has, signed in the clear like vct.
JsonObject withAka = VcClaims();
withAka[SdJwtVcConstants.AkaVctsClaim] = new JsonArray("https://credentials.example.com/general_credential");
SdJwtIssuer.Result akaIssued = await SdJwtVcIssuer.IssueAsync(withAka, frame, issuerSigner);
SdJwtVcVerificationResult akaResult = await SdJwtVcVerifier.VerifyAsync(akaIssued.Issuance, resolveIssuer, cryptoProvider: joseCrypto);
Console.WriteLine($"  aka_vcts in the clear verifies: {akaResult.IsValid}");
Check(akaResult.IsValid && akaResult.DisclosedPayload!.ContainsKey(SdJwtVcConstants.AkaVctsClaim), "a well-formed aka_vcts verifies");

bool akaDisclosureRejected;
try
{
    await SdJwtVcIssuer.IssueAsync(withAka, new DisclosureFrame().Disclose(SdJwtVcConstants.AkaVctsClaim), issuerSigner);
    akaDisclosureRejected = false;
}
catch (MalformedJoseException)
{
    akaDisclosureRejected = true;
}
Console.WriteLine($"  making aka_vcts disclosable rejected: {akaDisclosureRejected}");
Check(akaDisclosureRejected, "aka_vcts cannot be made selectively disclosable");

// The rule is positional (issue #48): it covers the registered top-level claims and everything inside
// them, so a member of status cannot be disclosed either, while a nested claim that only shares a
// registered name, such as credentialSubject.status, is an ordinary claim.
JsonObject withStatus = VcClaims();
withStatus[SdJwtVcConstants.StatusClaim] = new JsonObject
{
    ["status_list"] = new JsonObject { ["idx"] = 412, ["uri"] = "https://example.com/statuslists/1" },
};
withStatus["credentialSubject"] = new JsonObject { ["status"] = "active" };

bool statusMemberRejected;
try
{
    await SdJwtVcIssuer.IssueAsync(
        withStatus, new DisclosureFrame().DiscloseObjectProperties(SdJwtVcConstants.StatusClaim, "status_list"), issuerSigner);
    statusMemberRejected = false;
}
catch (MalformedJoseException)
{
    statusMemberRejected = true;
}
Console.WriteLine($"  making a member of status disclosable rejected: {statusMemberRejected}");
Check(statusMemberRejected, "a subclaim of a registered claim cannot be made selectively disclosable");

SdJwtIssuer.Result nestedIssued = await SdJwtVcIssuer.IssueAsync(
    withStatus, new DisclosureFrame().DiscloseObjectProperties("credentialSubject", "status"), issuerSigner);
SdJwtVcVerificationResult nestedResult = await SdJwtVcVerifier.VerifyAsync(nestedIssued.Issuance, resolveIssuer, cryptoProvider: joseCrypto);
Console.WriteLine($"  credentialSubject.status disclosed and verified: {nestedResult.IsValid}");
Check(nestedResult.IsValid && nestedResult.DisclosedPayload!["credentialSubject"]!["status"]!.GetValue<string>() == "active",
    "a nested claim named like a registered claim is selectively disclosable");
Console.WriteLine();

// ----------------------------------------------------------- 2b. Validity window (nbf / exp)
// draft -27 §2.2.2.3: the credential "MUST NOT be accepted" before nbf and "is no longer valid" after
// exp. Every SdJwtVcVerifier method judges both, in the clear at the top level as the issuer signed
// them, at CurrentTime with ClockSkew; a nested credentialSubject.exp is an ordinary claim.
Console.WriteLine("--- validity window (nbf / exp) ---");
var validFrom = new DateTimeOffset(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);
JsonObject windowed = VcClaims();
windowed["nbf"] = validFrom.ToUnixTimeSeconds();
windowed["exp"] = validFrom.AddYears(1).ToUnixTimeSeconds();
SdJwtIssuer.Result windowIssued = await SdJwtVcIssuer.IssueAsync(windowed, frame, issuerSigner);

async Task<SdJwtVcVerificationResult> VerifyAt(DateTimeOffset now) => await SdJwtVcVerifier.VerifyAsync(
    windowIssued.Issuance, resolveIssuer, new SdJwtVerificationOptions { CurrentTime = now, ClockSkew = TimeSpan.FromMinutes(1) },
    cryptoProvider: joseCrypto);

SdJwtVcVerificationResult current = await VerifyAt(validFrom.AddMonths(6));
SdJwtVcVerificationResult early = await VerifyAt(validFrom.AddMinutes(-2));
SdJwtVcVerificationResult withinSkew = await VerifyAt(validFrom.AddSeconds(-30));
SdJwtVcVerificationResult lapsed = await VerifyAt(validFrom.AddYears(1));
Console.WriteLine($"  mid-term: valid={current.IsValid}; 2 min early: {early.Errors[0].Split(':')[0]}; 30 s early: valid={withinSkew.IsValid}; "
    + $"at exp: valid={lapsed.IsValid} (inside the 1 min skew)");
Check(current.IsValid, "a credential inside its window verifies");
Check(!early.IsValid && early.Errors[0].StartsWith("SD_JWT_NOT_YET_VALID"), "before nbf - skew it is SD_JWT_NOT_YET_VALID");
Check(withinSkew.IsValid && lapsed.IsValid, "the clock skew widens the window on both sides");
SdJwtVcVerificationResult expired = await VerifyAt(validFrom.AddYears(1).AddMinutes(1));
Check(!expired.IsValid && expired.Errors[0].StartsWith("SD_JWT_EXPIRED"), "from exp + skew on it is SD_JWT_EXPIRED");

// A credentialSubject.exp in the past is an ordinary claim, not the credential's expiry.
JsonObject nestedExp = VcClaims();
nestedExp["credentialSubject"] = new JsonObject { ["exp"] = 1000000000 };
SdJwtIssuer.Result nestedExpIssued = await SdJwtVcIssuer.IssueAsync(nestedExp, frame, issuerSigner);
Check((await SdJwtVcVerifier.VerifyAsync(nestedExpIssued.Issuance, resolveIssuer, cryptoProvider: joseCrypto)).IsValid,
    "a nested exp is not the credential's expiry");
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

// ----------------------------------------------------------- 4. Type Metadata processing (§5.7, opt-in)
Console.WriteLine("--- Type Metadata processing (integrity, extends, claim and display metadata) ---");

// A parent type and the vct's type, as their publishers serve them. Integrity is over these exact octets (§6).
const string parentVct = "https://credentials.example.com/base_identity";
byte[] parentDocument = System.Text.Encoding.UTF8.GetBytes(new JsonObject
{
    ["vct"] = parentVct,
    ["claims"] = new JsonArray(
        new JsonObject { ["path"] = new JsonArray("given_name"), ["sd"] = "always", ["mandatory"] = true },
        new JsonObject { ["path"] = new JsonArray("address", "country"), ["sd"] = "never" }),
}.ToJsonString());
byte[] typeDocument = System.Text.Encoding.UTF8.GetBytes(new JsonObject
{
    ["vct"] = vct,
    ["name"] = "Identity Credential",
    ["description"] = "An example identity credential type.",
    ["extends"] = parentVct,
    ["extends#integrity"] = TypeMetadataIntegrity.Compute(parentDocument, TypeMetadataIntegrity.Sha384),
    ["display"] = new JsonArray(new JsonObject
    {
        ["locale"] = "en-US",
        ["name"] = "Identity",
        ["description"] = "Who you are",
        ["dir"] = "ltr",
        ["rendering"] = new JsonObject
        {
            ["simple"] = new JsonObject
            {
                ["logo"] = new JsonObject { ["uri"] = "https://credentials.example.com/logo.png", ["uri#integrity"] = "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=", ["alt_text"] = "Logo" },
                ["background_image"] = new JsonObject { ["uri"] = "https://credentials.example.com/background.png" },
                ["background_color"] = "#12107c",
                ["text_color"] = "#FFFFFF",
            },
            ["svg_templates"] = new JsonArray(new JsonObject
            {
                ["uri"] = "https://credentials.example.com/card.svg",
                ["properties"] = new JsonObject { ["orientation"] = "landscape", ["color_scheme"] = "light", ["contrast"] = "normal" },
            }),
        },
    }),
    ["claims"] = new JsonArray(
        new JsonObject
        {
            ["path"] = new JsonArray("given_name"),
            ["display"] = new JsonArray(new JsonObject { ["locale"] = "en-US", ["label"] = "Given name", ["description"] = "First name", ["dir"] = "auto" }),
            ["svg_id"] = "given_name",
        },
        new JsonObject { ["path"] = new JsonArray("nationalities", null), ["sd"] = "allowed" },
        new JsonObject { ["path"] = new JsonArray("nationalities", 0) }),
}.ToJsonString());

// The documents come from the consumer's resolver: an offline local cache of octets here, never the network.
ITypeMetadataDocumentResolver documents = new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]>
{
    [vct] = typeDocument,
    [parentVct] = parentDocument,
});
Check((await documents.ResolveDocumentAsync(parentVct))!.SequenceEqual(parentDocument), "ITypeMetadataDocumentResolver.ResolveDocumentAsync returns the octets");
var processing = new TypeMetadataProcessingOptions(documents)
{
    MaxExtendsDepth = TypeMetadataProcessingOptions.DefaultMaxExtendsDepth,
    MaxDocumentSize = TypeMetadataProcessingOptions.DefaultMaxDocumentSize,
};
Console.WriteLine($"  resolver set: {processing.Resolver is not null}, max extends hops: {processing.MaxExtendsDepth}, max document: {processing.MaxDocumentSize} octets");

// The issuer binds the credential to the exact type document with vct#integrity, and checks issuance against the
// metadata: given_name must be selectively disclosable, address.country must stay in the clear.
JsonObject typedClaims = VcClaims();
typedClaims[SdJwtVcConstants.VctIntegrityClaim] = TypeMetadataIntegrity.Compute(typeDocument);
typedClaims["nationalities"] = new JsonArray("US", "DE");
var typedFrame = new DisclosureFrame().Disclose("given_name").DiscloseArrayElements("nationalities", 1);
SdJwtIssuer.Result typedIssued = await SdJwtVcIssuer.IssueWithTypeMetadataAsync(typedClaims, typedFrame, issuerSigner, processing);

string typedPresentation = SdJwtHolder.CreatePresentation(typedIssued.Issuance, []); // present nothing selectively disclosable
SdJwtVcVerificationResult processed = await SdJwtVcVerifier.VerifyWithTypeMetadataAsync(
    typedPresentation, resolveIssuer, processing, cryptoProvider: joseCrypto);
Console.WriteLine($"  processed: valid={processed.IsValid}, fault={processed.TypeMetadataResolverFault is not null}");
Check(processed.IsValid, "a withheld mandatory claim is not a missing one (§5.6)");
Check(processed.TypeMetadataResolverFault is null, "no resolver fault");

ProcessedTypeMetadata metadata = processed.ProcessedTypeMetadata!;
Console.WriteLine($"  type {metadata.Vct}: {metadata.Name} ({metadata.Description}), {metadata.Documents.Count} documents in the chain");
Check(metadata.Documents.Count == 2 && processed.TypeMetadata!["extends"]!.GetValue<string>() == parentVct, "the extends chain was processed");

TypeDisplayMetadata display = metadata.Display[0];
Console.WriteLine($"  display [{display.Locale}, {display.Dir}]: {display.Name} - {display.Description}");
TypeRenderingMetadata rendering = display.Rendering!;
SimpleRenderingMetadata simple = rendering.Simple!;
RenderingImageMetadata logo = simple.Logo!;
Console.WriteLine($"  simple: logo {logo.Uri} ({logo.AltText}, integrity {logo.UriIntegrity is not null}), background {simple.BackgroundImage!.Uri} {simple.BackgroundColor}/{simple.TextColor}");
SvgTemplateMetadata template = rendering.SvgTemplates[0];
Console.WriteLine($"  svg: {template.Uri} {template.Orientation}/{template.ColorScheme}/{template.Contrast}, integrity {template.UriIntegrity ?? "(none)"}");
// A wallet that fetches the logo checks its bytes before use; the library never fetches it.
Check(!TypeMetadataIntegrity.Matches(logo.UriIntegrity!, "not the logo"u8), "a rendering resource is checked against uri#integrity by the wallet");

foreach (ClaimMetadata claim in metadata.Claims)
{
    string path = string.Join(".", claim.Path.Select((ClaimPathComponent c) => c.Key ?? (c.IsAllElements ? "*" : c.Index!.Value.ToString())));
    ClaimDisplayMetadata? claimDisplay = claim.Display.FirstOrDefault();
    string label = claimDisplay is { } d ? $"'{d.Label}' [{d.Locale}, {d.Dir}] {d.Description}" : "(no display)";
    Console.WriteLine($"  claim {path}: mandatory={claim.Mandatory}, sd={claim.SelectiveDisclosure}, svg_id={claim.SvgId ?? "-"}, {label}");
}
ClaimMetadata givenName = metadata.Claims.Single(c => c.Path[0].Key == "given_name");
Check(givenName is { Mandatory: true, SelectiveDisclosure: ClaimSelectiveDisclosure.Always, SvgId: "given_name" },
    "the child's display and svg_id are combined with the parent's mandatory and sd (§5.6.5)");
Check(metadata.Claims.Any(c => c.SelectiveDisclosure == ClaimSelectiveDisclosure.Never)
    && metadata.Claims.Any(c => c.SelectiveDisclosure == ClaimSelectiveDisclosure.Allowed)
    && metadata.Claims.Any(c => c.Path.Count == 2 && c.Path[1].Index == 0), "every sd value and path component kind is present");

// A credential that contradicts the metadata is refused at issuance and at verification, with a stable code.
bool contradicted;
try
{
    await SdJwtVcIssuer.IssueWithTypeMetadataAsync(typedClaims, new DisclosureFrame(), issuerSigner, processing);
    contradicted = false;
}
catch (MalformedJoseException ex) when (ex.Message.StartsWith("VC_CLAIM_SD_VIOLATION", StringComparison.Ordinal))
{
    contradicted = true;
}
Check(contradicted, "issuing given_name in the clear is refused (sd: always)");
SdJwtIssuer.Result clear = await SdJwtVcIssuer.IssueAsync(typedClaims, new DisclosureFrame(), issuerSigner);
SdJwtVcVerificationResult refused = await SdJwtVcVerifier.VerifyWithTypeMetadataAsync(clear.Issuance, resolveIssuer, processing, cryptoProvider: joseCrypto);
Console.WriteLine($"  given_name in the clear: {refused.Errors.FirstOrDefault()}");
Check(!refused.IsValid && refused.TypeMetadataResolverFault is null, "a contradiction is a verdict");

// A resolver that fails is a fault, told apart from a verdict.
SdJwtVcVerificationResult faulted = await SdJwtVcVerifier.VerifyWithTypeMetadataAsync(
    typedPresentation, resolveIssuer, new TypeMetadataProcessingOptions(new UnreachableResolver()), cryptoProvider: joseCrypto);
Console.WriteLine($"  resolver fault: {faulted.TypeMetadataResolverFault?.GetType().Name} ({faulted.Errors.FirstOrDefault()})");
Check(!faulted.IsValid && faulted.TypeMetadataResolverFault is HttpRequestException, "a resolver fault is not a verdict");
Check(processed.ProcessedTypeMetadata is not null && withMetadata.ProcessedTypeMetadata is null, "VerifyAsync does not process");
Check(TypeMetadataIntegrity.Compute(typeDocument, TypeMetadataIntegrity.Sha512).StartsWith(TypeMetadataIntegrity.Sha512 + "-", StringComparison.Ordinal),
    "integrity strings name their algorithm");

Console.WriteLine();
Console.WriteLine("Done! SD-JWT VC example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}

/// <summary>A resolver whose network is down: the verifier reports a fault, not a verdict.</summary>
sealed class UnreachableResolver : ITypeMetadataDocumentResolver
{
    public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
        => throw new HttpRequestException("Type Metadata host unreachable");
}
