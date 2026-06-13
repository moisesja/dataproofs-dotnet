using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// AC-3 step 7 (SD-JWT parts) — negative-path theories per RFC 9901 §10 security considerations:
/// rejected <c>none</c>/unexpected <c>alg</c>, tampered Disclosure, digest mismatch, KB-JWT
/// <c>sd_hash</c> mismatch, and expired/replayed nonce. Each returns the documented failure (a
/// structured <see cref="SdJwtVerificationResult"/> with <c>IsValid=false</c>, or a typed
/// <see cref="MalformedJoseException"/> for inputs so malformed no result can be produced) —
/// never an unhandled exception.
/// </summary>
public sealed class SdJwtNegativePathTests
{
    private static readonly Jwk _issuerKey = SdJwtFixtureSupport.Rfc9901IssuerKey();
    private static Func<string, Jwk?> Resolver => SdJwtFixtureSupport.SingleKeyResolver(_issuerKey);

    private static JsonObject SampleClaims() => new()
    {
        ["iss"] = "https://issuer.example.com",
        ["given_name"] = "John",
        ["family_name"] = "Doe",
    };

    private static async Task<(TestKeyMaterial issuer, SdJwtIssuer.Result issued)> IssueSampleAsync(
        SdJwtIssuerOptions? options = null)
    {
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");
        var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name");
        var issued = await SdJwtIssuer.IssueAsync(SampleClaims(), frame, issuer.Signer, options);
        return (issuer, issued);
    }

    // ---- alg=none / unexpected alg ----

    [Fact]
    public void Issuer_jwt_with_alg_none_is_a_structured_failure_not_a_throw()
    {
        // A forged issuer JWT with alg=none, plus a trailing '~'. CompactJwt.Decode rejects "none";
        // the verifier surfaces it as MALFORMED, never an unhandled exception.
        var header = Base64Url.EncodeUtf8("""{"alg":"none","typ":"example+sd-jwt"}""");
        var payload = Base64Url.EncodeUtf8("""{"_sd":[],"_sd_alg":"sha-256"}""");
        var forged = $"{header}.{payload}.{Base64Url.Encode([0])}~";

        SdJwtVerificationResult? result = null;
        Action act = () => result = SdJwtVerifier.Verify(forged, Resolver);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED");
    }

    [Fact]
    public async Task Issuer_signature_under_a_mismatched_key_curve_fails()
    {
        // Algorithm-confusion: the issuer signed with Ed25519 but the resolver returns a P-256 key.
        // The alg↔curve binding must fail verification (CompactJwt.Verify returns false), surfaced
        // as ISSUER_SIGNATURE_INVALID — never an unhandled throw.
        var (_, issued) = await IssueSampleAsync();
        var wrongKey = TestKeyMaterial.Generate(KeyType.P256, "issuer").PublicJwk;

        var result = SdJwtVerifier.Verify(issued.Issuance, _ => wrongKey);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("ISSUER_SIGNATURE_INVALID");
    }

    [Fact]
    public async Task Unknown_issuer_kid_is_a_structured_failure()
    {
        var (_, issued) = await IssueSampleAsync();

        var result = SdJwtVerifier.Verify(issued.Issuance, _ => null); // resolver knows no key

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("ISSUER_KEY_UNRESOLVED");
    }

    [Fact]
    public void Unsupported_sd_alg_is_rejected_closing_the_hash_downgrade_vector()
    {
        // RFC 9901 §10: an _sd_alg outside the supported SHA-2 set must be rejected up front.
        var header = Base64Url.EncodeUtf8("""{"alg":"ES256","typ":"example+sd-jwt"}""");
        var payload = Base64Url.EncodeUtf8("""{"_sd":[],"_sd_alg":"md5"}""");
        var forged = $"{header}.{payload}.{Base64Url.Encode([0])}~";

        var result = SdJwtVerifier.Verify(forged, Resolver);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED");
        string.Join(" ", result.Errors).Should().Contain("_sd_alg");
    }

    // ---- tampered Disclosure / digest mismatch ----

    [Fact]
    public async Task Tampered_disclosure_value_no_longer_matches_its_digest_and_is_dropped()
    {
        // Flip a byte in a presented Disclosure: its recomputed digest no longer matches any _sd
        // entry, so it is unreferenced — reconstruction rejects the leftover Disclosure
        // (RFC 9901 §7.1 unused-Disclosure rule). DISCLOSURE_INVALID, never an unhandled throw.
        var (issuer, issued) = await IssueSampleAsync();
        var parts = issued.Issuance.Split('~');
        // parts[0]=issuer jwt, parts[1..n]=disclosures, parts[last]=empty (trailing ~).
        var original = parts[1];
        var bytes = Base64Url.Decode(original);
        bytes[^1] ^= 0x01; // corrupt the last byte of the disclosure's decoded JSON
        // Re-encode as a *valid* but different Disclosure (still a 2/3-element array? maybe not) —
        // instead, mutate the base64url string itself to a still-decodable variant.
        var tamperedDisclosure = Base64Url.Encode(bytes);
        parts[1] = tamperedDisclosure;
        var tampered = string.Join('~', parts);

        SdJwtVerificationResult? result = null;
        Action act = () => result = SdJwtVerifier.Verify(tampered, _ => issuer.PublicJwk);

        act.Should().NotThrow("a tampered Disclosure must be a documented failure, never an unhandled exception");
        result!.IsValid.Should().BeFalse();
        // Either the Disclosure no longer parses (MALFORMED) or it parses but is unreferenced
        // (DISCLOSURE_INVALID) — both are documented failures.
        result.Errors.Should().ContainSingle().Which.Should().Match(e =>
            e.StartsWith("DISCLOSURE_INVALID") || e.StartsWith("MALFORMED"));
    }

    [Fact]
    public async Task Injecting_a_disclosure_with_no_matching_digest_is_rejected()
    {
        // Disclosure-injection defense (RFC 9901 §7.1): append a well-formed Disclosure whose
        // digest is not referenced by any _sd/'...' placeholder in the payload.
        var (issuer, issued) = await IssueSampleAsync();
        var rogue = Disclosure.ForObjectProperty("AAAAAAAAAAAAAAAAAAAAAA", "is_admin", JsonValue.Create(true));

        var parts = issued.Issuance.Split('~').ToList();
        // Insert the rogue Disclosure just before the trailing empty element.
        parts.Insert(parts.Count - 1, rogue.Encoded);
        var injected = string.Join('~', parts);

        var result = SdJwtVerifier.Verify(injected, _ => issuer.PublicJwk);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID");
    }

    [Fact]
    public async Task A_disclosure_colliding_with_a_clear_claim_is_rejected()
    {
        // RFC 9901 §7.1: a disclosed claim name must not overwrite a claim already present in the
        // object. Construct a payload where 'iss' is clear AND a Disclosure for 'iss' is referenced.
        // We do this by issuing a generic SD-JWT whose payload keeps iss clear but whose _sd carries
        // a digest of an iss Disclosure we present.
        var issuer = TestKeyMaterial.Generate(KeyType.Ed25519, "issuer");

        var issDisclosure = Disclosure.ForObjectProperty("BBBBBBBBBBBBBBBBBBBBBB", "iss", JsonValue.Create("evil"));
        var digest = issDisclosure.ComputeDigest(SdHashAlgorithm.Sha256);

        var payload = new JsonObject
        {
            ["iss"] = "https://issuer.example.com", // clear claim
            ["_sd"] = new JsonArray(digest),         // and a disclosable iss digest
            ["_sd_alg"] = "sha-256",
        };
        var payloadBytes = Encoding.UTF8.GetBytes(payload.ToJsonString());
        var issuerJwt = await JwsBuilder.BuildCompactAsync(payloadBytes, issuer.Signer, typ: "example+sd-jwt");
        var presentation = $"{issuerJwt}~{issDisclosure.Encoded}~";

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID");
    }

    // ---- KB-JWT sd_hash mismatch / replay / freshness ----

    [Fact]
    public async Task Kb_jwt_sd_hash_mismatch_after_dropping_a_disclosure_is_rejected()
    {
        // Mint a KB-JWT over the full presentation, then drop a Disclosure from the SD-JWT portion.
        // The KB-JWT's sd_hash no longer matches the (shorter) presentation — replay/splice defense.
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var (issuer, issued) = await IssueSampleAsync(new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        const string aud = "https://verifier.example.org";
        const string nonce = "n1";
        var full = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holder.Signer, aud, nonce);

        // Splice: keep the issuer JWT + first disclosure + KB-JWT, drop the second disclosure.
        var components = SdJwtComponents.Parse(full);
        var sdParts = components.SdJwtWithoutKeyBinding.Split('~'); // [jwt, D1, D2, ""]
        var spliced = $"{sdParts[0]}~{sdParts[1]}~{components.KeyBindingJwt}";

        var result = SdJwtVerifier.Verify(spliced, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = aud,
            ExpectedNonce = nonce,
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_SD_HASH_MISMATCH");
    }

    [Fact]
    public async Task Kb_jwt_with_wrong_nonce_is_rejected_replay_defense()
    {
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var (issuer, issued) = await IssueSampleAsync(new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        const string aud = "https://verifier.example.org";
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holder.Signer, aud, "issued-nonce");

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = aud,
            ExpectedNonce = "different-nonce", // verifier expected a different challenge
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_NONCE_MISMATCH");
    }

    [Fact]
    public async Task Kb_jwt_with_wrong_audience_is_rejected()
    {
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var (issuer, issued) = await IssueSampleAsync(new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holder.Signer, "https://other.example", "n1");

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = "https://verifier.example.org",
            ExpectedNonce = "n1",
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_AUDIENCE_MISMATCH");
    }

    [Fact]
    public async Task Expired_kb_jwt_exceeding_the_freshness_bound_is_rejected()
    {
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var (issuer, issued) = await IssueSampleAsync(new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        const string aud = "https://verifier.example.org";
        const string nonce = "n1";
        var issuedAt = DateTimeOffset.UtcNow.AddHours(-2); // KB-JWT minted 2 hours ago
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, issued.Disclosures.Select(d => d.Encoded), holder.Signer, aud, nonce, issuedAt);

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = aud,
            ExpectedNonce = nonce,
            MaxKeyBindingAge = TimeSpan.FromMinutes(5), // far younger than 2 hours
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_EXPIRED");
    }

    [Fact]
    public async Task Kb_jwt_signed_by_a_key_other_than_cnf_is_rejected()
    {
        // Proof-of-possession: a KB-JWT signed by an attacker key (not the SD-JWT's cnf) must fail.
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var attacker = TestKeyMaterial.Generate(KeyType.P256, "attacker");
        var (issuer, issued) = await IssueSampleAsync(new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        const string aud = "https://verifier.example.org";
        const string nonce = "n1";
        // Sign the KB-JWT with the attacker's key over the genuine presentation bytes.
        var sdJwtPresentation = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));
        var kbJwt = await KeyBindingJwt.IssueAsync(
            sdJwtPresentation, SdHashAlgorithm.Sha256, nonce, aud, DateTimeOffset.UtcNow, attacker.Signer);
        var forgedPresentation = sdJwtPresentation + kbJwt;

        var result = SdJwtVerifier.Verify(forgedPresentation, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = aud,
            ExpectedNonce = nonce,
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_SIGNATURE_INVALID");
    }

    [Fact]
    public async Task A_kb_jwt_without_a_cnf_in_the_sd_jwt_is_rejected()
    {
        // RFC 9901 §7.3: a presentation carrying a KB-JWT but whose SD-JWT has no cnf has nothing to
        // verify the KB-JWT against — rejected (KB_JWT_NO_CNF), not silently accepted.
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder");
        var (issuer, issued) = await IssueSampleAsync(); // NO HolderConfirmationKey → no cnf

        const string aud = "https://verifier.example.org";
        const string nonce = "n1";
        var sdJwtPresentation = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));
        var kbJwt = await KeyBindingJwt.IssueAsync(
            sdJwtPresentation, SdHashAlgorithm.Sha256, nonce, aud, DateTimeOffset.UtcNow, holder.Signer);
        var presentation = sdJwtPresentation + kbJwt;

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            ExpectedAudience = aud,
            ExpectedNonce = nonce,
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_NO_CNF");
    }

    [Fact]
    public async Task Required_key_binding_absent_is_rejected()
    {
        var (issuer, issued) = await IssueSampleAsync(new SdJwtIssuerOptions
        {
            HolderConfirmationKey = TestKeyMaterial.Generate(KeyType.P256, "holder").PublicJwk,
        });
        // Present without a KB-JWT.
        var presentation = SdJwtHolder.CreatePresentation(issued.Issuance, issued.Disclosures.Select(d => d.Encoded));

        var result = SdJwtVerifier.Verify(presentation, _ => issuer.PublicJwk, new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = "https://verifier.example.org",
            ExpectedNonce = "n1",
        });

        result.IsValid.Should().BeFalse();
        string.Join(" ", result.Errors).Should().Contain("KB_JWT_REQUIRED");
    }

    [Fact]
    public void Structurally_malformed_presentation_no_trailing_tilde_is_rejected()
    {
        // A bare JWT with no '~' is not a valid SD-JWT (RFC 9901 §4 requires the trailing '~').
        SdJwtVerificationResult? result = null;
        Action act = () => result = SdJwtVerifier.Verify("aaa.bbb.ccc", Resolver);

        act.Should().NotThrow();
        result!.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("MALFORMED");
    }

    [Fact]
    public async Task Duplicate_digest_in_two_disclosures_is_rejected()
    {
        // RFC 9901 §7.1: two Disclosures sharing the same digest is an attack signal. Present the
        // same Disclosure twice.
        var (issuer, issued) = await IssueSampleAsync();
        var d1 = issued.Disclosures[0].Encoded;
        var parts = issued.Issuance.Split('~').ToList();
        parts.Insert(parts.Count - 1, d1); // duplicate the first disclosure
        var dup = string.Join('~', parts);

        var result = SdJwtVerifier.Verify(dup, _ => issuer.PublicJwk);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith("DISCLOSURE_INVALID");
    }
}
