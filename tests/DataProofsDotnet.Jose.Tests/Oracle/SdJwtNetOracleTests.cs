using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Threading.Tasks;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NetCrypto;
using Xunit;
using OracleHolder = SdJwt.Net.Holder.SdJwtHolder;
using OracleHolderOptions = SdJwt.Net.Holder.SdJwtHolderOptions;
using OracleIssuanceOptions = SdJwt.Net.Issuer.SdIssuanceOptions;
using OracleIssuer = SdJwt.Net.Issuer.SdIssuer;
using OracleVerifier = SdJwt.Net.Verifier.SdVerifier;
using OracleVerifierOptions = SdJwt.Net.Verifier.SdVerifierOptions;

namespace DataProofsDotnet.Jose.Tests.Oracle;

/// <summary>
/// AC-3 step 3 (SD-JWT) — SdJwt.Net (OWF sd-jwt-dotnet) oracle cross-verification. The set under
/// test is the algorithm both libraries support: <b>ES256</b> (P-256 ECDSA + SHA-256). It is the
/// computed, not hard-coded, intersection — see
/// <see cref="The_shared_algorithm_is_the_one_both_libraries_implement"/>: this library's
/// SD-JWT signing flows through the JOSE signature set (which includes ES256), and SdJwt.Net's
/// approved-hash + ECDSA signing path supports ES256; EdDSA is the only other algorithm this
/// library's KB/issuer path can sign with, but SdJwt.Net's worked surface and tests are ECDSA
/// (SHA-2) — so ES256 is the cross-checkable algorithm, exercised in <b>both directions</b>
/// including KB-JWT validation.
///
/// <para>Bridging note: SdJwt.Net's public surface is keyed on
/// <c>Microsoft.IdentityModel.Tokens.SecurityKey</c>/<c>JsonWebKey</c> and
/// <c>System.IdentityModel.Tokens.Jwt.JwtPayload</c>; this library is keyed on its own
/// <see cref="Jwk"/> + NetCrypto <c>ISigner</c>. The two are bridged through EC parameters
/// (BCL crypto types are permitted in <c>tests/</c> — the AC-6 NetCrypto-only rule governs
/// <c>src/</c> exclusively).</para>
/// </summary>
public sealed class SdJwtNetOracleTests
{
    private const string Es256 = SecurityAlgorithms.EcdsaSha256; // "ES256"

    [Fact]
    public void The_shared_algorithm_is_the_one_both_libraries_implement()
    {
        // This library implements ES256 (FR-13); SdJwt.Net accepts ES256 issuer/holder signing and
        // the sha-256 _sd_alg. The intersection used below is therefore ES256, computed from each
        // side's published support rather than assumed.
        global::DataProofsDotnet.Jose.JoseAlgorithms.SupportedSignatureAlgorithms.Should().Contain("ES256");
        global::SdJwt.Net.Internal.SdJwtUtils.IsApprovedHashAlgorithm("sha-256").Should().BeTrue();
    }

    // ---------- Direction A: our SD-JWT verifies in SdJwt.Net (incl. KB-JWT) ----------

    [Fact]
    public async Task Our_presentation_with_kb_verifies_in_SdJwt_Net()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer-A");
        var holder = TestKeyMaterial.Generate(KeyType.P256, "holder-A");

        var claims = new System.Text.Json.Nodes.JsonObject
        {
            ["iss"] = "https://issuer.example.com",
            ["given_name"] = "John",
            ["family_name"] = "Doe",
            ["email"] = "john.doe@example.com",
        };
        var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name").Disclose("email");
        var issued = await SdJwtIssuer.IssueAsync(
            claims, frame, issuer.Signer,
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });

        const string audience = "https://verifier.example.com";
        const string nonce = "oracle-nonce-A";
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance,
            issued.Disclosures.Where(d => d.ClaimName is "given_name" or "email").Select(d => d.Encoded),
            holder.Signer, audience, nonce);

        // Verify it in SdJwt.Net.
        using var issuerEcdsa = ToEcdsa(issuer.PublicJwk, includePrivate: false);
        var issuerSecurityKey = new ECDsaSecurityKey(issuerEcdsa) { KeyId = "issuer-A" };
        var verifier = new OracleVerifier(_ => Task.FromResult<SecurityKey>(issuerSecurityKey), logger: null!);

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
        };
        var kbParams = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = false,
        };
        var verifierOptions = new OracleVerifierOptions { StrictMode = true };

        var result = await verifier.VerifyAsync(presentation, validationParams, kbParams, nonce, verifierOptions);

        result.KeyBindingVerified.Should().BeTrue("SdJwt.Net must accept the KB-JWT our holder produced");
        var principal = result.ClaimsPrincipal;
        principal.Should().NotBeNull();
        // SdJwt.Net surfaces the disclosed claims on the principal.
        principal.FindFirst("given_name")?.Value.Should().Be("John");
        principal.FindFirst("email")?.Value.Should().Be("john.doe@example.com");
        principal.FindFirst("family_name").Should().BeNull("the holder withheld family_name");
    }

    [Fact]
    public async Task Our_presentation_without_kb_verifies_in_SdJwt_Net()
    {
        var issuer = TestKeyMaterial.Generate(KeyType.P256, "issuer-A2");

        var claims = new System.Text.Json.Nodes.JsonObject
        {
            ["iss"] = "https://issuer.example.com",
            ["given_name"] = "Alice",
            ["family_name"] = "Smith",
        };
        var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name");
        var issued = await SdJwtIssuer.IssueAsync(claims, frame, issuer.Signer);

        var presentation = SdJwtHolder.CreatePresentation(
            issued.Issuance, issued.Disclosures.Where(d => d.ClaimName == "given_name").Select(d => d.Encoded));

        using var issuerEcdsa = ToEcdsa(issuer.PublicJwk, includePrivate: false);
        var issuerSecurityKey = new ECDsaSecurityKey(issuerEcdsa) { KeyId = "issuer-A2" };
        var verifier = new OracleVerifier(_ => Task.FromResult<SecurityKey>(issuerSecurityKey), logger: null!);

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
        };
        var result = await verifier.VerifyAsync(
            presentation, validationParams, kbJwtValidationParameters: null!, expectedKbJwtNonce: null!,
            verifierOptions: new OracleVerifierOptions { StrictMode = true });

        result.ClaimsPrincipal.FindFirst("given_name")?.Value.Should().Be("Alice");
        result.ClaimsPrincipal.FindFirst("family_name").Should().BeNull("withheld");
    }

    // ---------- Direction B: SdJwt.Net's SD-JWT verifies here (incl. KB-JWT) ----------

    [Fact]
    public async Task SdJwt_Net_presentation_with_kb_verifies_here()
    {
        using var issuerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerKey = new ECDsaSecurityKey(issuerEcdsa) { KeyId = "issuer-B" };
        var holderPublicJwk = JsonWebKeyConverter.ConvertFromSecurityKey(
            new ECDsaSecurityKey(ECDsa.Create(holderEcdsa.ExportParameters(false))) { KeyId = "holder-B" });

        var oracleIssuer = new OracleIssuer(issuerKey, Es256, SdHashAlgorithm.Sha256, logger: null!);

        var claims = new JwtPayload
        {
            ["iss"] = "https://issuer.example.com",
            ["given_name"] = "John",
            ["family_name"] = "Doe",
            ["email"] = "john.doe@example.com",
        };
        var options = new OracleIssuanceOptions
        {
            DisclosureStructure = new { given_name = true, family_name = true, email = true },
        };
        var output = oracleIssuer.Issue(claims, options, holderPublicJwk, tokenType: "example+sd-jwt");

        // Holder builds a KB presentation in SdJwt.Net, disclosing given_name + email.
        var holderPrivateKey = new ECDsaSecurityKey(holderEcdsa) { KeyId = "holder-B" };
        const string audience = "https://verifier.example.com";
        const string nonce = "oracle-nonce-B";
        var holderObj = new OracleHolder(output.Issuance, logger: null!);
        var kbPayload = new JwtPayload
        {
            ["aud"] = audience,
            ["nonce"] = nonce,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        var presentation = holderObj.CreatePresentation(
            d => d.ClaimName is "given_name" or "email",
            kbPayload, holderPrivateKey, Es256, holderOptions: new OracleHolderOptions { StrictMode = true });

        // Verify here. Our resolver needs the issuer public JWK.
        var issuerPublicJwk = ToOurJwk(issuerEcdsa, "issuer-B");
        var result = SdJwtVerifier.Verify(presentation, _ => issuerPublicJwk, new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = audience,
            ExpectedNonce = nonce,
        });

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue("our verifier must accept SdJwt.Net's KB-JWT");
        result.DisclosedPayload!["given_name"]!.GetValue<string>().Should().Be("John");
        result.DisclosedPayload!["email"]!.GetValue<string>().Should().Be("john.doe@example.com");
        result.DisclosedPayload!.Should().NotContainKey("family_name", "the holder withheld it");
    }

    [Fact]
    public async Task SdJwt_Net_presentation_without_kb_verifies_here()
    {
        using var issuerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerKey = new ECDsaSecurityKey(issuerEcdsa) { KeyId = "issuer-B2" };
        var oracleIssuer = new OracleIssuer(issuerKey, Es256, SdHashAlgorithm.Sha256, logger: null!);

        var claims = new JwtPayload
        {
            ["iss"] = "https://issuer.example.com",
            ["given_name"] = "Alice",
            ["family_name"] = "Smith",
        };
        var options = new OracleIssuanceOptions
        {
            DisclosureStructure = new { given_name = true, family_name = true },
        };
        // No holder key → no cnf, no KB.
        var output = oracleIssuer.Issue(claims, options, holderPublicKey: null!, tokenType: "example+sd-jwt");

        var holderObj = new OracleHolder(output.Issuance, logger: null!);
        // Present only given_name, no KB-JWT.
        var presentation = holderObj.CreatePresentation(
            d => d.ClaimName == "given_name",
            kbJwtPayload: null!, kbJwtSigningKey: null!, kbJwtSigningAlgorithm: null!,
            holderOptions: new OracleHolderOptions { StrictMode = true });

        var issuerPublicJwk = ToOurJwk(issuerEcdsa, "issuer-B2");
        var result = SdJwtVerifier.Verify(presentation, _ => issuerPublicJwk);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.DisclosedPayload!["given_name"]!.GetValue<string>().Should().Be("Alice");
        result.DisclosedPayload!.Should().NotContainKey("family_name", "withheld");
        await Task.CompletedTask;
    }

    // ---------- key bridges (test-side only) ----------

    private static ECDsa ToEcdsa(Jwk jwk, bool includePrivate) => ECDsa.Create(new ECParameters
    {
        Curve = jwk.Crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => throw new NotSupportedException($"No oracle curve mapping for '{jwk.Crv}'."),
        },
        Q = new ECPoint { X = Base64Url.Decode(jwk.X!), Y = Base64Url.Decode(jwk.Y!) },
        D = includePrivate ? Base64Url.Decode(jwk.D!) : null,
    });

    private static Jwk ToOurJwk(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);
        return new Jwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = Base64Url.Encode(p.Q.X!),
            Y = Base64Url.Encode(p.Q.Y!),
            Kid = kid,
        };
    }
}
