using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Verifies SD-JWT presentations (RFC 9901 §7): verifies the Issuer JWT signature, reconstructs
/// the processed (disclosed) payload by resolving every <c>_sd</c> digest and array-element
/// <c>{"...": digest}</c> placeholder against the presented Disclosures (rejecting
/// undisclosed/duplicate/unknown/shape-mismatched digests), and — when a Key Binding JWT is
/// present or required — verifies it (<c>typ</c>, signature under the SD-JWT's <c>cnf</c> key,
/// <c>sd_hash</c>, <c>aud</c>, <c>nonce</c>, freshness). Returns a structured
/// <see cref="SdJwtVerificationResult"/>; a structurally valid but failing presentation yields
/// <see cref="SdJwtVerificationResult.IsValid"/> <c>false</c> rather than throwing
/// (PRD FR-3/FR-23). Stateless and thread-safe.
/// </summary>
/// <remarks>
/// The Issuer JWT's <c>typ</c> is not checked here: RFC 9901 §9.11 leaves explicit typing to the
/// application profile, so this verifier accepts any kind of SD-JWT. A caller verifying one profile
/// checks its <c>typ</c>; for SD-JWT VC use <see cref="Vc.SdJwtVcVerifier"/>, which accepts only
/// <c>dc+sd-jwt</c>.
/// </remarks>
public static class SdJwtVerifier
{
    /// <summary>
    /// Verify a presented SD-JWT (with or without a Key Binding JWT) against the Issuer's public
    /// key. The Issuer JWT signature is checked first; on success the disclosed payload is
    /// reconstructed and (when applicable) the KB-JWT is verified.
    /// </summary>
    /// <param name="presentation">The presented SD-JWT (<c>issuer-JWT~D1~…~Dn~</c> optionally followed by a KB-JWT).</param>
    /// <param name="resolveIssuerPublicJwk">
    /// Maps the Issuer JWT's <c>kid</c> (empty string when the header carries none) to the
    /// Issuer's public JWK; returns <c>null</c> when the kid is unknown.
    /// </param>
    /// <param name="options">Verification/Key-Binding policy; <c>null</c> uses the defaults.</param>
    /// <param name="cryptoProvider">The crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="presentation"/> or <paramref name="resolveIssuerPublicJwk"/> is null.</exception>
    public static SdJwtVerificationResult Verify(
        string presentation,
        Func<string, Jwk?> resolveIssuerPublicJwk,
        SdJwtVerificationOptions? options = null,
        IJoseCryptoProvider? cryptoProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(presentation);
        ArgumentNullException.ThrowIfNull(resolveIssuerPublicJwk);
        return VerifyCore(presentation, IssuerKeySource.ByKid(resolveIssuerPublicJwk), options, cryptoProvider);
    }

    /// <summary>
    /// Verify a presented SD-JWT as <see cref="Verify"/> does, but with the Issuer's key taken from the <c>x5c</c>
    /// header parameter of the Issuer JWT (RFC 7515 §4.1.6): the X.509 mechanism, chosen by calling this method. The
    /// Issuer signature is verified with the end-entity certificate's key, and only then is the chain handed to
    /// <paramref name="validateIssuerCertificateChain"/>, which must return <c>true</c>; then the Disclosures and any
    /// Key Binding JWT are processed as usual. No <c>kid</c> resolver is consulted.
    /// </summary>
    /// <remarks>
    /// The hook is the trust decision: return <c>true</c> only when the chain validates (RFC 5280) to an anchor your
    /// policy permits for this Issuer. A certificate in <c>x5c</c> is not an anchor because it is there, and the library
    /// checks no certificate signature, validity, order, revocation or anchor (see <see cref="X509CertificateChain"/>);
    /// it does refuse an end-entity certificate whose Key Usage does not assert <c>digitalSignature</c>, before using the
    /// key. An exception from the hook propagates unchanged. Failures are coded: <c>X5C_MISSING</c>,
    /// <c>X5C_MALFORMED</c>, <c>X5C_UNSUPPORTED_KEY</c>, <c>X5C_KEY_USAGE</c>, <c>ISSUER_SIGNATURE_INVALID</c> (the
    /// signature does not verify under the end-entity key) and <c>X5C_UNTRUSTED</c> (the hook returned <c>false</c>).
    /// </remarks>
    /// <param name="presentation">The presented SD-JWT (<c>issuer-JWT~D1~…~Dn~</c> optionally followed by a KB-JWT).</param>
    /// <param name="validateIssuerCertificateChain">
    /// The caller's chain validation: <c>true</c> when the chain is valid to an anchor permitted for this Issuer.
    /// Called once, after the Issuer signature verified under the chain's end-entity key.
    /// </param>
    /// <param name="options">Verification/Key-Binding policy; <c>null</c> uses the defaults.</param>
    /// <param name="cryptoProvider">The crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="presentation"/> or <paramref name="validateIssuerCertificateChain"/> is null.</exception>
    public static SdJwtVerificationResult VerifyWithCertificateChain(
        string presentation,
        Func<X509CertificateChain, bool> validateIssuerCertificateChain,
        SdJwtVerificationOptions? options = null,
        IJoseCryptoProvider? cryptoProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(presentation);
        ArgumentNullException.ThrowIfNull(validateIssuerCertificateChain);
        return VerifyCore(presentation, IssuerKeySource.ByCertificateChain(validateIssuerCertificateChain), options, cryptoProvider);
    }

    /// <summary>
    /// Where the Issuer key comes from: a <c>kid</c> resolver, or the <c>x5c</c> chain and the caller's validation hook.
    /// Exactly one is set. The caller picks it by the method it calls; the presentation never does (sd-jwt-vc-27 §7.3).
    /// </summary>
    internal sealed record IssuerKeySource(Func<string, Jwk?>? ResolveByKid, Func<X509CertificateChain, bool>? ValidateChain)
    {
        public static IssuerKeySource ByKid(Func<string, Jwk?> resolve) => new(resolve, null);

        public static IssuerKeySource ByCertificateChain(Func<X509CertificateChain, bool> validate) => new(null, validate);
    }

    internal static SdJwtVerificationResult VerifyCore(
        string presentation,
        IssuerKeySource keySource,
        SdJwtVerificationOptions? options,
        IJoseCryptoProvider? cryptoProvider)
    {
        options ??= new SdJwtVerificationOptions();
        cryptoProvider ??= new JoseCryptoProvider();

        // 1. Structural decomposition. A first element that is not a compact JWT, or a malformed
        //    Disclosure, is a structural failure we surface as a result (never an unhandled throw).
        SdJwtComponents components;
        CompactJwt issuerJwt;
        try
        {
            components = SdJwtComponents.Parse(presentation);
            issuerJwt = CompactJwt.Decode(components.IssuerJwt);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"MALFORMED: {ex.Message}");
        }

        // 2. Resolve _sd_alg up front so an unsupported algorithm fails before any digesting,
        //    closing the RFC 9901 §10 hash-downgrade vector.
        string sdAlg;
        try
        {
            sdAlg = SdJwtClaims.ResolveSdAlg(issuerJwt.Payload);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"MALFORMED: {ex.Message}", issuerJwt.Algorithm);
        }

        // 3. Verify the Issuer JWT signature. The kid → JWK resolver mirrors the JwsParser/JwtHandler
        //    contract; an unknown kid or a non-verifying signature is a hard failure. Under the X.509 mechanism the
        //    key is the end-entity certificate's, read from the protected header (the only header a compact JWT has),
        //    and the kid is not consulted.
        Jwk issuerPublicJwk;
        X509CertificateChain? issuerChain = null;
        if (keySource.ResolveByKid is { } resolveIssuerPublicJwk)
        {
            var issuerKid = issuerJwt.KeyId ?? string.Empty;
            if (resolveIssuerPublicJwk(issuerKid) is not { } resolved)
                return SdJwtVerificationResult.Failure(
                    $"ISSUER_KEY_UNRESOLVED: no Issuer public JWK supplied for kid '{issuerKid}'.", issuerJwt.Algorithm);
            issuerPublicJwk = resolved;
        }
        else
        {
            var outcome = X509CertificateChain.FromHeader(issuerJwt.Header);
            if (outcome.Chain is not { } chain)
                return SdJwtVerificationResult.Failure(outcome.Message, issuerJwt.Algorithm);
            // A key whose certificate does not permit digital signatures is not used at all (RFC 5280 §4.2.1.3).
            if (!chain.EndEntityMaySign)
                return SdJwtVerificationResult.Failure(X509CertificateChain.KeyUsageMessage, issuerJwt.Algorithm);
            issuerChain = chain;
            var (keyType, publicKey) = chain.EndEntityKey;
            issuerPublicJwk = JwkConversion.ToPublicJwk(keyType, publicKey);
        }

        bool issuerSignatureVerified;
        try
        {
            issuerSignatureVerified = issuerJwt.Verify(issuerPublicJwk, cryptoProvider);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"ISSUER_KEY_INVALID: {ex.Message}", issuerJwt.Algorithm);
        }
        if (!issuerSignatureVerified)
            return SdJwtVerificationResult.Failure(
                "ISSUER_SIGNATURE_INVALID: the SD-JWT Issuer JWT signature did not verify.", issuerJwt.Algorithm);

        // 3a. The X.509 mechanism's trust decision is the caller's (RFC 7515 §4.1.6, sd-jwt-vc-27 §2.5). It runs
        //     only on a chain whose end-entity key has just verified the signature.
        if (issuerChain is not null && !keySource.ValidateChain!(issuerChain))
            return SdJwtVerificationResult.Failure(
                $"{X509CertificateChain.UntrustedCode}: the certificate chain validation hook did not accept the Issuer's 'x5c' chain.",
                issuerJwt.Algorithm);

        // 4. Reconstruct the disclosed payload (RFC 9901 §7.1): resolve every digest against the
        //    presented Disclosures, rejecting unknown/duplicate/shape-mismatched/unused ones.
        JsonObject disclosedPayload;
        try
        {
            disclosedPayload = SdJwtReconstructor.Reconstruct(issuerJwt.Payload, components.Disclosures, sdAlg);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"DISCLOSURE_INVALID: {ex.Message}", issuerJwt.Algorithm);
        }

        // 5. Key Binding (RFC 9901 §7.3).
        var keyBindingVerified = false;
        if (components.HasKeyBinding)
        {
            var cnf = SafeGetConfirmationKey(issuerJwt.Payload, out var cnfError);
            if (cnfError is not null)
                return SdJwtVerificationResult.Failure($"DISCLOSURE_INVALID: {cnfError}", issuerJwt.Algorithm);
            if (cnf is null)
                return SdJwtVerificationResult.Failure(
                    "KB_JWT_NO_CNF: the presentation carries a Key Binding JWT but the SD-JWT has no 'cnf' key to verify it against (RFC 9901 §7.3).",
                    issuerJwt.Algorithm);

            var kbErrors = KeyBindingJwt.Verify(
                components.KeyBindingJwt!, components.SdJwtWithoutKeyBinding, sdAlg, cnf, options, cryptoProvider);
            if (kbErrors.Count > 0)
                return SdJwtVerificationResult.Failure(kbErrors, issuerJwt.Algorithm);
            keyBindingVerified = true;
        }
        else if (options.RequireKeyBinding)
        {
            return SdJwtVerificationResult.Failure(
                "KB_JWT_REQUIRED: the verification policy requires a Key Binding JWT, but the presentation carries none.",
                issuerJwt.Algorithm);
        }

        return SdJwtVerificationResult.Success(disclosedPayload, keyBindingVerified, issuerJwt.Algorithm, issuerChain);
    }

    private static Jwk? SafeGetConfirmationKey(JsonObject payload, out string? error)
    {
        try
        {
            error = null;
            return SdJwtClaims.TryGetConfirmationKey(payload);
        }
        catch (MalformedJoseException ex)
        {
            error = ex.Message;
            return null;
        }
    }
}
