using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.Jwt;

/// <summary>
/// JWT issuance and validation atop the FR-13 JWS layer (PRD FR-15): compact JWS with
/// <c>typ="JWT"</c>, claims-set construction via <see cref="JwtClaims"/>, and validation of
/// <c>exp</c>/<c>nbf</c>/<c>iat</c>/<c>iss</c>/<c>aud</c>/<c>sub</c> with configurable clock
/// skew via <see cref="JwtValidationOptions"/>.
/// </summary>
public static class JwtHandler
{
    /// <summary>Sign <paramref name="claims"/> as a compact JWT (<c>typ="JWT"</c>).</summary>
    /// <param name="claims">The claims set to sign.</param>
    /// <param name="signer">The JWS signer (NetCrypto-backed; AC-8 — no raw private keys).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    public static Task<string> SignAsync(JwtClaims claims, JwsSigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(signer);
        return JwsBuilder.BuildCompactAsync(claims.ToJsonBytes(), signer, typ: "JWT", cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Verify a compact JWT: signature first (rejecting <c>alg="none"</c> and anything outside
    /// the allow-list), then the claims checks of <paramref name="options"/>. Returns a
    /// structured result — invalid tokens never throw (AC-3 negative-path convention);
    /// exceptions are reserved for caller misuse (null arguments).
    /// </summary>
    /// <param name="jwt">The compact JWT string.</param>
    /// <param name="resolveSignerPublicJwk">Signer kid → public JWK resolver (empty string when the header has no kid).</param>
    /// <param name="options">Validation policy; <c>null</c> uses the defaults.</param>
    /// <param name="cryptoProvider">Crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    public static JwtVerificationResult Verify(
        string jwt,
        Func<string, Jwk?> resolveSignerPublicJwk,
        JwtValidationOptions? options = null,
        IJoseCryptoProvider? cryptoProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(resolveSignerPublicJwk);
        options ??= new JwtValidationOptions();
        cryptoProvider ??= new JoseCryptoProvider();

        JwsParseResult parsed;
        try
        {
            parsed = JwsParser.ParseCompact(jwt, resolveSignerPublicJwk, cryptoProvider);
        }
        catch (MalformedJoseException ex)
        {
            return JwtVerificationResult.Failure([$"MALFORMED: {ex.Message}"]);
        }
        catch (JoseCryptoException ex)
        {
            return JwtVerificationResult.Failure([$"SIGNATURE_INVALID: {ex.Message}"]);
        }

        JwtClaims claims;
        try
        {
            claims = JwtClaims.Parse(parsed.PayloadBytes);
        }
        catch (MalformedJoseException ex)
        {
            return JwtVerificationResult.Failure(
                [$"MALFORMED: {ex.Message}"], claims: null, parsed.SignatureAlgorithm, parsed.SignerKid);
        }

        var errors = new List<string>();

        if (!options.AllowedAlgorithms.Contains(parsed.SignatureAlgorithm, StringComparer.Ordinal))
            errors.Add($"ALGORITHM_NOT_ALLOWED: JWS alg '{parsed.SignatureAlgorithm}' is not in the allowed set.");

        var now = options.CurrentTime ?? DateTimeOffset.UtcNow;
        var skew = options.ClockSkew;

        if (claims.ExpiresAt is { } exp)
        {
            if (now > exp + skew)
                errors.Add($"EXPIRED: token expired at {exp:O} (clock skew {skew}).");
        }
        else if (options.RequireExpirationTime)
        {
            errors.Add("MISSING_EXPIRATION: token has no 'exp' claim but the policy requires one.");
        }

        if (claims.NotBefore is { } nbf && now < nbf - skew)
            errors.Add($"NOT_YET_VALID: token not valid before {nbf:O} (clock skew {skew}).");

        if (claims.IssuedAt is { } iat && now < iat - skew)
            errors.Add($"ISSUED_IN_FUTURE: token issued at {iat:O}, which is after the current time (clock skew {skew}).");

        if (options.ExpectedIssuer is { } iss && !string.Equals(claims.Issuer, iss, StringComparison.Ordinal))
            errors.Add($"ISSUER_MISMATCH: expected '{iss}', got '{claims.Issuer}'.");

        if (options.ExpectedAudience is { } aud && !claims.Audiences.Contains(aud, StringComparer.Ordinal))
            errors.Add($"AUDIENCE_MISMATCH: expected '{aud}' among [{string.Join(", ", claims.Audiences)}].");

        if (options.ExpectedSubject is { } sub && !string.Equals(claims.Subject, sub, StringComparison.Ordinal))
            errors.Add($"SUBJECT_MISMATCH: expected '{sub}', got '{claims.Subject}'.");

        return errors.Count == 0
            ? JwtVerificationResult.Success(claims, parsed.SignatureAlgorithm, parsed.SignerKid)
            : JwtVerificationResult.Failure(errors, claims, parsed.SignatureAlgorithm, parsed.SignerKid);
    }
}
