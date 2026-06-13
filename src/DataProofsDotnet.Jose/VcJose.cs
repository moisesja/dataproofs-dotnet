using System.Text;
using System.Text.Json;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose;

/// <summary>
/// The JOSE half of VC-JOSE-COSE (PRD FR-18): enveloping a W3C VCDM 2.0 credential as a JWS per
/// "Securing Verifiable Credentials using JOSE and COSE". The credential is treated as opaque,
/// well-formed JSON bytes — credential data-model validation is out of scope (PRD §11). The
/// envelope carries the spec-mandated protected headers <c>typ: "vc+jwt"</c> and <c>cty: "vc"</c>
/// (the <c>application/vc+jwt</c> media type); verification rejects an envelope whose <c>typ</c>
/// or <c>cty</c> is wrong or absent. Mirrors the COSE counterpart
/// <c>DataProofsDotnet.Cose.VcCose</c> in shape and naming. Stateless and thread-safe.
/// </summary>
public static class VcJose
{
    /// <summary>The required <c>typ</c> protected-header value: the VC-JOSE media type without the <c>application/</c> prefix (W3C VC-JOSE-COSE).</summary>
    public const string EnvelopeType = "vc+jwt";

    /// <summary>The required <c>cty</c> protected-header value distinguishing the secured content as a VCDM credential (W3C VC-JOSE-COSE).</summary>
    public const string CredentialContentType = "vc";

    /// <summary>The registered media type identifying a JWS-secured VCDM credential.</summary>
    public const string MediaType = "application/vc+jwt";

    /// <summary>
    /// Envelope a VCDM 2.0 credential (UTF-8 JSON object bytes) as a compact JWS with the
    /// spec's <c>typ</c> and <c>cty</c> protected headers.
    /// </summary>
    /// <param name="credentialJson">The credential as UTF-8 JSON object bytes (treated as opaque; only well-formedness is checked).</param>
    /// <param name="signer">The NetCrypto-backed JWS signer (AC-8 — no raw private keys).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">When the payload is not a well-formed JSON object.</exception>
    public static async Task<string> EnvelopeCredentialAsync(
        ReadOnlyMemory<byte> credentialJson,
        JwsSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);

        try
        {
            using var document = JsonDocument.Parse(credentialJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new MalformedJoseException("A VCDM 2.0 credential must be a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("The credential payload is not well-formed JSON.", ex);
        }

        var header = new JwsProtectedHeader
        {
            Alg = signer.Algorithm,
            Kid = signer.Kid ?? string.Empty,
            Typ = EnvelopeType,
            AdditionalMembers = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["cty"] = JsonSerializer.SerializeToElement(CredentialContentType),
            },
        };

        var protectedB64u = header.EncodeBase64Url();
        var payloadB64u = Base64Url.Encode(credentialJson.Span);
        var signingInput = Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u);
        var signature = await signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);

        return string.Concat(protectedB64u, ".", payloadB64u, ".", Base64Url.Encode(signature));
    }

    /// <summary>
    /// Verify a VC-JOSE envelope: the <c>typ</c> protected header must be <see cref="EnvelopeType"/>
    /// and the <c>cty</c> protected header must be <see cref="CredentialContentType"/> — a wrong or
    /// absent value is rejected with <see cref="MalformedJoseException"/> — then the JWS signature
    /// is verified through the standard <see cref="JwsParser"/>. The enveloped credential bytes are
    /// returned on success.
    /// </summary>
    /// <param name="envelope">The compact JWS envelope.</param>
    /// <param name="resolveSignerPublicJwk">Maps the JWS <c>kid</c> (empty when absent) to the Issuer's public JWK.</param>
    /// <param name="cryptoProvider">The crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    /// <returns>The verified, enveloped VCDM 2.0 credential bytes.</returns>
    /// <exception cref="MalformedJoseException">When the envelope is structurally invalid or carries the wrong/absent <c>typ</c>/<c>cty</c>.</exception>
    /// <exception cref="JoseCryptoException">When the signature does not verify.</exception>
    public static byte[] VerifyCredential(
        string envelope,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider? cryptoProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(envelope);
        ArgumentNullException.ThrowIfNull(resolveSignerPublicJwk);
        cryptoProvider ??= new JoseCryptoProvider();

        var segments = envelope.Split('.');
        if (segments.Length != 3 || segments[0].Length == 0)
            throw new MalformedJoseException("VC-JOSE envelope is not a compact JWS (header.payload.signature).");

        // Inspect the protected header before verifying the signature so a wrong/absent typ/cty is
        // a documented failure rather than silently passing as a generic JWS (mirrors VcCose).
        var header = JwsProtectedHeader.Decode(segments[0]);
        if (!string.Equals(header.Typ, EnvelopeType, StringComparison.Ordinal))
            throw new MalformedJoseException(
                $"VC-JOSE requires the 'typ' protected header \"{EnvelopeType}\"; found \"{header.Typ ?? "(absent)"}\".");

        var cty = header.AdditionalMembers is not null
            && header.AdditionalMembers.TryGetValue("cty", out var ctyEl)
            && ctyEl.ValueKind == JsonValueKind.String
                ? ctyEl.GetString()
                : null;
        if (!string.Equals(cty, CredentialContentType, StringComparison.Ordinal))
            throw new MalformedJoseException(
                $"VC-JOSE requires the 'cty' protected header \"{CredentialContentType}\"; found \"{cty ?? "(absent)"}\".");

        var result = JwsParser.ParseCompact(envelope, resolveSignerPublicJwk, cryptoProvider);
        return result.PayloadBytes;
    }
}
