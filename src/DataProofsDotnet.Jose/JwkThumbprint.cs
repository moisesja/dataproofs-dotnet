using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Json;
using NetCrypto;

namespace DataProofsDotnet.Jose;

/// <summary>
/// RFC 7638 JWK thumbprints (PRD FR-15). The thumbprint is
/// <c>SHA-256( UTF8( canonical-JSON of the required members ) )</c> where the required members
/// are serialized with lexicographically sorted names, no whitespace, and no string escaping
/// beyond JSON's minimum — the JCS-consistent member serialization RFC 7638 §3 specifies.
/// Hashing routes through NetCrypto (PRD §2.2).
/// </summary>
public static class JwkThumbprint
{
    /// <summary>Compute the raw 32-byte RFC 7638 thumbprint of <paramref name="jwk"/>.</summary>
    /// <param name="jwk">The JWK (public members suffice; private members are never included).</param>
    /// <exception cref="MalformedJoseException">When the JWK's <c>kty</c> is missing/unsupported or a required member is absent.</exception>
    public static byte[] Compute(Jwk jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        var canonical = BuildCanonicalMembers(jwk);
        return Hash.Sha256(DeterministicJsonWriter.WriteUtf8(canonical));
    }

    /// <summary>Compute the thumbprint and return it base64url-encoded (the form JOSE carries).</summary>
    /// <param name="jwk">The JWK.</param>
    public static string ComputeBase64Url(Jwk jwk) => Base64Url.Encode(Compute(jwk));

    /// <summary>
    /// The RFC 7638 §3.1 <c>kid</c> convention: the base64url thumbprint used directly as the
    /// key identifier.
    /// </summary>
    /// <param name="jwk">The JWK.</param>
    public static string ComputeKid(Jwk jwk) => ComputeBase64Url(jwk);

    private static JsonObject BuildCanonicalMembers(Jwk jwk)
    {
        // Required members per RFC 7638 §3.2; the DeterministicJsonWriter sorts member names
        // ordinally, which equals the lexicographic order the RFC requires for these ASCII names.
        switch (jwk.Kty)
        {
            case "EC":
                return new JsonObject
                {
                    ["crv"] = Require(jwk.Crv, "crv"),
                    ["kty"] = "EC",
                    ["x"] = Require(jwk.X, "x"),
                    ["y"] = Require(jwk.Y, "y"),
                };
            case "OKP": // RFC 8037 §2: required members are crv, kty, x.
                return new JsonObject
                {
                    ["crv"] = Require(jwk.Crv, "crv"),
                    ["kty"] = "OKP",
                    ["x"] = Require(jwk.X, "x"),
                };
            case "oct":
                return new JsonObject
                {
                    ["k"] = Require(jwk.K, "k"),
                    ["kty"] = "oct",
                };
            case "RSA":
                // RSA keys are out of v1 signing scope (PRD FR-13) but their thumbprint is pure
                // JSON + hash; 'n'/'e' arrive through the extension-data bag.
                return new JsonObject
                {
                    ["e"] = RequireAdditional(jwk, "e"),
                    ["kty"] = "RSA",
                    ["n"] = RequireAdditional(jwk, "n"),
                };
            default:
                throw new MalformedJoseException($"JWK 'kty' '{jwk.Kty}' has no RFC 7638 thumbprint definition in this library.");
        }
    }

    private static string Require(string? value, string name)
        => string.IsNullOrEmpty(value)
            ? throw new MalformedJoseException($"JWK is missing required thumbprint member '{name}' (RFC 7638 §3.2).")
            : value;

    private static string RequireAdditional(Jwk jwk, string name)
    {
        if (jwk.AdditionalData is not null
            && jwk.AdditionalData.TryGetValue(name, out var el)
            && el.ValueKind == System.Text.Json.JsonValueKind.String)
            return el.GetString()!;
        throw new MalformedJoseException($"JWK is missing required thumbprint member '{name}' (RFC 7638 §3.2).");
    }
}
