using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProofsDotnet.Jose;

/// <summary>
/// JSON Web Key (RFC 7517) model used by the JWS/JWE builders and parsers. Holds the
/// JOSE-standard members directly and preserves any unknown members in
/// <see cref="AdditionalData"/> so a deserialize→serialize round-trip is lossless.
/// </summary>
/// <remarks>
/// <para>
/// Ported from didcomm-dotnet <c>DidComm.Jose.Jwk</c> (PRD §1.4 item 2), extended with the
/// symmetric-key member <see cref="K"/> (RFC 7518 §6.4, needed by the standalone
/// <c>A256KW</c> key-management algorithm of FR-14). Conversion to and from the
/// <c>Microsoft.IdentityModel.Tokens.JsonWebKey</c> boundary type and NetCid Multikey happens
/// in <see cref="JwkConversion"/>.
/// </para>
/// <para>
/// Binary members (<c>x</c>, <c>y</c>, <c>d</c>, <c>k</c>) use base64url-no-pad encoding per
/// RFC 7518 §6. Callers that need raw bytes should go through
/// <see cref="JwkConversion.ExtractPublicKey(Jwk)"/>.
/// </para>
/// </remarks>
public sealed class Jwk
{
    /// <summary>Key type. <c>"OKP"</c> for Ed25519/X25519; <c>"EC"</c> for P-256/P-384/P-521/secp256k1; <c>"oct"</c> for symmetric keys.</summary>
    [JsonPropertyName("kty")]
    public string Kty { get; set; } = string.Empty;

    /// <summary>Curve. One of <c>"Ed25519"</c>, <c>"X25519"</c>, <c>"P-256"</c>, <c>"P-384"</c>, <c>"P-521"</c>, <c>"secp256k1"</c>.</summary>
    [JsonPropertyName("crv")]
    public string? Crv { get; set; }

    /// <summary>Public key X-coordinate (EC) or raw public key (OKP), base64url-no-pad.</summary>
    [JsonPropertyName("x")]
    public string? X { get; set; }

    /// <summary>Public key Y-coordinate. Only present for <c>kty="EC"</c>.</summary>
    [JsonPropertyName("y")]
    public string? Y { get; set; }

    /// <summary>Private key. Base64url-no-pad. Present only on private JWKs.</summary>
    [JsonPropertyName("d")]
    public string? D { get; set; }

    /// <summary>Symmetric key value (RFC 7518 §6.4.1). Base64url-no-pad. Present only for <c>kty="oct"</c>.</summary>
    [JsonPropertyName("k")]
    public string? K { get; set; }

    /// <summary>Key identifier (RFC 7517 §4.5).</summary>
    [JsonPropertyName("kid")]
    public string? Kid { get; set; }

    /// <summary>Intended JWS/JWE algorithm hint (e.g. <c>"EdDSA"</c>, <c>"ECDH-1PU+A256KW"</c>).</summary>
    [JsonPropertyName("alg")]
    public string? Alg { get; set; }

    /// <summary>Public-key use hint (<c>"sig"</c> or <c>"enc"</c>).</summary>
    [JsonPropertyName("use")]
    public string? Use { get; set; }

    /// <summary>
    /// Unknown / extension members preserved verbatim across deserialize→serialize so a JWK
    /// carrying a member this model does not recognize survives a round-trip. Populated by
    /// <see cref="System.Text.Json"/>'s <see cref="JsonExtensionDataAttribute"/>.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalData { get; set; }
}
