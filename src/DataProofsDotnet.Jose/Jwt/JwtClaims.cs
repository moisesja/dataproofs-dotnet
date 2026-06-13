using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.Jwt;

/// <summary>
/// A JWT claims set (RFC 7519 §4) — the registered claims as typed properties plus an
/// extension bag for everything else (PRD FR-15). Immutable after construction (NFR-4).
/// </summary>
/// <remarks>
/// NumericDate claims (<c>exp</c>/<c>nbf</c>/<c>iat</c>) are whole seconds since the Unix
/// epoch; sub-second precision is truncated on construction so a serialize→parse round trip is
/// lossless. <c>aud</c> may be a single string or an array of strings on the wire (RFC 7519
/// §4.1.3); a single audience serializes as a bare string.
/// </remarks>
public sealed class JwtClaims
{
    /// <summary>Create a claims set. All parameters are optional; omitted claims are not serialized.</summary>
    /// <param name="issuer"><c>iss</c>.</param>
    /// <param name="subject"><c>sub</c>.</param>
    /// <param name="audiences"><c>aud</c> values (one serializes as a string, several as an array).</param>
    /// <param name="expiresAt"><c>exp</c> (truncated to whole seconds).</param>
    /// <param name="notBefore"><c>nbf</c> (truncated to whole seconds).</param>
    /// <param name="issuedAt"><c>iat</c> (truncated to whole seconds).</param>
    /// <param name="jwtId"><c>jti</c>.</param>
    /// <param name="additionalClaims">Any further claims, keyed by claim name; values are JSON nodes.</param>
    public JwtClaims(
        string? issuer = null,
        string? subject = null,
        IReadOnlyList<string>? audiences = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? issuedAt = null,
        string? jwtId = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
    {
        Issuer = issuer;
        Subject = subject;
        Audiences = audiences?.ToArray() ?? [];
        ExpiresAt = Truncate(expiresAt);
        NotBefore = Truncate(notBefore);
        IssuedAt = Truncate(issuedAt);
        JwtId = jwtId;
        AdditionalClaims = additionalClaims is null
            ? new Dictionary<string, JsonNode?>()
            : new Dictionary<string, JsonNode?>(additionalClaims.ToDictionary(p => p.Key, p => p.Value?.DeepClone()));
    }

    /// <summary>The <c>iss</c> claim, or <c>null</c>.</summary>
    public string? Issuer { get; }

    /// <summary>The <c>sub</c> claim, or <c>null</c>.</summary>
    public string? Subject { get; }

    /// <summary>The <c>aud</c> claim values; empty when absent.</summary>
    public IReadOnlyList<string> Audiences { get; }

    /// <summary>The <c>exp</c> claim, or <c>null</c>.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>The <c>nbf</c> claim, or <c>null</c>.</summary>
    public DateTimeOffset? NotBefore { get; }

    /// <summary>The <c>iat</c> claim, or <c>null</c>.</summary>
    public DateTimeOffset? IssuedAt { get; }

    /// <summary>The <c>jti</c> claim, or <c>null</c>.</summary>
    public string? JwtId { get; }

    /// <summary>Non-registered claims, keyed by claim name.</summary>
    public IReadOnlyDictionary<string, JsonNode?> AdditionalClaims { get; }

    /// <summary>Serialize the claims set to canonical UTF-8 JSON bytes (deterministic member order, NFR-5).</summary>
    public byte[] ToJsonBytes()
    {
        var obj = new JsonObject();
        if (Issuer is not null) obj["iss"] = Issuer;
        if (Subject is not null) obj["sub"] = Subject;
        if (Audiences.Count == 1) obj["aud"] = Audiences[0];
        else if (Audiences.Count > 1) obj["aud"] = new JsonArray(Audiences.Select(a => (JsonNode)a).ToArray());
        if (ExpiresAt is { } exp) obj["exp"] = exp.ToUnixTimeSeconds();
        if (NotBefore is { } nbf) obj["nbf"] = nbf.ToUnixTimeSeconds();
        if (IssuedAt is { } iat) obj["iat"] = iat.ToUnixTimeSeconds();
        if (JwtId is not null) obj["jti"] = JwtId;
        foreach (var (name, value) in AdditionalClaims)
            obj[name] = value?.DeepClone();
        return DeterministicJsonWriter.WriteUtf8(obj);
    }

    /// <summary>
    /// Parse a claims set from UTF-8 JSON bytes. Duplicate members are rejected (parser-
    /// differential defense); registered claims with the wrong JSON type are rejected.
    /// </summary>
    /// <param name="utf8Json">The claims-set JSON bytes (a JWS payload).</param>
    /// <exception cref="MalformedJoseException">When the bytes are not a valid claims-set object.</exception>
    public static JwtClaims Parse(ReadOnlySpan<byte> utf8Json)
    {
        JsonNode? node;
        try
        {
            using var doc = JsonDocument.Parse(utf8Json.ToArray(), JoseJson.StrictDocument);
            node = JsonObject.Create(doc.RootElement.Clone());
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("JWT claims set is not valid JSON.", ex);
        }

        if (node is not JsonObject obj)
            throw new MalformedJoseException("JWT claims set is not a JSON object.");

        string? issuer = null, subject = null, jwtId = null;
        List<string> audiences = [];
        DateTimeOffset? expiresAt = null, notBefore = null, issuedAt = null;
        var additional = new Dictionary<string, JsonNode?>();

        foreach (var (name, value) in obj)
        {
            switch (name)
            {
                case "iss": issuer = RequireString(value, "iss"); break;
                case "sub": subject = RequireString(value, "sub"); break;
                case "jti": jwtId = RequireString(value, "jti"); break;
                case "aud":
                    switch (value)
                    {
                        case JsonValue v when v.TryGetValue<string>(out var single):
                            audiences.Add(single);
                            break;
                        case JsonArray arr:
                            foreach (var item in arr)
                                audiences.Add(item is JsonValue iv && iv.TryGetValue<string>(out var s)
                                    ? s
                                    : throw new MalformedJoseException("JWT 'aud' array must contain only strings."));
                            break;
                        default:
                            throw new MalformedJoseException("JWT 'aud' must be a string or an array of strings.");
                    }
                    break;
                case "exp": expiresAt = RequireNumericDate(value, "exp"); break;
                case "nbf": notBefore = RequireNumericDate(value, "nbf"); break;
                case "iat": issuedAt = RequireNumericDate(value, "iat"); break;
                default: additional[name] = value?.DeepClone(); break;
            }
        }

        return new JwtClaims(issuer, subject, audiences, expiresAt, notBefore, issuedAt, jwtId, additional);
    }

    private static string RequireString(JsonNode? value, string name)
        => value is JsonValue v && v.TryGetValue<string>(out var s)
            ? s
            : throw new MalformedJoseException($"JWT '{name}' must be a JSON string.");

    private static DateTimeOffset RequireNumericDate(JsonNode? value, string name)
    {
        // RFC 7519 NumericDate is a JSON number of seconds; fractional seconds are permitted by
        // the spec but truncated here (whole-second resolution).
        if (value is JsonValue v)
        {
            if (v.TryGetValue<long>(out var seconds))
                return DateTimeOffset.FromUnixTimeSeconds(seconds);
            if (v.TryGetValue<double>(out var fractional) && !double.IsNaN(fractional) && !double.IsInfinity(fractional))
                return DateTimeOffset.FromUnixTimeSeconds((long)fractional);
        }
        throw new MalformedJoseException($"JWT '{name}' must be a NumericDate (JSON number of epoch seconds).");
    }

    private static DateTimeOffset? Truncate(DateTimeOffset? value)
        => value is { } v ? DateTimeOffset.FromUnixTimeSeconds(v.ToUnixTimeSeconds()) : null;
}
