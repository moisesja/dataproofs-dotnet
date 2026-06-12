namespace DataProofsDotnet.Cose;

/// <summary>
/// The CWT claims set of RFC 8392 §3: the seven registered claims, keyed in CBOR by their
/// integer claim keys. Immutable after construction (init-only). Unregistered claims are not
/// modeled in v1 and are ignored on decode.
/// </summary>
public sealed class CwtClaims
{
    /// <summary>iss (claim key 1).</summary>
    public string? Issuer { get; init; }

    /// <summary>sub (claim key 2).</summary>
    public string? Subject { get; init; }

    /// <summary>aud (claim key 3).</summary>
    public string? Audience { get; init; }

    /// <summary>exp (claim key 4). Encoded as integer epoch seconds; decoded from integer or float numeric dates.</summary>
    public DateTimeOffset? ExpirationTime { get; init; }

    /// <summary>nbf (claim key 5).</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>iat (claim key 6).</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>cti (claim key 7), a binary token identifier.</summary>
    public ReadOnlyMemory<byte>? CwtId { get; init; }
}
