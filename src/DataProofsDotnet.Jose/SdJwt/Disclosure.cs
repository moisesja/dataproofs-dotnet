using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// A single SD-JWT Disclosure (RFC 9901 §4.2): the base64url encoding of a JSON array that is
/// either <c>[salt, claimName, claimValue]</c> for an object property or <c>[salt, claimValue]</c>
/// for an array element. The encoded string is the integrity-bearing artifact — its digest
/// (<c>base64url(hash(ASCII(encoded)))</c>) is what appears in an <c>_sd</c> array or an array
/// <c>{"...": digest}</c> placeholder.
/// </summary>
/// <remarks>
/// When a Disclosure is parsed from a presentation, the <b>original encoded bytes are preserved
/// verbatim</b> (<see cref="Encoded"/>): RFC 9901 §4.2.5 hashes the received string as-is, so a
/// re-serialization (which could differ in whitespace or escaping) must never feed the digest.
/// Immutable and thread-safe.
/// </remarks>
public sealed class Disclosure
{
    private Disclosure(string encoded, string? claimName, bool isArrayElement, JsonNode? valueNode)
    {
        Encoded = encoded;
        ClaimName = claimName;
        IsArrayElement = isArrayElement;
        ClaimValueNode = valueNode;
    }

    /// <summary>The base64url-no-pad encoding of the Disclosure array — the exact bytes the digest is computed over.</summary>
    public string Encoded { get; }

    /// <summary>The claim name for an object-property Disclosure; <c>null</c> for an array-element Disclosure.</summary>
    public string? ClaimName { get; }

    /// <summary>The disclosed claim value as a JSON node (a defensive clone is returned on each access).</summary>
    public JsonNode? ClaimValue => ClaimValueNode?.DeepClone();

    /// <summary>True when this Disclosure discloses an array element (<c>[salt, value]</c>), false for an object property.</summary>
    public bool IsArrayElement { get; }

    internal JsonNode? ClaimValueNode { get; }

    /// <summary>
    /// Create an object-property Disclosure <c>[salt, claimName, claimValue]</c> from raw parts,
    /// serializing the array to base64url. Used by the Issuer; the salt MUST come from a CSPRNG
    /// (NFR-5).
    /// </summary>
    /// <param name="salt">Base64url-no-pad random salt (RFC 9901 §4.2: at least 128 bits of entropy).</param>
    /// <param name="claimName">The object property name being made selectively disclosable.</param>
    /// <param name="claimValue">The claim value as a JSON node (may be a nested object/array).</param>
    public static Disclosure ForObjectProperty(string salt, string claimName, JsonNode? claimValue)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        var array = new JsonArray(JsonValue.Create(salt), JsonValue.Create(claimName), claimValue?.DeepClone());
        var encoded = Base64Url.Encode(SerializeArray(array));
        return new Disclosure(encoded, claimName, isArrayElement: false, claimValue?.DeepClone());
    }

    /// <summary>
    /// Create an array-element Disclosure <c>[salt, claimValue]</c> from raw parts. Used by the
    /// Issuer for selectively disclosable array elements (RFC 9901 §4.2.2).
    /// </summary>
    /// <param name="salt">Base64url-no-pad random salt.</param>
    /// <param name="claimValue">The array element value as a JSON node.</param>
    public static Disclosure ForArrayElement(string salt, JsonNode? claimValue)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);
        var array = new JsonArray(JsonValue.Create(salt), claimValue?.DeepClone());
        var encoded = Base64Url.Encode(SerializeArray(array));
        return new Disclosure(encoded, null, isArrayElement: true, claimValue?.DeepClone());
    }

    /// <summary>
    /// Parse a base64url-encoded Disclosure string, preserving the original encoded value so its
    /// digest stays bit-exact (RFC 9901 §4.2.5).
    /// </summary>
    /// <param name="encoded">The base64url-no-pad Disclosure string (one tilde-separated segment).</param>
    /// <exception cref="MalformedJoseException">
    /// When the value is not valid base64url, does not decode to a JSON array, or the array does
    /// not have 2 (array element) or 3 (object property) elements with the expected shapes.
    /// </exception>
    public static Disclosure Parse(string encoded)
    {
        ArgumentException.ThrowIfNullOrEmpty(encoded);

        byte[] bytes;
        try
        {
            bytes = Base64Url.Decode(encoded);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("SD-JWT Disclosure is not valid base64url.", ex);
        }

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(bytes, documentOptions: new JsonDocumentOptions { AllowDuplicateProperties = false });
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("SD-JWT Disclosure does not decode to valid JSON.", ex);
        }

        if (node is not JsonArray array)
            throw new MalformedJoseException("SD-JWT Disclosure must decode to a JSON array.");

        return array.Count switch
        {
            3 => ParseObjectProperty(encoded, array),
            2 => ParseArrayElement(encoded, array),
            _ => throw new MalformedJoseException(
                $"SD-JWT Disclosure array must have 2 (array element) or 3 (object property) elements; got {array.Count} (RFC 9901 §4.2)."),
        };
    }

    private static Disclosure ParseObjectProperty(string encoded, JsonArray array)
    {
        var saltNode = array[0];
        var nameNode = array[1];
        if (saltNode is not JsonValue saltValue || saltValue.GetValueKind() != JsonValueKind.String)
            throw new MalformedJoseException("SD-JWT Disclosure salt must be a JSON string.");
        if (nameNode is not JsonValue nameValue || nameValue.GetValueKind() != JsonValueKind.String)
            throw new MalformedJoseException("Object-property SD-JWT Disclosure claim name must be a JSON string.");

        var name = nameValue.GetValue<string>();
        // RFC 9901 §4.2.5.1: a Disclosure claim name must not collide with the SD-JWT control
        // claims, or a malicious Disclosure could overwrite _sd / _sd_alg during reconstruction.
        if (name is "_sd" or "...")
            throw new MalformedJoseException($"SD-JWT Disclosure claim name '{name}' is reserved and not allowed (RFC 9901 §4.2.5.1).");

        return new Disclosure(encoded, name, isArrayElement: false, array[2]?.DeepClone());
    }

    private static Disclosure ParseArrayElement(string encoded, JsonArray array)
    {
        var saltNode = array[0];
        if (saltNode is not JsonValue saltValue || saltValue.GetValueKind() != JsonValueKind.String)
            throw new MalformedJoseException("SD-JWT Disclosure salt must be a JSON string.");
        return new Disclosure(encoded, null, isArrayElement: true, array[1]?.DeepClone());
    }

    /// <summary>Compute this Disclosure's digest under the given <c>_sd_alg</c> (RFC 9901 §4.2.5).</summary>
    /// <param name="sdAlg">The hash algorithm IANA name (e.g. <c>sha-256</c>).</param>
    public string ComputeDigest(string sdAlg) => SdHashAlgorithm.ComputeDigest(sdAlg, Encoded);

    private static byte[] SerializeArray(JsonArray array)
    {
        // Issuer-side serialization. The exact byte form is internal — the digest we publish is
        // computed over precisely these bytes, so reconstruction by any conformant verifier
        // (including ours) matches. RFC 9901 §4.2 only mandates that the array be valid JSON with
        // the right shape; it does not pin a canonical form.
        var json = array.ToJsonString(Json.JoseJson.Default);
        return Encoding.UTF8.GetBytes(json);
    }
}
