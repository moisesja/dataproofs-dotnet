using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// A W3C VC Data Integrity 1.0 proof (FR-1): <c>type</c> is always
/// <c>DataIntegrityProof</c> and the algorithm is named by <c>cryptosuite</c>.
/// </summary>
/// <remarks>
/// <para>
/// Serialization uses the spec's camelCase member names and omits <c>null</c> members.
/// Timestamps (<c>created</c>/<c>expires</c>) are stored as their verbatim wire strings
/// — never re-formatted — because cross-stack canonical byte-equivalence depends on the
/// exact characters that were signed.
/// </para>
/// <para>
/// Unmodeled members round-trip through <see cref="AdditionalProperties"/> so that
/// extension fields survive deserialization and canonicalization; without this,
/// signatures over proofs carrying extensions would silently break.
/// </para>
/// </remarks>
public sealed record DataIntegrityProof
{
    /// <summary>The conventional <c>type</c> value for Data Integrity proofs.</summary>
    public const string DataIntegrityProofType = "DataIntegrityProof";

    /// <summary>Optional proof identifier, required when the proof participates in a proof chain.</summary>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; init; }

    /// <summary>The proof type. Always <c>DataIntegrityProof</c> for this generation of suites.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = DataIntegrityProofType;

    /// <summary>The cryptosuite identifier (e.g. <c>eddsa-jcs-2022</c>, <c>ecdsa-jcs-2019</c>).</summary>
    [JsonPropertyName("cryptosuite")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Cryptosuite { get; init; }

    /// <summary>Creation timestamp as the verbatim <c>dateTimeStamp</c> wire string.</summary>
    [JsonPropertyName("created")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Created { get; init; }

    /// <summary>Expiry timestamp as the verbatim <c>dateTimeStamp</c> wire string.</summary>
    [JsonPropertyName("expires")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Expires { get; init; }

    /// <summary>The URL of the verification method used to create the proof.</summary>
    [JsonPropertyName("verificationMethod")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? VerificationMethod { get; init; }

    /// <summary>The purpose of the proof (e.g. <c>assertionMethod</c>; see <see cref="ProofPurposes"/>).</summary>
    [JsonPropertyName("proofPurpose")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProofPurpose { get; init; }

    /// <summary>Challenge supplied by a relying party to mitigate replay.</summary>
    [JsonPropertyName("challenge")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Challenge { get; init; }

    /// <summary>The domain the proof is bound to.</summary>
    [JsonPropertyName("domain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Domain { get; init; }

    /// <summary>Optional nonce.</summary>
    [JsonPropertyName("nonce")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Nonce { get; init; }

    /// <summary>
    /// Reference(s) to the proof(s) this proof depends on in a proof chain
    /// (FR-6): a single proof id or a set of ids.
    /// </summary>
    [JsonPropertyName("previousProof")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PreviousProofReference? PreviousProof { get; init; }

    /// <summary>
    /// The proof's <c>@context</c>. The JCS suites copy the secured document's
    /// <c>@context</c> here at creation time and validate it at verification time.
    /// </summary>
    [JsonPropertyName("@context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Context { get; init; }

    /// <summary>The multibase-encoded signature value. Absent in a proof configuration.</summary>
    [JsonPropertyName("proofValue")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProofValue { get; init; }

    /// <summary>Unmodeled members, preserved verbatim for round-tripping and canonicalization.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}
