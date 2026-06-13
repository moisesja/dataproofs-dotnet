using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProofsDotnet;

/// <summary>
/// The shared <see cref="JsonSerializerOptions"/> used for every wire (de)serialization
/// performed by this library. Sign-time serialization and wire emission share these
/// options so that signed bytes always equal wire bytes.
/// </summary>
public static class DataProofsJsonOptions
{
    /// <summary>
    /// Spec-correct serializer options: no indentation, original member names preserved,
    /// <c>null</c> members omitted, and RFC 8785-compatible minimal string escaping
    /// (<see cref="JavaScriptEncoder.UnsafeRelaxedJsonEscaping"/> — the default encoder
    /// escapes <c>+ &lt; &gt; &amp; '</c>, which silently diverges canonical bytes from
    /// conformant peers). The instance is read-only.
    /// </summary>
    public static JsonSerializerOptions Default { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        // populateMissingResolver: the default reflection resolver is attached before
        // freezing — without it, MakeReadOnly() throws on options that never resolved
        // a TypeInfoResolver, breaking every consumer at first use.
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
