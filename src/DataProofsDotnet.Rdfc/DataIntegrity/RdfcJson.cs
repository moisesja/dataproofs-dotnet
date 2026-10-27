using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet.Rdfc.DataIntegrity;

/// <summary>
/// Source-generated System.Text.Json metadata for the types this package serializes (issue #27): the
/// proof model and the <see cref="JsonObject"/> documents the RDFC and bbs-2023 suites build their
/// proof configurations, skolemized documents and reveal documents with. Core's context is internal to
/// Core; each package declares what it serializes, and a type missing here fails fast in every host
/// instead of falling back to reflection.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(DataIntegrityProof))]
[JsonSerializable(typeof(JsonObject))]
internal sealed partial class RdfcJsonContext : JsonSerializerContext;

/// <summary>
/// Typed metadata accessors for <see cref="RdfcJsonContext"/>, bound to a read-only copy of
/// <see cref="DataProofsJsonOptions.Default"/>: the same encoder, null handling and indentation, so
/// the bytes equal Core's, resolved by this package's context alone.
/// </summary>
internal static class RdfcJson
{
    /// <summary>The package's wire options: <see cref="DataProofsJsonOptions.Default"/> resolved by <see cref="RdfcJsonContext"/>.</summary>
    public static JsonSerializerOptions Options { get; } = Create();

    /// <summary>Metadata for <see cref="DataIntegrityProof"/>, bound to <see cref="Options"/>.</summary>
    public static JsonTypeInfo<DataIntegrityProof> ProofTypeInfo { get; } = TypeInfo<DataIntegrityProof>();

    /// <summary>Metadata for <see cref="JsonObject"/>, bound to <see cref="Options"/>.</summary>
    public static JsonTypeInfo<JsonObject> JsonObjectTypeInfo { get; } = TypeInfo<JsonObject>();

    private static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Options.GetTypeInfo(typeof(T));

    private static JsonSerializerOptions Create()
    {
        // The copy constructor carries every wire setting; replacing the resolver drops the JIT-only
        // reflection link that Default may carry, so nothing here ever resolves through reflection.
        var options = new JsonSerializerOptions(DataProofsJsonOptions.Default) { TypeInfoResolver = RdfcJsonContext.Default };
        options.MakeReadOnly();
        return options;
    }
}
