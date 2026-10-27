using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet.Legacy.DataIntegrity;

/// <summary>
/// Source-generated System.Text.Json metadata for the types this package serializes (issue #27): the
/// proof model, the <see cref="JsonObject"/> the JCS variant nests the proof configuration into, and
/// the <see cref="JsonNode"/> that null-stripping yields. Core's context is internal to Core; each
/// package declares what it serializes, and a type missing here fails fast in every host instead of
/// falling back to reflection.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(DataIntegrityProof))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonNode))]
internal sealed partial class LegacyJsonContext : JsonSerializerContext;

/// <summary>
/// Typed metadata accessors for <see cref="LegacyJsonContext"/>, bound to a read-only copy of
/// <see cref="DataProofsJsonOptions.Default"/>: the same encoder, null handling and indentation, so
/// the bytes equal Core's — load-bearing for the cross-stack byte identity with zcap-dotnet.
/// </summary>
internal static class LegacyJson
{
    /// <summary>The package's wire options: <see cref="DataProofsJsonOptions.Default"/> resolved by <see cref="LegacyJsonContext"/>.</summary>
    public static JsonSerializerOptions Options { get; } = Create();

    /// <summary>Metadata for <see cref="DataIntegrityProof"/>, bound to <see cref="Options"/>.</summary>
    public static JsonTypeInfo<DataIntegrityProof> ProofTypeInfo { get; } = TypeInfo<DataIntegrityProof>();

    /// <summary>Metadata for <see cref="JsonObject"/>, bound to <see cref="Options"/>.</summary>
    public static JsonTypeInfo<JsonObject> JsonObjectTypeInfo { get; } = TypeInfo<JsonObject>();

    /// <summary>Metadata for <see cref="JsonNode"/>, bound to <see cref="Options"/>.</summary>
    public static JsonTypeInfo<JsonNode> JsonNodeTypeInfo { get; } = TypeInfo<JsonNode>();

    private static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Options.GetTypeInfo(typeof(T));

    private static JsonSerializerOptions Create()
    {
        // The copy constructor carries every wire setting; replacing the resolver drops the JIT-only
        // reflection link that Default may carry, so nothing here ever resolves through reflection.
        var options = new JsonSerializerOptions(DataProofsJsonOptions.Default) { TypeInfoResolver = LegacyJsonContext.Default };
        options.MakeReadOnly();
        return options;
    }
}
