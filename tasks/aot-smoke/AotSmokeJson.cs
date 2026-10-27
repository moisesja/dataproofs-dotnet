using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>
/// The downstream-consumer scenario (zcap-dotnet#154): an application's own source-generated context
/// that lists <see cref="DataIntegrityProof"/> directly. This compiles only because
/// <c>PreviousProofReferenceJsonConverter</c> is public; it is the proof that a trimmed or native-AOT
/// consumer can (de)serialize the library's proof model without any reflection fallback.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(DataIntegrityProof))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(JsonElement))]
internal sealed partial class AotSmokeJsonContext : JsonSerializerContext;

/// <summary>
/// The consumer context bound to a copy of the library's wire options, so bytes produced here carry
/// the same encoder and null handling as the library's own output. Every serializer call in this
/// tool goes through one of these typed infos — never a reflection-based overload.
/// </summary>
internal static class AotSmokeJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    public static JsonTypeInfo<DataIntegrityProof> Proof { get; } = TypeInfo<DataIntegrityProof>();
    public static JsonTypeInfo<JsonNode> Node { get; } = TypeInfo<JsonNode>();
    public static JsonTypeInfo<JsonElement> Element { get; } = TypeInfo<JsonElement>();

    private static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Options.GetTypeInfo(typeof(T));

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions(DataProofsJsonOptions.Default) { TypeInfoResolver = AotSmokeJsonContext.Default };
        options.MakeReadOnly();
        return options;
    }
}
