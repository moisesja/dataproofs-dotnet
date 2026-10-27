using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet;

/// <summary>
/// Source-generated System.Text.Json metadata for every type this package serializes, so the
/// package runs unchanged in trimmed and native-AOT applications (issue #27). The context is only
/// a metadata provider: it is installed as the <see cref="JsonSerializerOptions.TypeInfoResolver"/>
/// of <see cref="DataProofsJsonOptions.Default"/>, and every serializer call in this package goes
/// through a <see cref="System.Text.Json.Serialization.Metadata.JsonTypeInfo{T}"/> obtained from
/// those options, which carry the wire settings (encoder, null handling). Metadata-only generation
/// keeps the generated code to what the serializer actually uses.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(DataIntegrityProof))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(JsonElement))]
internal sealed partial class DataProofsJsonContext : JsonSerializerContext;
