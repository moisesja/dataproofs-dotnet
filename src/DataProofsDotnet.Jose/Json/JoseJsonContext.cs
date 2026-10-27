using System.Text.Json.Serialization;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.Json;

/// <summary>
/// Source-generated System.Text.Json metadata for every type this package serializes, so the
/// package runs unchanged in trimmed and native-AOT applications (issue #27). Installed as the
/// resolver of <see cref="JoseJson.Default"/>; the serializer calls go through the typed
/// <see cref="System.Text.Json.Serialization.Metadata.JsonTypeInfo{T}"/> accessors on
/// <see cref="JoseJson"/>, which are bound to those options and so carry the relaxed encoder and
/// the duplicate-member rejection. Metadata-only generation keeps the generated code to what the
/// serializer actually uses.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(JwsProtectedHeader))]
[JsonSerializable(typeof(JweProtectedHeader))]
[JsonSerializable(typeof(Jwk))]
[JsonSerializable(typeof(string))]
internal sealed partial class JoseJsonContext : JsonSerializerContext;
