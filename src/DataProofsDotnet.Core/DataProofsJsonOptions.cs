using System.Diagnostics.CodeAnalysis;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet;

/// <summary>
/// The shared <see cref="JsonSerializerOptions"/> used for every wire (de)serialization
/// performed by this library. Sign-time serialization and wire emission share these
/// options so that signed bytes always equal wire bytes.
/// </summary>
/// <remarks>
/// <para>
/// Metadata for this library's own types — <see cref="DataIntegrityProof"/>, <see cref="JsonObject"/>,
/// <see cref="JsonNode"/> and <see cref="JsonElement"/> — is source-generated, so the packages run unchanged in trimmed
/// and native-AOT applications and never reflect over their own models, whatever the host.
/// </para>
/// <para>
/// <b>Consumer types.</b> For any other type, <see cref="Default"/> falls back to reflection-based
/// metadata only when the host enables it (<see cref="JsonSerializer.IsReflectionEnabledByDefault"/>,
/// which is <c>true</c> in an ordinary JIT application), so existing JIT consumers see no change. In a
/// trimmed or native-AOT application — and in any project that sets <c>PublishAot</c>, where the SDK
/// turns that switch off even under <c>dotnet run</c> — a consumer type without source-generated
/// metadata fails with System.Text.Json's own <see cref="NotSupportedException"/>, which names the
/// type. Such consumers register the types they serialize in their own
/// <see cref="JsonSerializerContext"/>; <see cref="DataIntegrityProof"/> can be listed there directly
/// (its <c>previousProof</c> converter is public for that reason).
/// </para>
/// </remarks>
public static class DataProofsJsonOptions
{
    /// <summary>
    /// Spec-correct serializer options: no indentation, original member names preserved,
    /// <c>null</c> members omitted, and RFC 8785-compatible minimal string escaping
    /// (<see cref="JavaScriptEncoder.UnsafeRelaxedJsonEscaping"/> — the default encoder
    /// escapes <c>+ &lt; &gt; &amp; '</c>, which silently diverges canonical bytes from
    /// conformant peers). The instance is read-only. This library's types resolve through
    /// source-generated metadata; other types through reflection when the host enables it (see the
    /// type remarks).
    /// </summary>
    public static JsonSerializerOptions Default { get; } = Create();

    /// <summary>Metadata for <see cref="DataIntegrityProof"/>, bound to <see cref="Default"/>.</summary>
    internal static JsonTypeInfo<DataIntegrityProof> ProofTypeInfo { get; } = TypeInfo<DataIntegrityProof>();

    /// <summary>Metadata for <see cref="JsonObject"/>, bound to <see cref="Default"/>.</summary>
    internal static JsonTypeInfo<JsonObject> JsonObjectTypeInfo { get; } = TypeInfo<JsonObject>();

    /// <summary>Metadata for <see cref="JsonNode"/>, bound to <see cref="Default"/>.</summary>
    internal static JsonTypeInfo<JsonNode> JsonNodeTypeInfo { get; } = TypeInfo<JsonNode>();

    /// <summary>Metadata for <see cref="JsonElement"/>, bound to <see cref="Default"/>.</summary>
    internal static JsonTypeInfo<JsonElement> JsonElementTypeInfo { get; } = TypeInfo<JsonElement>();

    // GetTypeInfo(Type) is AOT-safe (no RequiresUnreferencedCode): it resolves through the options'
    // resolver chain, whose first link is the source-generated context, and returns metadata bound to
    // Default's wire settings. The cast is exact because the context resolves T to JsonTypeInfo<T>.
    private static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Default.GetTypeInfo(typeof(T));

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            TypeInfoResolver = DataProofsJsonContext.Default,
        };
        // The chain must be complete before the options freeze: a JsonSerializerContext bound to an
        // options instance, or MakeReadOnly(), both lock the resolver chain.
        AddReflectionFallbackForJitHosts(options);
        options.MakeReadOnly();
        return options;
    }

    // The ASP.NET Core pattern (Microsoft.AspNetCore.Http.Json.JsonOptions): the guard is the trimmer
    // feature switch JsonSerializerIsReflectionEnabledByDefault. Trimmed and native-AOT builds default it
    // to false, the trimmer substitutes the constant, and the branch — the reflection resolver with it —
    // is removed. A host can opt back in (JsonSerializerIsReflectionEnabledByDefault=true in a trimmed or
    // AOT build): that host has asked for reflection-based serialization of its own types, with the
    // trim and AOT caveats that come with it, exactly as for any JsonSerializerOptions it builds. The
    // library's own types resolve through the first link of the chain and never reach this one.
    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "Guarded by the JsonSerializerIsReflectionEnabledByDefault feature switch, false by default in trimmed and native-AOT builds, where the trimmer removes the branch. A host that sets it to true has opted into reflection-based serialization for its own types; the library's types never resolve through this resolver.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "Same feature-switch guard as IL2026: removed by default in native-AOT builds; present only when the host opts back into reflection-based serialization, for its own types.")]
    private static void AddReflectionFallbackForJitHosts(JsonSerializerOptions options)
    {
        if (JsonSerializer.IsReflectionEnabledByDefault)
        {
            options.TypeInfoResolverChain.Add(new DefaultJsonTypeInfoResolver());
        }
    }
}
