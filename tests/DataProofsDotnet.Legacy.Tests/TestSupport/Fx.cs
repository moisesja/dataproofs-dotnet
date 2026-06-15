using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

namespace DataProofsDotnet.Legacy.Tests.TestSupport;

/// <summary>
/// Shared fixture plumbing for the legacy Linked-Data-Signature tests: fixture path
/// resolution under the copied <c>fixtures/</c> tree, deterministic seed keys, signer and
/// JSON helpers, and a single-method resolver. Mirrors the sibling test projects' <c>Fx</c>.
/// </summary>
internal static class Fx
{
    public static readonly DefaultCryptoProvider Crypto = new();
    public static readonly DefaultKeyGenerator KeyGen = new();

    public static string PathOf(params string[] parts)
        => Path.Combine([AppContext.BaseDirectory, "fixtures", .. parts]);

    public static JsonElement Json(params string[] parts)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(PathOf(parts)));
        return document.RootElement.Clone();
    }

    /// <summary>A deterministic key pair from a constant-filled seed (constructed-fixture keys).</summary>
    public static KeyPair SeedKey(byte fill, KeyType keyType = KeyType.Ed25519)
        => KeyGen.FromPrivateKey(keyType, Enumerable.Repeat(fill, keyType == KeyType.P384 ? 48 : 32).ToArray());

    /// <summary>The exact fixed Ed25519 seed (bytes 1..32) zcap derives its golden vector from.</summary>
    public static KeyPair GoldenSeedKey()
        => KeyGen.FromPrivateKey(KeyType.Ed25519, Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());

    public static KeyPairSigner Signer(KeyPair keyPair) => new(keyPair, Crypto);

    /// <summary>Serializes a node to a <see cref="JsonElement"/> using the stack's canonical options.</summary>
    public static JsonElement ToElement(JsonNode node)
        => JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);

    /// <summary>Applies a node-level mutation to a document and returns the new element.</summary>
    public static JsonElement Mutate(JsonElement element, Action<JsonObject> mutate)
    {
        var node = JsonObject.Create(element)!;
        mutate(node);
        return JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);
    }

    /// <summary>A single-method resolver for a <c>did:key</c>-style fixture method.</summary>
    public static StaticVerificationMethodResolver SingleMethodResolver(
        string verificationMethodId,
        PublicKeyMaterial publicKey,
        string relationship = ProofPurposes.AssertionMethod)
        => new(
        [
            new ResolvedVerificationMethod
            {
                Id = verificationMethodId,
                Controller = verificationMethodId.Split('#')[0],
                PublicKey = publicKey,
                Relationships = new HashSet<string>(StringComparer.Ordinal) { relationship },
                ControllerControlsMethod = true,
            },
        ]);
}
