using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCid;
using NetCrypto;

namespace DataProofsDotnet.Rdfc.Tests.TestSupport;

/// <summary>
/// Shared fixture plumbing for the Rdfc tests: path resolution under the copied
/// <c>fixtures/</c> tree, multikey secret-key decoding, JSON helpers, and resolver builders.
/// Mirrors the Core test project's <c>Fx</c> so the RDFC suites are exercised through the
/// same consumer-facing pipeline shapes.
/// </summary>
internal static class Fx
{
    public static readonly DefaultCryptoProvider Crypto = new();
    public static readonly DefaultKeyGenerator KeyGen = new();

    // Secret-key multicodec values (multicodec registry).
    private const ulong Ed25519Priv = 0x1300;
    private const ulong P256Priv = 0x1306;
    private const ulong P384Priv = 0x1307;

    public static string PathOf(params string[] parts)
        => Path.Combine([AppContext.BaseDirectory, "fixtures", .. parts]);

    public static JsonElement Json(params string[] parts)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(PathOf(parts)));
        return document.RootElement.Clone();
    }

    public static string Text(params string[] parts) => File.ReadAllText(PathOf(parts)).Trim();

    public static byte[] HexBytes(params string[] parts) => Convert.FromHexString(Text(parts));

    /// <summary>Decodes a fixture's multibase/multicodec secret key into a NetCrypto key pair.</summary>
    public static KeyPair SecretKey(string secretKeyMultibase)
    {
        if (!Multibase.TryDecode(secretKeyMultibase, out var prefixed, out var encoding)
            || encoding != MultibaseEncoding.Base58Btc
            || !Multicodec.TryDecode(prefixed, out var codec, out var raw)
            || raw is null)
        {
            throw new InvalidOperationException("Fixture secret key is not a multicodec-prefixed base58-btc value.");
        }

        var keyType = codec switch
        {
            Ed25519Priv => KeyType.Ed25519,
            P256Priv => KeyType.P256,
            P384Priv => KeyType.P384,
            _ => throw new InvalidOperationException($"Unexpected fixture secret-key codec 0x{codec:X}."),
        };

        return KeyGen.FromPrivateKey(keyType, raw);
    }

    public static KeyPairSigner Signer(KeyPair keyPair) => new(keyPair, Crypto);

    public static string Compact(JsonElement element)
        => JsonSerializer.Serialize(element, DataProofsJsonOptions.Default);

    /// <summary>Applies a node-level mutation to a document and returns the new element.</summary>
    public static JsonElement Mutate(JsonElement element, Action<JsonObject> mutate)
    {
        var node = JsonObject.Create(element)!;
        mutate(node);
        return JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);
    }

    /// <summary>A single-method static resolver for a W3C <c>did:key</c>-style fixture method.</summary>
    public static StaticVerificationMethodResolver SingleMethodResolver(
        string verificationMethodId,
        string publicKeyMultibase,
        string relationship = ProofPurposes.AssertionMethod)
        => new(
        [
            new ResolvedVerificationMethod
            {
                Id = verificationMethodId,
                Controller = verificationMethodId.Split('#')[0],
                PublicKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase),
                Relationships = new HashSet<string>(StringComparer.Ordinal) { relationship },
                ControllerControlsMethod = true,
            },
        ]);

    /// <summary>The Multikey embedded in a <c>did:key</c> verification-method id (the fragment).</summary>
    public static string MultikeyOf(string didKeyVerificationMethod)
        => didKeyVerificationMethod.Split('#')[^1];
}
