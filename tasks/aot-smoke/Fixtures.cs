using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Jose;
using NetCrypto;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>Fixed inputs shared by every path: seed keys, timestamps, documents, and JSON helpers.</summary>
internal static class Fixtures
{
    public const string Created = "2026-01-01T00:00:00Z";
    public static readonly DateTimeOffset FixedTime = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    public const string Audience = "https://verifier.example.org";
    public const string Nonce = "n-aot-smoke-2026";

    public static readonly DefaultCryptoProvider Crypto = new();
    public static readonly DefaultKeyGenerator KeyGen = new();
    public static readonly JoseCryptoProvider JoseCrypto = new();

    // Deterministic key pairs from constant-filled seeds (the Fx.SeedKey idiom of the test suite).
    public static readonly KeyPair Ed = SeedKey(0x01, KeyType.Ed25519);
    public static readonly KeyPair Ed2 = SeedKey(0x02, KeyType.Ed25519);
    public static readonly KeyPair P256 = SeedKey(0x03, KeyType.P256);
    public static readonly KeyPair JweP256 = SeedKey(0x06, KeyType.P256);
    public static readonly KeyPair HolderP256 = SeedKey(0x08, KeyType.P256);
    public static readonly byte[] HmacKey = Fill(0x05);
    public static readonly byte[] SymKey = Fill(0x07);
    // The BLS12-381 G2 pair is derived lazily: a host without the BBS native library must not fail here.
    public static KeyPair Bbs() => SeedKey(0x04, KeyType.Bls12381G2);

    public static readonly byte[] Payload = "{\"sub\":\"did:example:subject\",\"scope\":\"read\"}"u8.ToArray();
    public static readonly byte[] Plaintext = "{\"msg\":\"the eagle has landed\",\"ts\":1767225600}"u8.ToArray();

    private const string CredentialJson =
        """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:issuer","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:example:subject","name":"Alice Example"}}""";

    private const string BbsCredentialJson =
        """{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"type":["VerifiableCredential","AlumniCredential"],"issuer":"https://vc.example/issuers/5678","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:example:abcdefgh","alumniOf":"The School of Examples","gpa":"4.0","favoriteColor":"purple"}}""";

    // An inline @context with a nested blank node, so RDFC-1.0 blank-node labeling (c14n*) is exercised.
    private const string InlineContextJson =
        """{"@context":{"name":"https://schema.org/name","knows":{"@id":"https://schema.org/knows","@type":"@id"},"friend":"https://schema.org/knows"},"@id":"did:example:alice","name":"Alice","knows":"did:example:bob","friend":{"name":"Carol"}}""";

    public static byte[] CredentialBytes => Encoding.UTF8.GetBytes(CredentialJson);
    public static JsonElement Credential() => Parse(CredentialJson);
    public static JsonElement BbsCredential() => Parse(BbsCredentialJson);
    public static JsonElement InlineContextDoc() => Parse(InlineContextJson);

    public static KeyPair SeedKey(byte fill, KeyType keyType) => KeyGen.FromPrivateKey(keyType, Fill(fill));
    private static byte[] Fill(byte value) => Enumerable.Repeat(value, 32).ToArray();

    public static string Vm(KeyPair key) => $"did:key:{key.MultibasePublicKey}#{key.MultibasePublicKey}";
    public static ISigner Signer(KeyPair key) => new KeyPairSigner(key, Crypto);
    public static PublicKeyMaterial Pk(KeyPair key) => PublicKeyMaterial.FromMultikey(key.MultibasePublicKey);
    public static Jwk PublicJwk(KeyPair key) => JwkConversion.ToPublicJwk(key.KeyType, key.PublicKey, Vm(key));

    public static DataIntegrityProof Proof(string cryptosuite, KeyPair key, string? type = null) => new()
    {
        Type = type ?? DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = cryptosuite,
        Created = Created,
        VerificationMethod = Vm(key),
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    public static readonly ProofVerificationOptions AssertionMethod = new() { ExpectedProofPurpose = ProofPurposes.AssertionMethod };

    /// <summary>A resolver listing every seed key under assertionMethod, controller = the did:key.</summary>
    public static StaticVerificationMethodResolver Resolver(params KeyPair[] keys) => new(keys.Select(k => new ResolvedVerificationMethod
    {
        Id = Vm(k),
        Controller = $"did:key:{k.MultibasePublicKey}",
        PublicKey = Pk(k),
        Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
        ControllerControlsMethod = true,
    }));

    // --- JSON helpers: typed-info only, never a reflection-based serializer overload ---

    public static JsonElement Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    public static string Compact(JsonElement element) => JsonSerializer.Serialize(element, AotSmokeJson.Element);
    public static JsonElement ToElement(JsonNode node) => JsonSerializer.SerializeToElement(node, AotSmokeJson.Node);
    public static JsonObject Wrap(JsonElement element) => JsonObject.Create(element)!;

    public static JsonElement Embed(JsonElement unsecured, DataIntegrityProof proof)
    {
        var node = Wrap(unsecured);
        node["proof"] = JsonSerializer.SerializeToNode(proof, AotSmokeJson.Proof);
        return ToElement(node);
    }

    public static (JsonElement Unsecured, DataIntegrityProof Proof) Split(JsonElement secured)
    {
        var proof = secured.GetProperty("proof").Deserialize(AotSmokeJson.Proof)!;
        var node = Wrap(secured);
        node.Remove("proof");
        return (ToElement(node), proof);
    }

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
    public static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
}

/// <summary>The gate: every expectation prints one line; the first failure exits 1.</summary>
internal static class Gate
{
    /// <summary>Expect a verified document; on failure the message carries every proof problem.</summary>
    public static void Expect(DocumentVerificationResult result, string what)
        => Expect(result.Verified, result.Verified ? what : $"{what} — {Describe(result)}");

    private static string Describe(DocumentVerificationResult result)
        => string.Join("; ", result.Problems.Concat(result.ProofResults.SelectMany(r => r.Problems))
            .Select(p => $"{p.Code}: {p.Message}"));

    public static int Verified { get; private set; }

    public static void Expect(bool condition, string what)
    {
        if (!condition)
        {
            Fail(what);
        }

        Verified++;
        Console.WriteLine($"  ok  {what}");
    }

    public static void Fail(string what)
    {
        Console.Error.WriteLine($"FAILED: {what}");
        Environment.Exit(1);
    }
}

/// <summary>The report file: a runtime block, a deterministic string map, and a map of artifact objects.</summary>
internal sealed class Report
{
    private readonly JsonObject _root;

    private Report(JsonObject root) => _root = root;

    public static Report New() => new(new JsonObject
    {
        ["runtime"] = new JsonObject(),
        ["deterministic"] = new JsonObject(),
        ["artifacts"] = new JsonObject(),
    });

    public static Report Load(string path)
    {
        var root = JsonNode.Parse(File.ReadAllText(path))?.AsObject() ?? throw new InvalidOperationException($"{path} is not a JSON object.");
        foreach (var section in new[] { "runtime", "deterministic", "artifacts" })
        {
            if (root[section] is not JsonObject)
            {
                Gate.Fail($"{path} has no '{section}' object");
            }
        }

        return new Report(root);
    }

    public JsonObject Runtime => _root["runtime"]!.AsObject();
    public JsonObject Deterministic => _root["deterministic"]!.AsObject();
    public JsonObject Artifacts => _root["artifacts"]!.AsObject();

    public void Det(string key, string value)
    {
        if (Deterministic.ContainsKey(key))
        {
            Gate.Fail($"deterministic key '{key}' recorded twice");
        }

        Deterministic[key] = value;
    }

    public string Det(string key)
        => Deterministic[key]?.GetValue<string>() ?? throw new InvalidOperationException($"report has no deterministic value '{key}'");

    public void Artifact(string name, JsonObject value) => Artifacts[name] = value;

    public bool HasArtifact(string name) => Artifacts.ContainsKey(name);

    public JsonObject Artifact(string name)
        => Artifacts[name]?.AsObject() ?? throw new InvalidOperationException($"report has no artifact '{name}'");

    public string ArtifactString(string name, string member)
        => Artifact(name)[member]?.GetValue<string>() ?? throw new InvalidOperationException($"artifact '{name}' has no '{member}'");

    public JsonElement ArtifactElement(string name, string member)
        => Fixtures.ToElement(Artifact(name)[member] ?? throw new InvalidOperationException($"artifact '{name}' has no '{member}'"));

    public void Save(string path)
    {
        var options = new JsonSerializerOptions(AotSmokeJson.Options) { WriteIndented = true };
        File.WriteAllText(path, _root.ToJsonString(options) + Environment.NewLine);
    }
}
