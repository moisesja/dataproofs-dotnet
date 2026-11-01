using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;

// Example service profile for small credentials, not library-wide defaults or a latency guarantee.
// Apply MaxBodyBytes to the decompressed request stream before buffering it, too.
internal static class VerificationAdmission
{
    public const int MaxBodyBytes = 32 * 1024;
    public const int MaxProofCharacters = 16 * 1024;
    private const int MaxArrayItems = 128;
    private const int MaxNodes = 2048;
    private static readonly SemaphoreSlim Slots = new(2, 2); // process-wide, no waiting queue
    private static readonly DataIntegrityProofPipeline Pipeline = new(CryptosuiteRegistry.CreateDefault().AddBbs2023());
    private static readonly ProofVerificationOptions Options = new()
    {
        ExpectedProofPurpose = ProofPurposes.AssertionMethod,
        KnownContexts = ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
    };

    // The default suite uses pinned offline contexts. The caller supplies an already trusted key;
    // issuer authorization and presentation/replay policy remain the host's responsibility.
    public static bool TryVerify(ReadOnlyMemory<byte> body, PublicKeyMaterial key, out DocumentVerificationResult? result)
    {
        result = null;
        if (body.Length > MaxBodyBytes || !Slots.Wait(0)) return false;
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            var nodes = 0;
            if (!WithinShape(root, ref nodes) || root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("proof", out var proof) || proof.ValueKind != JsonValueKind.Object
                || !proof.TryGetProperty("cryptosuite", out var suite) || suite.ValueKind != JsonValueKind.String
                || suite.GetString() != Bbs2023Cryptosuite.CryptosuiteName
                || !proof.TryGetProperty("proofValue", out var value) || value.ValueKind != JsonValueKind.String
                || value.GetString()!.Length > MaxProofCharacters)
            {
                return false;
            }

            result = Pipeline.Verify(root, key, Options);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        finally
        {
            Slots.Release();
        }
    }

    private static bool WithinShape(JsonElement node, ref int nodes)
    {
        if (++nodes > MaxNodes) return false;
        if (node.ValueKind == JsonValueKind.Array)
        {
            if (node.GetArrayLength() > MaxArrayItems) return false;
            foreach (var item in node.EnumerateArray())
                if (!WithinShape(item, ref nodes)) return false;
        }
        else if (node.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in node.EnumerateObject())
                if (!WithinShape(property.Value, ref nodes)) return false;
        }
        return true;
    }
}
