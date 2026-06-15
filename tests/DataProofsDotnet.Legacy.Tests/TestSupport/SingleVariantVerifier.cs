using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Rdfc;
using NetCid;
using NetCrypto;

namespace DataProofsDotnet.Legacy.Tests.TestSupport;

/// <summary>
/// A STRICT single-variant Ed25519Signature2020 verifier used to prove variant isolation: it
/// honors EXACTLY one canonicalization variant with NO fallback, reproducing the engine's
/// signing-input construction for that variant and checking the Ed25519 signature directly.
/// A proof built under the other variant must fail here (the whole point of the isolation test).
/// </summary>
internal sealed class SingleVariantVerifier(LegacyCanonicalization variant)
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private readonly RdfcDocumentCanonicalizer _rdfc = new();

    /// <summary>Verifies the document's single embedded proof under this verifier's one variant.</summary>
    public bool Verify(JsonElement securedDocument, PublicKeyMaterial publicKey)
    {
        if (securedDocument.ValueKind != JsonValueKind.Object
            || !securedDocument.TryGetProperty("proof", out var proofElement))
        {
            return false;
        }

        var proof = proofElement.Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        if (!Multibase.TryDecode(proof.ProofValue ?? string.Empty, out var signature, out var encoding)
            || encoding != MultibaseEncoding.Base58Btc)
        {
            return false;
        }

        // The unsecured document is the secured document minus its proof member (what the
        // pipeline hands the suite, and what the engine canonicalizes).
        var unsecuredNode = JsonObject.Create(securedDocument)!;
        unsecuredNode.Remove("proof");
        var unsecured = JsonSerializer.SerializeToElement(unsecuredNode, DataProofsJsonOptions.Default);

        var proofConfig = proof with { Cryptosuite = null, ProofValue = null };
        var signingInput = variant == LegacyCanonicalization.Rdfc
            ? BuildRdfc(unsecured, proofConfig)
            : BuildJcs(unsecured, proofConfig);

        return Crypto.Verify(publicKey.KeyType, publicKey.KeyBytes.Span, signingInput, signature);
    }

    private static byte[] BuildJcs(JsonElement unsecured, DataIntegrityProof proofConfig)
    {
        var docNode = JsonObject.Create(unsecured)!;
        docNode["proof"] = JsonSerializer.SerializeToNode(proofConfig, DataProofsJsonOptions.Default);
        var combined = JsonSerializer.SerializeToElement(docNode, DataProofsJsonOptions.Default);
        return JcsCanonicalizer.Canonicalize(combined);
    }

    private byte[] BuildRdfc(JsonElement unsecured, DataIntegrityProof proofConfig)
    {
        var withContext = unsecured.TryGetProperty("@context", out var ctx)
            ? proofConfig with { Context = ctx.Clone() }
            : proofConfig;

        var proofOptionsHash = Hash.Sha256(_rdfc.CanonicalizeJsonLd(
            JsonSerializer.SerializeToElement(withContext, DataProofsJsonOptions.Default),
            RdfCanonicalizationHashAlgorithm.Sha256));
        var documentHash = Hash.Sha256(_rdfc.CanonicalizeJsonLd(
            unsecured, RdfCanonicalizationHashAlgorithm.Sha256));

        return [.. proofOptionsHash, .. documentHash];
    }
}
