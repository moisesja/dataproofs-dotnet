using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.Internal;
using NetCrypto;

namespace DataProofsDotnet.Rdfc.DataIntegrity;

/// <summary>
/// The <c>bbs-2023</c> selective-disclosure cryptosuite of Data Integrity BBS Cryptosuites
/// v1.0 (FR-12; CRD snapshot 2026-04-07). Unlike the deterministic-signature RDFC suites,
/// <c>bbs-2023</c> has a three-stage lifecycle that does not fit a plain sign/verify
/// <see cref="ICryptosuite"/>:
/// <list type="number">
/// <item><description><b>Base proof</b> (issuer): RDFC-1.0 canonicalize, HMAC-shuffle the
/// blank-node labels (FR-12), partition the N-Quads into a mandatory group (addressed by
/// JSON Pointers) and a selectively-disclosable remainder, BBS-sign the ordered messages,
/// and pack <c>bbsSignature</c>, <c>bbsHeader</c>, issuer <c>publicKey</c>, <c>hmacKey</c>,
/// and the mandatory pointers into a CBOR <c>proofValue</c> (<c>u2V0C…</c>).</description></item>
/// <item><description><b>Derive</b> (holder): re-partition against a selective-pointer set,
/// BBS-derive a zero-knowledge proof revealing only mandatory + selected messages, and emit
/// a reveal document with a derived CBOR <c>proofValue</c> (<c>u2V0D…</c>).</description></item>
/// <item><description><b>Verify</b> (verifier): reconstruct the disclosed messages from the
/// reveal document and the derived proof's label map, then BBS-verify the proof.</description></item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// All cryptography routes through NetCrypto: BBS via <see cref="IBbsCryptoProvider"/>
/// (<see cref="BbsCiphersuite.Bls12381Sha256"/>), HMAC via the SHA-256-composed
/// <see cref="HmacSha256"/>, and multibase via NetCid. The CBOR coupling is contained in
/// <see cref="Bbs2023ProofValue"/>; no CBOR, dotNetRDF, or Newtonsoft type appears on this
/// type's surface (AC-7).
/// </para>
/// <para>
/// <b>Capability behavior (AC-6):</b> construction always succeeds; the lifecycle methods
/// throw NetCrypto's <see cref="BbsUnavailableException"/> when the BBS native library is
/// absent on the host. <see cref="IsAvailable"/> reports the capability without throwing.
/// </para>
/// <para>
/// <b>⚠ EXPERIMENTAL — mandatory disclosure is NOT cryptographically enforced (security
/// limitation).</b> The W3C suite binds the BBS <c>header</c> parameter to
/// <c>bbsHeader = proofHash ‖ mandatoryHash</c> at both sign and proof-generation time; that
/// binding is what forces a holder to keep every issuer-designated mandatory statement in a
/// presentation. NetCrypto v1's <see cref="IBbsCryptoProvider"/> does not surface the BBS
/// <c>header</c> argument (it is hardcoded empty), so this suite cannot bind the mandatory
/// group. <b>Consequence:</b> a malicious holder can derive a proof that omits a mandatory
/// statement and it will still verify. Do not rely on the mandatory-disclosure guarantee until
/// NetCrypto exposes the header (tracked: <c>docs/dependencies/netcrypto-bbs-header.md</c>,
/// upstream <c>moisesja/crypto-dotnet#2</c>); treat <c>bbs-2023</c> as experimental — it is
/// pinned to a Candidate Recommendation <em>draft</em> (PRD §12.3). The honest create → derive →
/// verify lifecycle is otherwise correct (BBS proves the revealed messages were issuer-signed).
/// </para>
/// <para>
/// As a further consequence, the suite's <c>proofValue</c> bytes are not interchangeable with
/// W3C reference vectors generated with a non-empty BBS header (those are validated structurally
/// in the test suite). The CBOR framing and proof-value headers match the reference wire form;
/// the blank-node relabeling keys the HMAC on document-order-stable skolem identifiers (see the
/// partition note below) rather than canonical <c>c14n*</c> labels, which keeps the create →
/// derive → verify partition exactly consistent across the lifecycle without depending on
/// canonical-label alignment between sub-documents. Immutable and thread-safe after construction
/// (NFR-4).
/// </para>
/// </remarks>
public sealed class Bbs2023Cryptosuite : ICryptosuite
{
    /// <summary>The cryptosuite identifier, <c>bbs-2023</c>.</summary>
    public const string CryptosuiteName = "bbs-2023";

    private static readonly DefaultKeyGenerator KeyGenerator = new();

    private readonly IRdfCanonicalizer _canonicalizer;
    private readonly IBbsCryptoProvider _bbs;

    /// <summary>Creates the suite over the offline-default RDFC canonicalizer (FR-10).</summary>
    public Bbs2023Cryptosuite()
        : this(new RdfcDocumentCanonicalizer())
    {
    }

    /// <summary>Creates the suite over the given RDFC canonicalizer.</summary>
    public Bbs2023Cryptosuite(IRdfCanonicalizer canonicalizer)
    {
        ArgumentNullException.ThrowIfNull(canonicalizer);
        _canonicalizer = canonicalizer;
        _bbs = new DefaultBbsCryptoProvider(BbsCiphersuite.Bls12381Sha256);
    }

    /// <inheritdoc />
    public string Name => CryptosuiteName;

    /// <summary>
    /// Whether the BBS native library is usable on this host. When <c>false</c>, the
    /// lifecycle methods throw <see cref="BbsUnavailableException"/>; registration and
    /// construction still succeed (AC-6).
    /// </summary>
    public bool IsAvailable => _bbs.IsAvailable;

    /// <summary>
    /// Not supported: <c>bbs-2023</c> base proofs require an ordered BBS multi-message
    /// signing key, not a single-message <see cref="ISigner"/>. Use
    /// <see cref="CreateBaseProofAsync"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public Task<DataIntegrityProof> CreateProofAsync(
        JsonElement unsecuredDocument,
        DataIntegrityProof proofOptions,
        ISigner signer,
        CancellationToken cancellationToken = default)
        => throw new NotSupportedException(
            "bbs-2023 base proofs are created with CreateBaseProofAsync (an ordered BBS key), not a single-message ISigner.");

    /// <summary>
    /// Creates a <c>bbs-2023</c> <b>base proof</b> over <paramref name="unsecuredDocument"/>
    /// (issuer side, spec §3.4.1). The mandatory N-Quad group is addressed by
    /// <paramref name="mandatoryPointers"/>; everything else is selectively disclosable by a
    /// holder via <see cref="DeriveProof"/>.
    /// </summary>
    /// <param name="unsecuredDocument">The JSON-LD object to secure.</param>
    /// <param name="proofOptions">The proof options (type <c>DataIntegrityProof</c>,
    /// cryptosuite <c>bbs-2023</c>); no <c>proofValue</c>.</param>
    /// <param name="bbsPrivateKey">The issuer's 32-byte BLS12-381-G2 BBS private key.</param>
    /// <param name="hmacKey">The per-credential HMAC key used to shuffle blank-node labels.</param>
    /// <param name="mandatoryPointers">RFC 6901 JSON Pointers selecting the always-revealed group.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <returns>The completed base proof including its <c>u2V0C…</c> <c>proofValue</c>.</returns>
    /// <exception cref="ProofGenerationException">The options or document are invalid for this suite.</exception>
    /// <exception cref="BbsUnavailableException">The BBS native library is unavailable.</exception>
    public Task<DataIntegrityProof> CreateBaseProofAsync(
        JsonElement unsecuredDocument,
        DataIntegrityProof proofOptions,
        ReadOnlyMemory<byte> bbsPrivateKey,
        ReadOnlyMemory<byte> hmacKey,
        IReadOnlyList<string> mandatoryPointers,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proofOptions);
        ArgumentNullException.ThrowIfNull(mandatoryPointers);
        ValidateProofOptions(proofOptions);

        if (unsecuredDocument.ValueKind != JsonValueKind.Object)
        {
            throw new ProofGenerationException("The document to secure must be a JSON object.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var publicKey = KeyGenerator.FromPrivateKey(KeyType.Bls12381G2, bbsPrivateKey.Span).PublicKey;

        var proofConfig = BuildProofConfig(unsecuredDocument, proofOptions);
        var transformed = Transform(unsecuredDocument, hmacKey.Span, mandatoryPointers);

        var proofHash = HashProofConfig(proofConfig);
        var mandatoryHash = HashMandatory(transformed.Mandatory.Values);
        var bbsHeader = Concat(proofHash, mandatoryHash);

        // BBS messages are ALL the relabeled N-Quads in canonical order. The W3C suite binds
        // the mandatory group through the BBS header (proofHash ‖ mandatoryHash); NetCrypto's
        // IBbsCryptoProvider v1 does not surface that header, so to keep the mandatory group
        // cryptographically bound (tampering a mandatory statement MUST fail verification) the
        // mandatory statements are signed as always-disclosed messages alongside the
        // selectively-disclosable ones. (See the type's BBS-header remarks.)
        var messages = transformed.NQuads.Select(nq => Encoding.UTF8.GetBytes(nq)).ToList();
        var bbsSignature = _bbs.Sign(bbsPrivateKey.Span, messages);

        var proofValue = Bbs2023ProofValue.SerializeBaseProof(
            bbsSignature, bbsHeader, publicKey, hmacKey.Span, mandatoryPointers);

        return Task.FromResult(proofConfig with { ProofValue = proofValue });
    }

    /// <summary>
    /// Derives a <c>bbs-2023</c> reveal document (holder side, spec §3.4.6): from a document
    /// carrying a base proof, discloses the mandatory group plus the values addressed by
    /// <paramref name="selectivePointers"/>, replacing the base proof with a derived proof.
    /// </summary>
    /// <param name="securedBaseDocument">The document secured with a <c>bbs-2023</c> base proof.</param>
    /// <param name="selectivePointers">RFC 6901 JSON Pointers selecting additional values to reveal.</param>
    /// <param name="presentationHeader">The holder's presentation header (binds the derived proof).</param>
    /// <returns>The reveal document carrying the <c>u2V0D…</c> derived proof.</returns>
    /// <exception cref="ProofGenerationException">The base document or pointers are invalid.</exception>
    /// <exception cref="BbsUnavailableException">The BBS native library is unavailable.</exception>
    public JsonElement DeriveProof(
        JsonElement securedBaseDocument,
        IReadOnlyList<string> selectivePointers,
        ReadOnlyMemory<byte> presentationHeader)
    {
        ArgumentNullException.ThrowIfNull(selectivePointers);
        if (securedBaseDocument.ValueKind != JsonValueKind.Object)
        {
            throw new ProofGenerationException("The secured base document must be a JSON object.");
        }

        var (baseProof, unsecured) = SplitProof(securedBaseDocument);
        Bbs2023ProofValue.BaseProofComponents components;
        try
        {
            components = Bbs2023ProofValue.ParseBaseProof(baseProof.ProofValue
                ?? throw new ProofGenerationException("The base proof carries no proofValue."));
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new ProofGenerationException("The base proofValue is not a valid bbs-2023 base proof.", ex);
        }

        var combinedPointers = components.MandatoryPointers.Concat(selectivePointers).ToList();
        var disclosure = CreateDisclosureData(
            unsecured, components, combinedPointers, presentationHeader.Span);

        // Build the reveal document: the JSON-LD selection over the combined pointers,
        // re-secured with the derived proof carrying the same proof options.
        var revealDocument = (JsonObject)disclosure.RevealDocument;
        var derivedProofValue = Bbs2023ProofValue.SerializeDerivedProof(
            disclosure.BbsProof, disclosure.LabelMap, disclosure.MandatoryIndexes,
            disclosure.SelectiveIndexes, presentationHeader.Span);

        var derivedProof = baseProof with { ProofValue = derivedProofValue };
        revealDocument["proof"] = JsonSerializer.SerializeToNode(derivedProof, DataProofsJsonOptions.Default);

        return JsonSerializer.SerializeToElement(revealDocument, DataProofsJsonOptions.Default);
    }

    /// <summary>
    /// Verifies a <c>bbs-2023</c> <b>derived</b> proof (verifier side, spec §3.4.8). The
    /// pipeline calls this for any <c>bbs-2023</c> proof; a base proof presented for
    /// verification is rejected (only derived proofs are verifiable). Invalid proofs produce
    /// failed results, never exceptions.
    /// </summary>
    public ProofVerificationResult VerifyProof(
        JsonElement unsecuredDocument,
        DataIntegrityProof proof,
        PublicKeyMaterial publicKey)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(publicKey);

        try
        {
            if (unsecuredDocument.ValueKind != JsonValueKind.Object)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The reveal document must be a JSON object.", proof);
            }

            if (!string.Equals(proof.Type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal)
                || !string.Equals(proof.Cryptosuite, Name, StringComparison.Ordinal))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    $"The proof type/cryptosuite is not supported by the {Name} cryptosuite.", proof);
            }

            if (publicKey.KeyType != KeyType.Bls12381G2)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    "bbs-2023 requires a BLS12-381-G2 verification key.", proof);
            }

            if (string.IsNullOrEmpty(proof.ProofValue))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof carries no proofValue.", proof);
            }

            Bbs2023ProofValue.DerivedProofComponents components;
            try
            {
                components = Bbs2023ProofValue.ParseDerivedProof(proof.ProofValue);
            }
            catch (Exception ex) when (ex is FormatException or ArgumentException)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    "The proofValue is not a valid bbs-2023 derived proof.", proof);
            }

            var proofConfig = proof with { ProofValue = null };
            if (proofConfig.Context is null && unsecuredDocument.TryGetProperty("@context", out var docContext))
            {
                proofConfig = proofConfig with { Context = docContext.Clone() };
            }

            var disclosed = CreateVerifyData(unsecuredDocument, components);

            var revealedMessages = disclosed.Messages.Select(nq => Encoding.UTF8.GetBytes(nq)).ToList();
            var verified = _bbs.VerifyProof(
                publicKey.KeyBytes.Span,
                components.BbsProof,
                revealedMessages,
                disclosed.RevealedIndexes,
                components.PresentationHeader);

            return verified
                ? ProofVerificationResult.Success(proof)
                : ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The BBS derived proof did not verify.", proof);
        }
        catch (BbsUnavailableException)
        {
            // Capability faults propagate (a verifier with no BBS cannot make a verdict).
            throw;
        }
        catch (Exception ex)
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError,
                $"Verification failed unexpectedly ({ex.GetType().Name}).", proof);
        }
    }

    // ---- spec sub-algorithms (canonicalizeAndGroup family, §3.4.16 + DI-ECDSA primitives) ----
    //
    // The group partition is made label-stable by SKOLEMIZATION: blank nodes are replaced by
    // urn:bnid:_:b* URIs in document order BEFORE any selection, so a selected sub-document's
    // RDF nodes keep the identity they had in the whole document. Canonicalizing the skolemized
    // document then yields only named nodes (no canonical blank-node renaming), and the
    // deskolemized N-Quads carry the stable b* identifiers. The HMAC label map (FR-12) keys on
    // those stable identifiers and shuffles them, so every group's relabeled N-Quads are an
    // exact string-subset of the whole document's.

    private readonly record struct TransformResult(
        IReadOnlyDictionary<string, string> LabelMap,
        IReadOnlyList<string> NQuads,
        GroupResult Mandatory,
        GroupResult NonMandatory,
        JsonObject SkolemizedDocument);

    private readonly record struct GroupResult(IReadOnlyList<int> Indexes, IReadOnlyList<string> Values);

    // transformation (§3.4.2): skolemize, canonicalize, deskolemize, HMAC-shuffle the stable
    // blank-node ids, relabel and sort, then partition the relabeled N-Quads into the mandatory
    // group (matched against the skolemized mandatory selection) and the non-mandatory remainder.
    private TransformResult Transform(
        JsonElement document, ReadOnlySpan<byte> hmacKey, IReadOnlyList<string> mandatoryPointers)
    {
        var skolemized = JsonLdSkolemizer.Skolemize(document);
        var stableNQuads = SkolemizedToStableNQuads(skolemized);

        var labelMap = BlankNodeLabels.CreateHmacIdLabelMap(stableNQuads, hmacKey);
        var nquads = BlankNodeLabels.RelabelAndSort(stableNQuads, labelMap);

        var mandatoryMatches = SelectionNQuads(skolemized, mandatoryPointers, labelMap);

        var mandatoryIndexes = new List<int>();
        var mandatoryValues = new List<string>();
        var nonMandatoryIndexes = new List<int>();
        var nonMandatoryValues = new List<string>();
        for (var i = 0; i < nquads.Count; i++)
        {
            if (mandatoryMatches.Contains(nquads[i]))
            {
                mandatoryIndexes.Add(i);
                mandatoryValues.Add(nquads[i]);
            }
            else
            {
                nonMandatoryIndexes.Add(i);
                nonMandatoryValues.Add(nquads[i]);
            }
        }

        return new TransformResult(
            labelMap, nquads,
            new GroupResult(mandatoryIndexes, mandatoryValues),
            new GroupResult(nonMandatoryIndexes, nonMandatoryValues),
            skolemized);
    }

    private readonly record struct DisclosureData(
        byte[] BbsProof,
        IReadOnlyDictionary<string, string> LabelMap,
        IReadOnlyList<int> MandatoryIndexes,
        IReadOnlyList<int> SelectiveIndexes,
        JsonNode RevealDocument);

    // createDisclosureData (§3.4.6): recompute the partition over the base document, identify
    // which non-mandatory messages the combined pointers disclose, BBS-derive a proof over the
    // non-mandatory message list revealing exactly those, and select the reveal document over
    // the combined pointers (carrying the stable skolem ids so the verifier reconstructs labels).
    private DisclosureData CreateDisclosureData(
        JsonElement document,
        Bbs2023ProofValue.BaseProofComponents baseComponents,
        IReadOnlyList<string> combinedPointers,
        ReadOnlySpan<byte> presentationHeader)
    {
        var transformed = Transform(document, baseComponents.HmacKey, baseComponents.MandatoryPointers);

        // Selective indexes: positions in the FULL relabeled N-Quad list of the non-mandatory
        // statements the combined pointers disclose.
        var combinedMatches = SelectionNQuads(transformed.SkolemizedDocument, combinedPointers, transformed.LabelMap);
        var mandatorySet = new HashSet<int>(transformed.Mandatory.Indexes);
        var selectiveIndexes = new List<int>();
        for (var i = 0; i < transformed.NQuads.Count; i++)
        {
            if (!mandatorySet.Contains(i) && combinedMatches.Contains(transformed.NQuads[i]))
            {
                selectiveIndexes.Add(i);
            }
        }

        // Reveal the mandatory group AND the selected statements (ascending full-list order).
        var revealedIndexes = transformed.Mandatory.Indexes.Concat(selectiveIndexes).Distinct().OrderBy(x => x).ToList();
        var messages = transformed.NQuads.Select(nq => Encoding.UTF8.GetBytes(nq)).ToList();
        var bbsProof = _bbs.DeriveProof(
            baseComponents.PublicKey, baseComponents.BbsSignature, messages, revealedIndexes, presentationHeader);

        // Select the reveal document on the SKOLEMIZED document so it carries the stable
        // urn:bnid ids; the verifier deskolemizes + relabels with the same labelMap.
        var revealDocument = JsonPointer.SelectJsonLd(
                JsonSerializer.SerializeToElement(transformed.SkolemizedDocument, DataProofsJsonOptions.Default),
                combinedPointers)
            ?? throw new ProofGenerationException("The selective disclosure produced an empty reveal document.");

        return new DisclosureData(
            bbsProof, transformed.LabelMap, transformed.Mandatory.Indexes, selectiveIndexes, revealDocument);
    }

    private readonly record struct VerifyData(IReadOnlyList<string> Messages, IReadOnlyList<int> RevealedIndexes);

    // createVerifyData (§3.4.8): the reveal document carries stable skolem ids; canonicalize,
    // deskolemize, relabel via the derived proof's labelMap and sort to recover the disclosed
    // N-Quads — these are exactly the revealed BBS messages. Their original full-list indexes
    // are the union of the mandatory and selective index sets, ascending.
    private VerifyData CreateVerifyData(JsonElement revealDocument, Bbs2023ProofValue.DerivedProofComponents components)
    {
        var stable = SkolemizedToStableNQuads(JsonLdSkolemizer.Skolemize(revealDocument));
        var disclosedMessages = BlankNodeLabels.RelabelAndSort(stable, components.LabelMap);

        var revealedIndexes = components.MandatoryIndexes
            .Concat(components.SelectiveIndexes)
            .Distinct()
            .OrderBy(x => x)
            .ToList();

        return new VerifyData(disclosedMessages, revealedIndexes);
    }

    // Skolemize → canonicalize (only named nodes survive) → deskolemize back to stable _:b*
    // blank-node labels. The result is the document's N-Quads with document-order-stable ids.
    private IReadOnlyList<string> SkolemizedToStableNQuads(JsonObject skolemized)
    {
        var element = JsonSerializer.SerializeToElement(skolemized, DataProofsJsonOptions.Default);
        var canonical = CanonicalNQuadLines(element);
        var deskolemized = JsonLdSkolemizer.Deskolemize(canonical);
        var sorted = deskolemized.ToList();
        sorted.Sort(StringComparer.Ordinal);
        return sorted;
    }

    private IReadOnlyList<string> CanonicalNQuadLines(JsonElement document)
    {
        byte[] canonical;
        try
        {
            canonical = _canonicalizer.CanonicalizeJsonLd(document, RdfCanonicalizationHashAlgorithm.Sha256);
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException("The document could not be RDFC-canonicalized.", ex);
        }

        return BlankNodeLabels.SplitLines(Encoding.UTF8.GetString(canonical));
    }

    // The relabeled N-Quads of the skolemized selection over the given pointers — an exact
    // string-subset of the whole document's relabeled N-Quads (skolem ids are shared).
    private HashSet<string> SelectionNQuads(
        JsonObject skolemizedDocument, IReadOnlyList<string> pointers, IReadOnlyDictionary<string, string> labelMap)
    {
        var element = JsonSerializer.SerializeToElement(skolemizedDocument, DataProofsJsonOptions.Default);
        var selection = JsonPointer.SelectJsonLd(element, pointers);
        if (selection is JsonObject selectionObject)
        {
            var selectionStable = SkolemizedToStableNQuads(selectionObject);
            var relabeled = BlankNodeLabels.RelabelAndSort(selectionStable, labelMap);
            return new HashSet<string>(relabeled, StringComparer.Ordinal);
        }

        return new HashSet<string>(StringComparer.Ordinal);
    }

    private DataIntegrityProof BuildProofConfig(JsonElement document, DataIntegrityProof proofOptions)
    {
        var context = document.TryGetProperty("@context", out var documentContext)
            ? documentContext.Clone()
            : proofOptions.Context;

        return proofOptions with
        {
            Cryptosuite = proofOptions.Cryptosuite ?? Name,
            Context = context,
            ProofValue = null,
        };
    }

    private byte[] HashProofConfig(DataIntegrityProof proofConfig)
    {
        byte[] canonical;
        try
        {
            canonical = _canonicalizer.CanonicalizeJsonLd(
                JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default),
                RdfCanonicalizationHashAlgorithm.Sha256);
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException("The proof configuration could not be RDFC-canonicalized.", ex);
        }

        return Hash.Sha256(canonical);
    }

    private static byte[] HashMandatory(IReadOnlyList<string> mandatoryNQuads)
    {
        var joined = string.Concat(mandatoryNQuads);
        return Hash.Sha256(Encoding.UTF8.GetBytes(joined));
    }

    private static (DataIntegrityProof Proof, JsonElement Unsecured) SplitProof(JsonElement securedDocument)
    {
        if (!securedDocument.TryGetProperty("proof", out var proofElement) || proofElement.ValueKind != JsonValueKind.Object)
        {
            throw new ProofGenerationException("The secured base document must carry a single proof object.");
        }

        var proof = proofElement.Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)
            ?? throw new ProofGenerationException("The base proof could not be parsed.");

        var unsecured = JsonObject.Create(securedDocument)!;
        unsecured.Remove("proof");
        return (proof, JsonSerializer.SerializeToElement(unsecured, DataProofsJsonOptions.Default));
    }

    private void ValidateProofOptions(DataIntegrityProof proofOptions)
    {
        if (!string.Equals(proofOptions.Type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal))
        {
            throw new ProofGenerationException($"Proof options type must be '{DataIntegrityProof.DataIntegrityProofType}'.");
        }

        var cryptosuite = proofOptions.Cryptosuite ?? Name;
        if (!string.Equals(cryptosuite, Name, StringComparison.Ordinal))
        {
            throw new ProofGenerationException($"Proof options cryptosuite '{cryptosuite}' does not match '{Name}'.");
        }

        if (proofOptions.ProofValue is not null)
        {
            throw new ProofGenerationException("Proof options must not carry a proofValue.");
        }

        if (string.IsNullOrEmpty(proofOptions.ProofPurpose))
        {
            throw new ProofGenerationException("Proof options must declare a proofPurpose.");
        }

        if (string.IsNullOrEmpty(proofOptions.VerificationMethod))
        {
            throw new ProofGenerationException("Proof options must declare a verificationMethod.");
        }
    }

    private static byte[] Concat(byte[] left, byte[] right)
    {
        var result = new byte[left.Length + right.Length];
        left.CopyTo(result, 0);
        right.CopyTo(result, left.Length);
        return result;
    }
}
