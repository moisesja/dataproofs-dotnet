using System.Formats.Cbor;
using System.Security.Cryptography;
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
/// <b>Mandatory-disclosure binding.</b> The W3C suite binds the mandatory group into the BBS
/// signature <c>header</c>: <c>bbsHeader = SHA-256(proofConfig) ‖ SHA-256(mandatory N-Quads)</c>,
/// supplied at <see cref="IBbsCryptoProvider.Sign"/> (issuer) and
/// <see cref="IBbsCryptoProvider.DeriveProof"/> (holder, from the value carried in the base
/// proofValue). At verification the header is <em>recomputed</em> from the revealed mandatory
/// messages — never taken from the holder-controlled derived proofValue — so a holder that drops
/// or alters a mandatory statement produces a header that no longer matches the one committed by
/// the proof, and verification fails. This makes mandatory disclosure cryptographically enforced
/// (requires NetCrypto's BBS <c>header</c> parameter, ≥ 1.0.0).
/// </para>
/// <para>
/// The lifecycle follows the specification's algorithms as the reference implementation runs them
/// (<c>@digitalbazaar/bbs-2023-cryptosuite</c> over <c>di-sd-primitives</c>): the base proof signs
/// the non-mandatory N-Quads, with the mandatory ones bound through the BBS header; the derived
/// proof's indexes are relative (mandatory within the revealed N-Quads, selective within the
/// non-mandatory messages); the reveal document is selected from the document as the issuer wrote
/// it, so its blank nodes stay blank; and the derived proof's label map is keyed by the reveal's
/// canonical (<c>c14n*</c>) labels, which the verifier recomputes by canonicalizing the reveal as
/// given. The W3C derived-proof vector verifies here, and reveals made here verify on the reference
/// verifier (PR #42). The suite is pinned to a Candidate Recommendation draft (PRD §12.3).
/// </para>
/// </remarks>
public sealed class Bbs2023Cryptosuite : ICryptosuite
{
    /// <summary>The cryptosuite identifier, <c>bbs-2023</c>.</summary>
    public const string CryptosuiteName = "bbs-2023";

    private const string DataLossMessage =
        "The document or proof configuration cannot be RDFC-canonicalized without losing data, so it cannot be secured.";

    private static readonly DefaultKeyGenerator KeyGenerator = new();

    private readonly IRdfCanonicalizer _canonicalizer;
    private readonly IBbsCryptoProvider _bbs;

    /// <summary>
    /// Creates the suite over <paramref name="canonicalizer"/>, or over the offline-default RDFC
    /// canonicalizer (FR-10) when it is omitted or <see langword="null"/>. One public constructor,
    /// so reflection-based activation has a single candidate (PR #39).
    /// </summary>
    public Bbs2023Cryptosuite(IRdfCanonicalizer? canonicalizer = null)
    {
        _canonicalizer = canonicalizer ?? new RdfcDocumentCanonicalizer();
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
    /// <param name="hmacKey">The per-credential 32-byte HMAC key used to shuffle blank-node labels.</param>
    /// <param name="mandatoryPointers">RFC 6901 JSON Pointers selecting the always-revealed group.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <returns>The completed base proof including its <c>u2V0C…</c> <c>proofValue</c>.</returns>
    /// <exception cref="ProofGenerationException">The options, document or HMAC key are invalid for this suite.</exception>
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

        // The base proof parser requires this length, as the reference does, so a proof issued with
        // another could never be derived from.
        if (hmacKey.Length != Bbs2023ProofValue.HmacKeyLength)
        {
            throw new ProofGenerationException($"The bbs-2023 HMAC key must be {Bbs2023ProofValue.HmacKeyLength} bytes.");
        }

        if (unsecuredDocument.ValueKind != JsonValueKind.Object)
        {
            throw new ProofGenerationException("The document to secure must be a JSON object.");
        }

        // Before skolemization and the @context lookup, which read member names (issue #33).
        unsecuredDocument = JsonInputCheck.RequireValid(unsecuredDocument, "The document to secure");
        RequirePointers(mandatoryPointers, "A mandatory pointer is invalid.");

        cancellationToken.ThrowIfCancellationRequested();

        var publicKey = KeyGenerator.FromPrivateKey(KeyType.Bls12381G2, bbsPrivateKey.Span).PublicKey;

        var proofConfig = BuildProofConfig(unsecuredDocument, proofOptions);
        _ = JsonInputCheck.SerializeChecked(proofConfig, RdfcJson.ProofTypeInfo, "The proof configuration");
        var transformed = Transform(unsecuredDocument, hmacKey.Span);
        var mandatory = Group(transformed, mandatoryPointers);

        var proofHash = HashProofConfig(proofConfig);
        var mandatoryHash = HashMandatory(mandatory.Matching);
        var bbsHeader = Concat(proofHash, mandatoryHash);

        // The BBS messages are the non-mandatory N-Quads (spec createBaseProofValue step 2). The
        // mandatory group is bound through the BBS signature header instead:
        // bbsHeader = SHA-256(proofConfig) ‖ SHA-256(mandatory N-Quads). The verifier recomputes
        // this header from the revealed mandatory N-Quads, so a holder that drops or alters a
        // mandatory statement produces a header that no longer matches the one committed by the
        // proof, and verification fails.
        var messages = mandatory.NonMatching.Select(nq => Encoding.UTF8.GetBytes(nq)).ToList();
        if (messages.Count == 0)
        {
            // The BBS provider cannot sign an empty message list (NetCrypto 1.7.1), so a document whose
            // every statement is mandatory cannot be secured with bbs-2023 here.
            throw new ProofGenerationException(
                "bbs-2023 needs at least one non-mandatory statement: the BBS provider cannot sign an empty message list.");
        }

        var bbsSignature = _bbs.Sign(bbsPrivateKey.Span, messages, bbsHeader);

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

        // The holder derives over a document an issuer sent: check it before splitting off the
        // proof, which reads member names (issue #33).
        securedBaseDocument = JsonInputCheck.RequireValid(securedBaseDocument, "The secured base document");

        var (baseProof, unsecured) = SplitProof(securedBaseDocument);
        Bbs2023ProofValue.BaseProofComponents components;
        try
        {
            components = Bbs2023ProofValue.ParseBaseProof(baseProof.ProofValue
                ?? throw new ProofGenerationException("The base proof carries no proofValue."));
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or InvalidOperationException or CborContentException)
        {
            // CborReader reports an item of the wrong kind as InvalidOperationException and a
            // malformed encoding as CborContentException (PR #35 review).
            throw new ProofGenerationException("The base proofValue is not a valid bbs-2023 base proof.", ex);
        }

        // The mandatory pointers come from the issuer's document, the selective ones from the
        // caller; both are parsed here so a malformed one fails as the documented exception.
        RequirePointers(components.MandatoryPointers, "The base proof carries an invalid mandatory pointer.");
        RequirePointers(selectivePointers, "A selective pointer is invalid.");

        DisclosureData disclosure;
        try
        {
            disclosure = CreateDisclosureData(unsecured, baseProof, components, selectivePointers, presentationHeader.Span);
        }
        catch (CryptographicException ex) when (ex is not BbsUnavailableException)
        {
            // The base proof parsed, but its signature is not valid over its own messages, so the
            // BBS proof cannot be generated: an invalid base document, not an unavailable library.
            throw new ProofGenerationException("The base proof's BBS signature could not be used to derive a proof.", ex);
        }

        // Build the reveal document: the JSON-LD selection over the combined pointers,
        // re-secured with the derived proof carrying the same proof options.
        var revealDocument = (JsonObject)disclosure.RevealDocument;
        var derivedProofValue = Bbs2023ProofValue.SerializeDerivedProof(
            disclosure.BbsProof, disclosure.LabelMap, disclosure.MandatoryIndexes,
            disclosure.SelectiveIndexes, presentationHeader.Span);

        // The derived proof carries no @context of its own, as the reference's does not: the reveal
        // document's applies, and the verifier borrows it.
        var derivedProof = baseProof with { ProofValue = derivedProofValue, Context = null };
        revealDocument["proof"] = JsonSerializer.SerializeToNode(derivedProof, RdfcJson.ProofTypeInfo);

        return JsonSerializer.SerializeToElement(revealDocument, RdfcJson.JsonObjectTypeInfo);
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
            catch (Exception ex) when (ex is FormatException or ArgumentException or InvalidOperationException
                or OverflowException or CborContentException)
            {
                // CborReader reports an item of the wrong kind as InvalidOperationException, a value past
                // the integer range as OverflowException and a malformed encoding as CborContentException.
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
            if (disclosed.Problem is not null)
            {
                return ProofVerificationResult.Failure(ProofProblemCodes.ProofVerificationError, disclosed.Problem, proof);
            }

            // Recompute the BBS signature header the issuer bound (spec createVerifyData):
            // bbsHeader = SHA-256(proofConfig) ‖ SHA-256(revealed mandatory N-Quads). A holder that
            // drops or alters a mandatory statement changes this recomputed header, so it no longer
            // equals the header committed by the proof and BBS verification fails — this is what
            // enforces mandatory disclosure. The header is recomputed here, NOT taken from the
            // holder-controlled derived proofValue.
            var proofHash = HashProofConfig(proofConfig);
            var bbsHeader = Concat(proofHash, HashMandatory(disclosed.Mandatory));

            // The revealed non-mandatory N-Quads are the disclosed BBS messages, at the selective
            // indexes of the issuer's non-mandatory message list.
            var revealedMessages = disclosed.NonMandatory.Select(nq => Encoding.UTF8.GetBytes(nq)).ToList();
            var verified = _bbs.VerifyProof(
                publicKey.KeyBytes.Span,
                components.BbsProof,
                revealedMessages,
                components.SelectiveIndexes,
                components.PresentationHeader,
                bbsHeader);

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
        catch (ProofGenerationException ex) when (ex.InnerException is JsonLdDataLossException)
        {
            // Content the canonical form would drop is unsigned, so it may have been altered (issue #36).
            return ProofVerificationResult.Failure(
                ProofProblemCodes.DataLossDetectionError,
                "The reveal document or proof configuration cannot be RDFC-canonicalized without losing data.", proof);
        }
        catch (Exception ex)
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError,
                $"Verification failed unexpectedly ({ex.GetType().Name}).", proof);
        }
    }

    // ---- spec sub-algorithms (canonicalizeAndGroup family + DI-ECDSA primitives) ----
    //
    // The group partition is made label-stable by SKOLEMIZATION: blank nodes are replaced by
    // urn:bnid:_:b* URIs in document order BEFORE any selection, so a selected sub-document's
    // RDF nodes keep the identity they had in the whole document. Those ids are read back as
    // blank nodes (_:b*, the "input labels"), the whole document is canonicalized once to map each
    // input label to its c14n label, and the HMAC label map shuffles the c14n labels into b*
    // labels (spec createShuffledIdLabelMapFunction). A selection's N-Quads, relabeled through the
    // same input-label map, are an exact string-subset of the whole document's. A blank node the
    // skolemizer cannot name (an RDF list's) would have no stable input label, so it is refused.

    // The whole document's relabeled, sorted canonical N-Quads (the BBS message universe), the
    // input-label → b-label map a selection is relabeled through, and the skolemized document the
    // selections are taken from.
    private readonly record struct TransformResult(
        IReadOnlyList<string> NQuads,
        IReadOnlyDictionary<string, string> LabelMap,
        JsonObject SkolemizedDocument);

    // One pointer group's partition of TransformResult.NQuads: the matching statements with their
    // absolute indexes, the rest with theirs, and the selection's deskolemized N-Quads.
    private readonly record struct GroupResult(
        IReadOnlyList<int> MatchingIndexes,
        IReadOnlyList<string> Matching,
        IReadOnlyList<int> NonMatchingIndexes,
        IReadOnlyList<string> NonMatching,
        IReadOnlyList<string> DeskolemizedNQuads);

    // canonicalizeAndGroup, the shared part: skolemize, read the skolem ids back as blank nodes,
    // canonicalize once to learn each input label's c14n label, HMAC-shuffle those, relabel and sort.
    private TransformResult Transform(JsonElement document, ReadOnlySpan<byte> hmacKey)
    {
        var canonicalDocument = RequireNoSkolemIris(document);
        var skolemized = JsonLdSkolemizer.Skolemize(document);
        var deskolemized = DeskolemizedNQuads(skolemized, canonicalDocument);

        var canonicalIdMap = CanonicalIdMap(deskolemized);
        var shuffled = BlankNodeLabels.CreateShuffledIdLabelMap(canonicalIdMap.Values, hmacKey);
        var labelMap = canonicalIdMap.ToDictionary(pair => pair.Key, pair => shuffled[pair.Value], StringComparer.Ordinal);
        var nquads = BlankNodeLabels.RelabelAndSort(deskolemized, labelMap);

        return new TransformResult(nquads, labelMap, skolemized);
    }

    // The group of TransformResult.NQuads a pointer set addresses: the skolemized selection's
    // N-Quads, relabeled through the shared label map, are an exact string-subset of the whole.
    private GroupResult Group(TransformResult transformed, IReadOnlyList<string> pointers)
    {
        var deskolemizedSelection = SelectionNQuads(transformed.SkolemizedDocument, pointers);
        var selected = new HashSet<string>(
            BlankNodeLabels.RelabelAndSort(deskolemizedSelection, transformed.LabelMap), StringComparer.Ordinal);

        var matchingIndexes = new List<int>();
        var matching = new List<string>();
        var nonMatchingIndexes = new List<int>();
        var nonMatching = new List<string>();
        for (var i = 0; i < transformed.NQuads.Count; i++)
        {
            if (selected.Contains(transformed.NQuads[i]))
            {
                matchingIndexes.Add(i);
                matching.Add(transformed.NQuads[i]);
            }
            else
            {
                nonMatchingIndexes.Add(i);
                nonMatching.Add(transformed.NQuads[i]);
            }
        }

        return new GroupResult(matchingIndexes, matching, nonMatchingIndexes, nonMatching, deskolemizedSelection);
    }

    private readonly record struct DisclosureData(
        byte[] BbsProof,
        IReadOnlyDictionary<string, string> LabelMap,
        IReadOnlyList<int> MandatoryIndexes,
        IReadOnlyList<int> SelectiveIndexes,
        JsonNode RevealDocument);

    // createDisclosureData: recompute the partition over the base document for the mandatory,
    // selective and combined pointer groups; express the mandatory indexes relative to the revealed
    // (combined) N-Quads and the selective indexes relative to the non-mandatory messages; BBS-derive
    // a proof over the non-mandatory messages revealing the selective ones; select the reveal
    // document from the document as the issuer wrote it; and key the verifier's label map by the
    // canonical labels the verifier will compute from that reveal document.
    private DisclosureData CreateDisclosureData(
        JsonElement document,
        DataIntegrityProof baseProof,
        Bbs2023ProofValue.BaseProofComponents baseComponents,
        IReadOnlyList<string> selectivePointers,
        ReadOnlySpan<byte> presentationHeader)
    {
        var transformed = Transform(document, baseComponents.HmacKey);
        var combinedPointers = baseComponents.MandatoryPointers.Concat(selectivePointers).ToList();
        var mandatory = Group(transformed, baseComponents.MandatoryPointers);
        var selective = Group(transformed, selectivePointers);
        var combined = Group(transformed, combinedPointers);

        // Mandatory indexes, relative to the revealed N-Quads (the combined group's matches, ascending).
        var mandatorySet = new HashSet<int>(mandatory.MatchingIndexes);
        var mandatoryIndexes = new List<int>();
        for (var relative = 0; relative < combined.MatchingIndexes.Count; relative++)
        {
            if (mandatorySet.Contains(combined.MatchingIndexes[relative]))
            {
                mandatoryIndexes.Add(relative);
            }
        }

        // Selective indexes, relative to the non-mandatory messages (the BBS message list).
        var selectiveSet = new HashSet<int>(selective.MatchingIndexes);
        var selectiveIndexes = new List<int>();
        for (var relative = 0; relative < mandatory.NonMatchingIndexes.Count; relative++)
        {
            if (selectiveSet.Contains(mandatory.NonMatchingIndexes[relative]))
            {
                selectiveIndexes.Add(relative);
            }
        }

        // A selection that is empty or matches nothing discloses no BBS message. Without mandatory
        // statements that reveals nothing at all (PR #35 review). With them it is the spec's
        // mandatory-only disclosure, which the BBS provider cannot produce: it needs at least one
        // revealed index (NetCrypto 1.7.1). Both are reported as the documented exception.
        if (selectiveIndexes.Count == 0)
        {
            throw new ProofGenerationException(mandatory.Matching.Count == 0
                ? "The selective disclosure reveals no statements."
                : "A mandatory-only disclosure is not supported: the BBS provider needs at least one disclosed message, so select at least one non-mandatory statement.");
        }

        // The derived proof commits to the same BBS header the issuer bound at sign time
        // (bbsHeader = proofHash ‖ mandatoryHash, carried in the base proofValue); the verifier
        // recomputes it from the revealed mandatory N-Quads. BBS proof generation checks nothing, so
        // a base document or proof configuration altered since signing would derive a proof that can
        // never verify: recompute the header from what the holder has and check the signature over
        // the non-mandatory messages first, and say which failed (PR #42 review).
        var proofConfig = baseProof with { ProofValue = null };
        if (proofConfig.Context is null && document.TryGetProperty("@context", out var documentContext))
        {
            proofConfig = proofConfig with { Context = documentContext.Clone() };
        }

        var expectedHeader = Concat(HashProofConfig(proofConfig), HashMandatory(mandatory.Matching));
        if (!expectedHeader.AsSpan().SequenceEqual(baseComponents.BbsHeader))
        {
            throw new ProofGenerationException(
                "The base proof's BBS header does not match the document and proof configuration: a mandatory value or the proof was altered after signing.");
        }

        var messages = mandatory.NonMatching.Select(nq => Encoding.UTF8.GetBytes(nq)).ToList();
        if (!_bbs.Verify(baseComponents.PublicKey, baseComponents.BbsSignature, messages, baseComponents.BbsHeader))
        {
            throw new ProofGenerationException("The base proof's BBS signature could not be used to derive a proof.");
        }

        var bbsProof = _bbs.DeriveProof(
            baseComponents.PublicKey, baseComponents.BbsSignature, messages, selectiveIndexes,
            presentationHeader, baseComponents.BbsHeader);

        // The reveal document is selected from the document as given, so its blank nodes stay blank
        // and a verifier sees no skolem id.
        var revealDocument = JsonPointer.SelectJsonLd(document, combinedPointers)
            ?? throw new ProofGenerationException("The selective disclosure produced an empty reveal document.");

        // The verifier canonicalizes that reveal document and gets c14n labels; the deskolemized
        // combined selection is the same dataset, so canonicalizing it tells which c14n label each
        // input label becomes. Map those to the HMAC labels (spec createDisclosureData steps 9–10).
        var verifierLabelMap = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (inputLabel, canonicalLabel) in CanonicalIdMap(combined.DeskolemizedNQuads))
        {
            verifierLabelMap[canonicalLabel] = transformed.LabelMap[inputLabel];
        }

        return new DisclosureData(bbsProof, verifierLabelMap, mandatoryIndexes, selectiveIndexes, revealDocument);
    }

    // The revealed N-Quads split by the derived proof's mandatory indexes, or the reason the reveal
    // document and the derived proof do not fit together.
    private readonly record struct VerifyData(IReadOnlyList<string> Mandatory, IReadOnlyList<string> NonMandatory, string? Problem);

    // createVerifyData: canonicalize the reveal document as given (its blank nodes get c14n labels),
    // relabel through the derived proof's label map, sort, and split by the mandatory indexes. The
    // reveal is never skolemized: it is canonicalized exactly as a reference verifier would.
    private VerifyData CreateVerifyData(JsonElement revealDocument, Bbs2023ProofValue.DerivedProofComponents components)
    {
        var canonical = CanonicalNQuadLines(revealDocument);

        // Every blank node of the reveal must be in the holder's label map; an unmapped label would
        // keep its c14n name and could never match a signed message.
        if (BlankNodeLabels.LabelsOf(canonical).Any(label => !components.LabelMap.ContainsKey(label)))
        {
            return new VerifyData([], [], "The derived proof's label map does not cover the reveal document.");
        }

        var nquads = BlankNodeLabels.RelabelAndSort(canonical, components.LabelMap);

        var mandatorySet = new HashSet<int>(components.MandatoryIndexes);
        if (mandatorySet.Count != components.MandatoryIndexes.Count || mandatorySet.Any(index => index < 0 || index >= nquads.Count))
        {
            return new VerifyData([], [], "The derived proof's mandatory indexes do not address the reveal document.");
        }

        if (components.SelectiveIndexes.Distinct().Count() != components.SelectiveIndexes.Count || components.SelectiveIndexes.Any(index => index < 0))
        {
            return new VerifyData([], [], "The derived proof's selective indexes are not distinct non-negative positions.");
        }

        var mandatory = new List<string>();
        var nonMandatory = new List<string>();
        for (var i = 0; i < nquads.Count; i++)
        {
            (mandatorySet.Contains(i) ? mandatory : nonMandatory).Add(nquads[i]);
        }

        if (nonMandatory.Count != components.SelectiveIndexes.Count)
        {
            return new VerifyData([], [], "The number of disclosed non-mandatory statements does not equal the number of selective indexes.");
        }

        return new VerifyData(mandatory, nonMandatory, null);
    }

    // Skolem ids are urn:bnid: IRIs that deskolemization reads back as blank nodes, so the issuer's
    // document must not hold one of its own: it would become a blank node too, and could merge with
    // the skolemized node it collides with (adversarial review). Checked on the canonical form, so a
    // compact IRI that only a context expands into urn:bnid: is caught as well. Verification
    // canonicalizes the reveal document as given and does not skolemize, so it does not run this.
    private IReadOnlyList<string> RequireNoSkolemIris(JsonElement document)
    {
        var usesNamespace = false;
        var canonical = CanonicalNQuadLines(document);
        foreach (var line in canonical)
        {
            BlankNodeLabels.RewriteTerms(line, iri: iri =>
            {
                usesNamespace |= iri.StartsWith(JsonLdSkolemizer.UrnPrefix, StringComparison.Ordinal);
                return iri;
            });
        }

        if (usesNamespace)
        {
            throw new ProofGenerationException(DataLossMessage, new JsonLdDataLossException(
                "The JSON-LD input cannot be canonicalized without losing data: it uses the urn:bnid: namespace, "
                + "which bbs-2023 reserves for its blank-node identifiers."));
        }

        return canonical;
    }

    // Skolemization works on compact JSON without the context, so it can mistake a JSON value for a
    // node and add an @id to it, such as a @json literal or an @id map: the signed data would then
    // carry a member the issuer never wrote (adversarial review). So on creation and derivation the
    // document as given and the skolemized document, with skolem ids read back as blank nodes, must
    // canonicalize to the same dataset. Verification canonicalizes the reveal document as given.
    private void RequireSameDataset(IReadOnlyList<string> document, IReadOnlyList<string> deskolemized)
    {
        string given;
        string skolemized;
        try
        {
            given = _canonicalizer.CanonicalizeNQuads(string.Concat(document));
            skolemized = _canonicalizer.CanonicalizeNQuads(string.Concat(deskolemized));
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException("The document could not be RDFC-canonicalized.", ex);
        }

        if (!string.Equals(given, skolemized, StringComparison.Ordinal))
        {
            throw SkolemizationWouldChange();
        }
    }

    private static ProofGenerationException SkolemizationWouldChange()
        => new(DataLossMessage, new JsonLdDataLossException(
            "The JSON-LD input cannot be canonicalized without losing data: bbs-2023 skolemization would change "
            + "it, which happens for a @json value, a container map, a top-level @graph, @nest or an aliased @id."));

    // The skolemized document's canonical N-Quads with the skolem ids read back as blank nodes: the
    // document's statements under document-order-stable input labels (_:b*), sorted.
    private IReadOnlyList<string> DeskolemizedNQuads(JsonObject skolemized, IReadOnlyList<string> canonicalDocument)
    {
        IReadOnlyList<string> skolemizedNQuads;
        try
        {
            skolemizedNQuads = CanonicalNQuadLines(JsonSerializer.SerializeToElement(skolemized, RdfcJson.JsonObjectTypeInfo));
        }
        catch (ProofGenerationException)
        {
            // The document itself canonicalized (canonicalDocument), so whatever stops the skolemized
            // copy is the skolemizer's doing: the @id it added to a language map reads as a language
            // tag, an @id added under @nest or beside an aliased @id is invalid JSON-LD, and so on.
            throw SkolemizationWouldChange();
        }

        // After skolemization every node object has an IRI. A blank node still here has no stable
        // input label, so a selection could not be relabeled consistently: an RDF list's nodes, or a
        // blank node identifier used as a plain value, which compact JSON cannot tell from a string
        // (the reference implementation cannot sign a @list either).
        if (BlankNodeLabels.LabelsOf(skolemizedNQuads).Count > 0)
        {
            throw new ProofGenerationException(DataLossMessage, new JsonLdDataLossException(
                "The JSON-LD input cannot be canonicalized without losing data: it holds a blank node that bbs-2023 "
                + "skolemization cannot name, such as a @list's or a blank node identifier used as a plain value."));
        }

        var deskolemized = JsonLdSkolemizer.Deskolemize(skolemizedNQuads).ToList();
        deskolemized.Sort(StringComparer.Ordinal);
        RequireSameDataset(canonicalDocument, deskolemized);
        return deskolemized;
    }

    // Each input blank-node label (without _:) → its RDFC-1.0 canonical label (without _:).
    private IReadOnlyDictionary<string, string> CanonicalIdMap(IReadOnlyList<string> nquads)
    {
        try
        {
            return _canonicalizer.CanonicalizeNQuadsToMap(string.Concat(nquads));
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException("The document could not be RDFC-canonicalized.", ex);
        }
    }

    private IReadOnlyList<string> CanonicalNQuadLines(JsonElement document)
    {
        byte[] canonical;
        try
        {
            canonical = _canonicalizer.CanonicalizeJsonLd(document, RdfCanonicalizationHashAlgorithm.Sha256);
        }
        catch (JsonLdDataLossException ex)
        {
            // VC Data Integrity 1.0 §2.4.3: what JSON-LD processing drops would not be signed (issue #36).
            throw new ProofGenerationException(DataLossMessage, ex);
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException("The document could not be RDFC-canonicalized.", ex);
        }

        return BlankNodeLabels.SplitLines(Encoding.UTF8.GetString(canonical));
    }

    // The deskolemized N-Quads of the skolemized selection over the given pointers: the selection
    // carries the whole document's skolem ids, so its statements are the whole document's, under
    // the same input labels. Empty when the pointers select nothing.
    private IReadOnlyList<string> SelectionNQuads(JsonObject skolemizedDocument, IReadOnlyList<string> pointers)
    {
        var element = JsonSerializer.SerializeToElement(skolemizedDocument, RdfcJson.JsonObjectTypeInfo);
        JsonNode? selected;
        try
        {
            selected = JsonPointer.SelectJsonLd(element, pointers);
        }
        catch (ArgumentException ex)
        {
            // A pointer that addresses nothing (the spec's selectJsonLd fails on it too).
            throw new ProofGenerationException("A JSON pointer does not match the document.", ex);
        }

        if (selected is not JsonObject selection)
        {
            return [];
        }

        var canonical = CanonicalNQuadLines(JsonSerializer.SerializeToElement(selection, RdfcJson.JsonObjectTypeInfo));
        return JsonLdSkolemizer.Deskolemize(canonical);
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
                JsonSerializer.SerializeToElement(proofConfig, RdfcJson.ProofTypeInfo),
                RdfCanonicalizationHashAlgorithm.Sha256);
        }
        catch (JsonLdDataLossException ex)
        {
            throw new ProofGenerationException(DataLossMessage, ex);
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

        DataIntegrityProof? proof;
        try
        {
            proof = proofElement.Deserialize(RdfcJson.ProofTypeInfo);
        }
        catch (JsonException ex)
        {
            // A member of the wrong JSON kind ("type": 1, "previousProof": {}) (PR #35 review).
            throw new ProofGenerationException("The base proof could not be parsed.", ex);
        }

        if (proof is null)
        {
            throw new ProofGenerationException("The base proof could not be parsed.");
        }

        var unsecured = JsonObject.Create(securedDocument)!;
        unsecured.Remove("proof");
        return (proof, JsonSerializer.SerializeToElement(unsecured, RdfcJson.JsonObjectTypeInfo));
    }

    private static void RequirePointers(IReadOnlyList<string> pointers, string message)
    {
        try
        {
            foreach (var pointer in pointers)
            {
                if (pointer is null)
                {
                    throw new ProofGenerationException(message);
                }

                _ = JsonPointer.Parse(pointer);
            }
        }
        catch (ArgumentException ex)
        {
            throw new ProofGenerationException(message, ex);
        }
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
