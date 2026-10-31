using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Internal;
using NetCrypto;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The cryptosuite-agnostic Add Proof / Verify Proof engine of VC Data Integrity 1.0
/// (FR-2/FR-3), including proof sets and proof chains (FR-6). Suite-specific steps are
/// delegated to the cryptosuites registered in the <see cref="CryptosuiteRegistry"/>;
/// signing goes through a NetCrypto <see cref="ISigner"/>, so a non-exporting
/// key-store-backed signer is sufficient for every suite.
/// </summary>
/// <remarks>
/// <para>
/// Verification comes in two forms (FR-7): <b>raw-key</b> overloads perform
/// signature-only verification (no controller document is available, so no controller
/// authorization), and <b>resolver</b> overloads run the full algorithm including
/// controller authorization — the resolved controller document must list the proof's
/// verification method under the relationship matching its <c>proofPurpose</c>, and the
/// controller must control the method.
/// </para>
/// <para>
/// Invalid proofs produce failed results, never exceptions; exceptions are reserved for
/// malformed inputs and misconfiguration on the creation path (FR-23). Instances are
/// immutable and thread-safe after construction (NFR-4).
/// </para>
/// <para>
/// Both directions first check the JSON they are given, before any step reads it: it must be
/// valid UTF-8, contain no JSON escape for an unpaired UTF-16 surrogate, repeat no member name
/// in any object, and nest no deeper than 64 levels (issue #33). A secured document that fails
/// the check is one document-level <see cref="ProofProblemCodes.ProofTransformationError"/>,
/// returned before any proof is parsed or any resolver is called; a document or proof options
/// that fail it on creation throw <see cref="ProofGenerationException"/>. Comments and trailing
/// commas left by a lenient parse are not faults.
/// </para>
/// </remarks>
public sealed class DataIntegrityProofPipeline
{
    private const string ProofMemberName = "proof";

    private readonly CryptosuiteRegistry _registry;

    /// <summary>Creates a pipeline over the default registry (the JCS suites).</summary>
    public DataIntegrityProofPipeline()
        : this(CryptosuiteRegistry.CreateDefault())
    {
    }

    /// <summary>Creates a pipeline over the given cryptosuite registry.</summary>
    public DataIntegrityProofPipeline(CryptosuiteRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
    }

    /// <summary>The cryptosuite registry this pipeline consults.</summary>
    public CryptosuiteRegistry Suites => _registry;

    /// <summary>
    /// Adds a proof to <paramref name="document"/> (which may already carry proofs —
    /// set semantics, FR-6). When <paramref name="proofOptions"/> carries
    /// <c>previousProof</c>, the referenced proofs are embedded into the signing input
    /// per the proof-chain rules, and every reference must match the <c>id</c> of an
    /// existing proof.
    /// </summary>
    /// <param name="document">The JSON object to secure.</param>
    /// <param name="proofOptions">The proof options naming the cryptosuite; no <c>proofValue</c>.</param>
    /// <param name="signer">The NetCrypto signer.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <returns>The secured document carrying the new proof.</returns>
    /// <exception cref="ProofGenerationException">The options, document, or signer are invalid,
    /// including JSON in the document or options that fails the check in the type remarks.</exception>
    public async Task<JsonElement> AddProofAsync(
        JsonElement document,
        DataIntegrityProof proofOptions,
        ISigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proofOptions);
        ArgumentNullException.ThrowIfNull(signer);

        if (document.ValueKind != JsonValueKind.Object)
        {
            throw new ProofGenerationException("The document to secure must be a JSON object.");
        }

        if (string.IsNullOrEmpty(proofOptions.Cryptosuite))
        {
            throw new ProofGenerationException("The proof options must name a cryptosuite.");
        }

        var suite = _registry.GetByName(proofOptions.Cryptosuite)
            ?? throw new ProofGenerationException($"No cryptosuite named '{proofOptions.Cryptosuite}' is registered.");

        if (proofOptions.ProofValue is not null)
        {
            throw new ProofGenerationException("Proof options must not carry a proofValue.");
        }

        // Every step below, and the suite, reads member names and strings: reject what they
        // cannot read before the first one does, and carry on with strict JSON (issue #33).
        document = JsonInputCheck.RequireValid(document, "The document to secure");

        // The options end up inside the secured document: one level below its root, or two once
        // the proof member is an array. Check them against that depth now, before signing, rather
        // than discover after the signature that the result cannot be written (PR #35 review).
        var optionsDepth = JsonInputCheck.MaxDepth - (document.TryGetProperty(ProofMemberName, out _) ? 2 : 1);
        _ = JsonInputCheck.SerializeChecked(proofOptions, DataProofsJsonOptions.ProofTypeInfo, "The proof options object", optionsDepth);

        JsonElement signingElement;
        try
        {
            var existingProofs = ReadExistingProofs(document);

            // Build the signing input: the document without its proof member; for chains,
            // with the matching previous proofs re-embedded as an array (spec §4.5 shape).
            var signingInput = JsonObject.Create(document)!;
            signingInput.Remove(ProofMemberName);

            if (proofOptions.PreviousProof is { } previousProof)
            {
                var matching = new JsonArray();
                foreach (var reference in previousProof.Values)
                {
                    var match = existingProofs.FirstOrDefault(p => string.Equals(GetProofId(p), reference, StringComparison.Ordinal));
                    if (match.ValueKind != JsonValueKind.Object)
                    {
                        throw new ProofGenerationException($"previousProof references '{reference}', which matches no existing proof id.");
                    }

                    matching.Add(JsonNode.Parse(match.GetRawText()));
                }

                signingInput[ProofMemberName] = matching;
            }

            signingElement = JsonSerializer.SerializeToElement(signingInput, DataProofsJsonOptions.JsonObjectTypeInfo);
        }
        catch (Exception ex) when (IsTransformationFault(ex))
        {
            throw new ProofGenerationException("The document could not be prepared for signing.", ex);
        }

        // The suite call stays outside the mapping: its own contract covers it, and a signer
        // fault must not be relabelled as a document fault.
        var proof = await suite.CreateProofAsync(signingElement, proofOptions, signer, cancellationToken).ConfigureAwait(false);

        try
        {
            var proofNode = JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.ProofTypeInfo)!;

            // Append the proof: none -> object form; existing object -> two-element array;
            // existing array -> append.
            var output = JsonObject.Create(document)!;
            if (!document.TryGetProperty(ProofMemberName, out var proofMember))
            {
                output[ProofMemberName] = proofNode;
            }
            else if (proofMember.ValueKind == JsonValueKind.Object)
            {
                output[ProofMemberName] = new JsonArray(JsonNode.Parse(proofMember.GetRawText()), proofNode);
            }
            else
            {
                var array = (JsonArray)output[ProofMemberName]!;
                array.Add(proofNode);
            }

            return JsonSerializer.SerializeToElement(output, DataProofsJsonOptions.JsonObjectTypeInfo);
        }
        catch (Exception ex) when (IsTransformationFault(ex))
        {
            throw new ProofGenerationException("The secured document could not be assembled.", ex);
        }
    }

    /// <summary>
    /// Verifies every proof on <paramref name="securedDocument"/> against a caller-supplied
    /// public key — the signature-only raw-key form (FR-7); no controller authorization is
    /// performed because no controller document is available.
    /// </summary>
    /// <param name="securedDocument">The secured JSON document.</param>
    /// <param name="publicKey">The verification key for every proof.</param>
    /// <param name="options">Verifier expectations (purpose, domain, challenge, clock).</param>
    public DocumentVerificationResult Verify(
        JsonElement securedDocument,
        PublicKeyMaterial publicKey,
        ProofVerificationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        // The delegate completes synchronously, so the returned task is already complete.
        var task = VerifyCoreAsync(
            securedDocument,
            (_, _) => ValueTask.FromResult<(PublicKeyMaterial?, ProofProblem?)>((publicKey, null)),
            options,
            CancellationToken.None);
        return task.GetAwaiter().GetResult();
    }

    /// <summary>
    /// Verifies every proof on <paramref name="securedDocument"/> using the resolver —
    /// the full algorithm (FR-3) including controller authorization: the resolved
    /// controller document must list the verification method under the relationship
    /// matching the proof's <c>proofPurpose</c>
    /// (<see cref="ProofProblemCodes.InvalidVerificationMethod"/> otherwise), and the
    /// controller must control the method.
    /// </summary>
    /// <param name="securedDocument">The secured JSON document.</param>
    /// <param name="resolver">The verification-method resolver.</param>
    /// <param name="options">Verifier expectations (purpose, domain, challenge, clock).</param>
    /// <param name="cancellationToken">Cancels resolution.</param>
    public Task<DocumentVerificationResult> VerifyAsync(
        JsonElement securedDocument,
        IVerificationMethodResolver resolver,
        ProofVerificationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        return VerifyCoreAsync(securedDocument, ResolveKeyAsync, options, cancellationToken);

        async ValueTask<(PublicKeyMaterial?, ProofProblem?)> ResolveKeyAsync(DataIntegrityProof proof, CancellationToken ct)
        {
            ResolvedVerificationMethod? resolved;
            try
            {
                resolved = await resolver.ResolveAsync(proof.VerificationMethod!, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Infrastructure fault during resolution: fail closed, with a cause
                // distinguishable from "the controller said no".
                return (null, new ProofProblem
                {
                    Code = ProofProblemCodes.ProofVerificationError,
                    Message = $"Verification method resolution failed ({ex.GetType().Name}).",
                });
            }

            if (resolved is null)
            {
                return (null, new ProofProblem
                {
                    Code = ProofProblemCodes.InvalidVerificationMethod,
                    Message = "The verification method could not be resolved.",
                });
            }

            if (!string.Equals(resolved.Id, proof.VerificationMethod, StringComparison.Ordinal))
            {
                return (null, new ProofProblem
                {
                    Code = ProofProblemCodes.InvalidVerificationMethod,
                    Message = "The resolved verification method id does not match the proof's verificationMethod.",
                });
            }

            if (!resolved.ControllerControlsMethod)
            {
                return (null, new ProofProblem
                {
                    Code = ProofProblemCodes.InvalidVerificationMethod,
                    Message = "The controller does not control the verification method.",
                });
            }

            if (!resolved.Relationships.Contains(proof.ProofPurpose!))
            {
                return (null, new ProofProblem
                {
                    Code = ProofProblemCodes.InvalidVerificationMethod,
                    Message = $"The controller document does not authorize the verification method for proof purpose '{proof.ProofPurpose}'.",
                });
            }

            return (resolved.PublicKey, null);
        }
    }

    private async Task<DocumentVerificationResult> VerifyCoreAsync(
        JsonElement securedDocument,
        Func<DataIntegrityProof, CancellationToken, ValueTask<(PublicKeyMaterial? Key, ProofProblem? Problem)>> keyProvider,
        ProofVerificationOptions? options,
        CancellationToken cancellationToken)
    {
        options ??= new ProofVerificationOptions();

        if (securedDocument.ValueKind != JsonValueKind.Object)
        {
            return DocumentFailure(ProofProblemCodes.ProofVerificationError, "The secured document must be a JSON object.");
        }

        // FR-3: a document whose member names or strings cannot be read, or whose members repeat,
        // fails here as a result — before any proof is parsed or any resolver is called — rather
        // than throwing from whichever later step reads it first (issue #33).
        if (!JsonInputCheck.TryAccept(securedDocument, out securedDocument, out var problem))
        {
            return DocumentFailure(ProofProblemCodes.ProofTransformationError, $"The secured document {problem}.");
        }

        if (!securedDocument.TryGetProperty(ProofMemberName, out var proofMember))
        {
            return DocumentFailure(ProofProblemCodes.ProofVerificationError, "The document carries no proof.");
        }

        List<JsonElement> proofElements;
        if (proofMember.ValueKind == JsonValueKind.Object)
        {
            proofElements = [proofMember];
        }
        else if (proofMember.ValueKind == JsonValueKind.Array)
        {
            proofElements = [.. proofMember.EnumerateArray()];
            if (proofElements.Count == 0)
            {
                return DocumentFailure(ProofProblemCodes.ProofVerificationError, "The proof array is empty.");
            }
        }
        else
        {
            return DocumentFailure(ProofProblemCodes.ProofVerificationError, "The proof member must be an object or an array of objects.");
        }

        // VC Data Integrity 1.0 §4.6: with known contexts supplied, the document is accepted only when
        // every @context in it, at any depth, holds only those. §2.4.1 allows a different ordering of
        // the steps that gives the same protections. The suites load contexts while they verify, so
        // this runs first: an unlisted context is never loaded, and a holder cannot choose a URL the
        // verifier fetches. Such a document has no per-proof results.
        if (options.KnownContexts is { } knownContexts && ContextProblem(securedDocument, knownContexts) is { } contextProblem)
        {
            return new DocumentVerificationResult { Verified = false, Problems = [contextProblem] };
        }

        var results = new List<ProofVerificationResult>(proofElements.Count);
        foreach (var proofElement in proofElements)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await VerifySingleProofAsync(
                securedDocument, proofElements, proofElement, keyProvider, options, cancellationToken).ConfigureAwait(false));
        }

        return new DocumentVerificationResult
        {
            Verified = results.Count > 0 && results.All(r => r.Verified),
            ProofResults = results,
        };
    }

    // Context Validation (VC Data Integrity 1.0 §4.6) over context IRIs: every @context in the
    // document, at any depth, must hold only listed IRIs. An inline context object cannot be a
    // listed value, so it fails; a document without any @context has nothing to validate.
    //
    // Step 3 fails a subtree's @context outright, but the JCS suites copy @context into each proof
    // and a presentation embeds credentials with their own, so a nested @context follows the root's
    // rule instead (§2.4.1 allows equivalent protections). A listed context nested gives a holder
    // nothing that adding it at the root does not.
    //
    // This goes by name alone, with no exemptions. Telling a JSON literal apart takes processing the
    // contexts: a term's type can make one, and @value is a keyword only outside a container map,
    // where it is an ordinary key whose value the processor expands. So every key named @context
    // counts, as step 3 reads, and one inside a literal fails closed. TryAccept has bounded the
    // depth, refused repeated members and made every name readable.
    private static ProofProblem? ContextProblem(JsonElement element, IReadOnlyCollection<string> knownContexts)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (ContextProblem(item, knownContexts) is { } problem)
                {
                    return problem;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var member in element.EnumerateObject())
            {
                var problem = member.Name == "@context"
                    ? ContextValueProblem(member.Value, knownContexts)
                    : ContextProblem(member.Value, knownContexts);

                if (problem is not null)
                {
                    return problem;
                }
            }
        }

        return null;
    }

    // Messages do not quote the value (FR-23).
    private static ProofProblem? ContextValueProblem(JsonElement context, IReadOnlyCollection<string> knownContexts)
    {
        var values = context.ValueKind == JsonValueKind.Array ? context.EnumerateArray().ToList() : [context];
        foreach (var value in values)
        {
            if (value.ValueKind != JsonValueKind.String)
            {
                return new ProofProblem
                {
                    Code = ProofProblemCodes.ProofVerificationError,
                    Message = "A @context in the secured document holds a value that is not a context IRI, so it cannot be a known context.",
                };
            }

            if (!knownContexts.Contains(value.GetString()!, StringComparer.Ordinal))
            {
                return new ProofProblem
                {
                    Code = ProofProblemCodes.ProofVerificationError,
                    Message = "A @context in the secured document holds a value that is not a known context.",
                };
            }
        }

        return null;
    }

    private async Task<ProofVerificationResult> VerifySingleProofAsync(
        JsonElement securedDocument,
        List<JsonElement> allProofs,
        JsonElement proofElement,
        Func<DataIntegrityProof, CancellationToken, ValueTask<(PublicKeyMaterial? Key, ProofProblem? Problem)>> keyProvider,
        ProofVerificationOptions options,
        CancellationToken cancellationToken)
    {
        if (proofElement.ValueKind != JsonValueKind.Object)
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError, "Each proof must be a JSON object.");
        }

        DataIntegrityProof? proof;
        try
        {
            proof = proofElement.Deserialize(DataProofsJsonOptions.ProofTypeInfo);
        }
        catch (JsonException)
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError, "The proof could not be parsed.");
        }

        if (proof is null)
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError, "The proof could not be parsed.");
        }

        // Spec §4.4 step: type, verificationMethod, and proofPurpose are mandatory.
        // The type member must be present on the wire — the model defaults it, so the
        // raw element is checked too (a defaulted member would also desynchronize the
        // canonical bytes from what was signed).
        if (!proofElement.TryGetProperty("type", out _)
            || string.IsNullOrEmpty(proof.Type)
            || string.IsNullOrEmpty(proof.VerificationMethod)
            || string.IsNullOrEmpty(proof.ProofPurpose))
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError,
                "The proof must carry type, verificationMethod, and proofPurpose.", proof);
        }

        // proofPurpose FIELD mismatch — deliberately distinct from the
        // controller-authorization failure (INVALID_VERIFICATION_METHOD).
        if (options.ExpectedProofPurpose is not null
            && !string.Equals(options.ExpectedProofPurpose, proof.ProofPurpose, StringComparison.Ordinal))
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError,
                $"The proofPurpose '{proof.ProofPurpose}' does not match the expected '{options.ExpectedProofPurpose}'.", proof);
        }

        if (options.ExpectedDomain is not null
            && !string.Equals(options.ExpectedDomain, proof.Domain, StringComparison.Ordinal))
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.InvalidDomainError,
                "The proof's domain does not match the expected domain.", proof);
        }

        if (options.ExpectedChallenge is not null
            && !string.Equals(options.ExpectedChallenge, proof.Challenge, StringComparison.Ordinal))
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.InvalidChallengeError,
                "The proof's challenge does not match the expected challenge.", proof);
        }

        if (proof.Expires is not null)
        {
            if (!XmlDateTimeStamp.TryParse(proof.Expires, out var expires))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof 'expires' is not a valid dateTimeStamp.", proof);
            }

            if (expires <= (options.VerificationTime ?? DateTimeOffset.UtcNow))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof has expired.", proof);
            }
        }

        // Suite dispatch (FR-4): the on-wire cryptosuite name always wins (the 2022/2019
        // generation), falling back to the proof type for legacy Linked-Data-Signature
        // proofs that name their algorithm by type and carry no cryptosuite. The suite must
        // claim the type; it then re-validates type/cryptosuite/key/encoding/signature
        // itself, so this gate only confirms the dispatch target is willing to handle it.
        var suite = _registry.GetByName(proof.Cryptosuite)
            ?? _registry.GetByProofType(proof.Type);
        if (suite is null || !(suite.SupportedProofTypes ?? []).Contains(proof.Type))
        {
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError,
                "The proof type or cryptosuite is not supported.", proof);
        }

        // Proof-chain dependency checking (FR-6 / spec §4.5): every previousProof
        // reference must match the id of a proof in the document, and the matching
        // proofs are embedded in the verification input of this proof.
        JsonArray? matchingProofs = null;
        if (proof.PreviousProof is { } previousProof)
        {
            try
            {
                matchingProofs = [];
                foreach (var reference in previousProof.Values)
                {
                    var match = allProofs.FirstOrDefault(
                        p => p.ValueKind == JsonValueKind.Object
                            && string.Equals(GetProofId(p), reference, StringComparison.Ordinal));
                    if (match.ValueKind != JsonValueKind.Object)
                    {
                        return ProofVerificationResult.Failure(
                            ProofProblemCodes.ProofVerificationError,
                            $"previousProof references '{reference}', which matches no proof id in the document.", proof);
                    }

                    matchingProofs.Add(JsonNode.Parse(match.GetRawText()));
                }
            }
            catch (Exception ex) when (IsTransformationFault(ex))
            {
                return TransformationFailure(proof);
            }
        }

        var (publicKey, keyProblem) = await keyProvider(proof, cancellationToken).ConfigureAwait(false);
        if (keyProblem is not null || publicKey is null)
        {
            return new ProofVerificationResult
            {
                Verified = false,
                Proof = proof,
                Problems = [keyProblem ?? new ProofProblem { Code = ProofProblemCodes.ProofVerificationError }],
            };
        }

        try
        {
            var inputDocument = JsonObject.Create(securedDocument)!;
            inputDocument.Remove(ProofMemberName);
            if (matchingProofs is not null)
            {
                inputDocument[ProofMemberName] = matchingProofs;
            }

            var inputElement = JsonSerializer.SerializeToElement(inputDocument, DataProofsJsonOptions.JsonObjectTypeInfo);
            return suite.VerifyProof(inputElement, proof, publicKey);
        }
        catch (Exception ex) when (IsTransformationFault(ex))
        {
            return TransformationFailure(proof);
        }
    }

    // The exceptions System.Text.Json raises for content it cannot transform: an over-nested or
    // unwritable value (JsonException), a duplicate member materialized by a JsonObject
    // (ArgumentException), a name or string that cannot be read (InvalidOperationException).
    // JsonInputCheck rejects all of them up front (issue #33); the mapping stays so that a gap in it
    // still fails through the documented contract — a failed result on verification (FR-3), never a
    // crash on attacker-controlled input, and ProofGenerationException on creation (FR-23).
    private static bool IsTransformationFault(Exception ex)
        => ex is JsonException or ArgumentException or InvalidOperationException;

    // A fixed message, like every other problem here: the exception's own message carries parser
    // positions and characters of the document (FR-23).
    private static ProofVerificationResult TransformationFailure(DataIntegrityProof proof)
        => ProofVerificationResult.Failure(
            ProofProblemCodes.ProofTransformationError,
            "The secured document could not be transformed for verification.", proof);

    private static List<JsonElement> ReadExistingProofs(JsonElement document)
    {
        if (!document.TryGetProperty(ProofMemberName, out var proofMember))
        {
            return [];
        }

        return proofMember.ValueKind switch
        {
            JsonValueKind.Object => [proofMember],
            JsonValueKind.Array when proofMember.EnumerateArray().All(p => p.ValueKind == JsonValueKind.Object)
                => [.. proofMember.EnumerateArray()],
            _ => throw new ProofGenerationException("The document's existing proof member must be an object or an array of objects."),
        };
    }

    private static string? GetProofId(JsonElement proof)
        => proof.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String
            ? id.GetString()
            : null;

    private static DocumentVerificationResult DocumentFailure(string code, string message)
        => new()
        {
            Verified = false,
            Problems = [new ProofProblem { Code = code, Message = message }],
        };
}
