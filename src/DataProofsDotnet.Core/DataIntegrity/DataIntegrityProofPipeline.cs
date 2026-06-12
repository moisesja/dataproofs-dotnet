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
    /// <exception cref="ProofGenerationException">The options, document, or signer are invalid.</exception>
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

        var signingElement = JsonSerializer.SerializeToElement(signingInput, DataProofsJsonOptions.Default);
        var proof = await suite.CreateProofAsync(signingElement, proofOptions, signer, cancellationToken).ConfigureAwait(false);
        var proofNode = JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.Default)!;

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

        return JsonSerializer.SerializeToElement(output, DataProofsJsonOptions.Default);
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
            proof = proofElement.Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default);
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
        if (string.IsNullOrEmpty(proof.Type)
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

        var suite = _registry.GetByName(proof.Cryptosuite);
        if (suite is null || !string.Equals(proof.Type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal))
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

        var inputDocument = JsonObject.Create(securedDocument)!;
        inputDocument.Remove(ProofMemberName);
        if (matchingProofs is not null)
        {
            inputDocument[ProofMemberName] = matchingProofs;
        }

        var inputElement = JsonSerializer.SerializeToElement(inputDocument, DataProofsJsonOptions.Default);
        return suite.VerifyProof(inputElement, proof, publicKey);
    }

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
