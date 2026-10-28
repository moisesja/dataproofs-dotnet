using System.Text;
using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Rdfc.Internal;
using Newtonsoft.Json.Linq;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.Parsing;

namespace DataProofsDotnet.Rdfc;

/// <summary>
/// The dotNetRDF-backed implementation of <see cref="IRdfCanonicalizer"/> (FR-9): JSON-LD
/// 1.1 expansion via <see cref="JsonLdParser"/> and RDF Dataset Canonicalization via
/// <see cref="RdfCanonicalizer"/>, with context loading delegated to a pluggable
/// <see cref="IDocumentLoader"/> (offline-only by default, FR-10).
/// </summary>
/// <remarks>
/// All <c>dotNetRDF</c> and <c>Newtonsoft</c> coupling is contained here (this is the sole
/// dotNetRDF reference in the stack, PRD §2.2): nothing of those libraries leaks across the
/// <see cref="IRdfCanonicalizer"/> boundary. Documents enter as <c>System.Text.Json</c>
/// values, are handed to dotNetRDF as serialized JSON strings, and leave as canonical
/// N-Quads. Every failure surfaces as <see cref="RdfCanonicalizationException"/>. Immutable
/// and thread-safe after construction (NFR-4).
/// <para>
/// Canonicalization <b>fails closed on data loss</b> (issue #36, VC Data Integrity 1.0 §2.4.3).
/// dotNetRDF on its own drops what it cannot turn into RDF, silently or with a warning, and
/// normalizes IRIs when it prints them. Whatever is dropped or respelled would not be signed.
/// So a JSON-LD input is rejected with <see cref="JsonLdDataLossException"/> when it uses a term
/// its <c>@context</c> does not define, has an IRI that is not a well-formed absolute IRI in any
/// position (subject, type, property, value, named graph, list member, datatype), has a
/// malformed language tag, uses a blank node as a property, uses <c>@direction</c> or
/// <c>@index</c>, or has an IRI the canonical N-Quads would spell differently (dot segments,
/// percent-encoded unreserved or non-ASCII characters, upper-case scheme or host, a default
/// port). Accepted input canonicalizes to exactly the bytes it did before, and every IRI in the
/// output is spelled as in the input. N-Quads input with an IRI that would be respelled is
/// rejected too. JSON-LD constructs that produce no RDF by definition (a <c>null</c> value, a
/// top-level value or node that carries nothing but an <c>@id</c>) are not data loss here, and
/// numbers are signed in their canonical XSD form, so <c>1</c> and <c>1.0</c> sign the same.
/// </para>
/// </remarks>
public sealed class RdfcDocumentCanonicalizer : IRdfCanonicalizer
{
    private readonly IDocumentLoader _documentLoader;

    /// <summary>Creates a canonicalizer over the offline-default document loader (FR-10).</summary>
    public RdfcDocumentCanonicalizer()
        : this(OfflineDocumentLoader.Instance)
    {
    }

    /// <summary>Creates a canonicalizer over the given document loader.</summary>
    public RdfcDocumentCanonicalizer(IDocumentLoader documentLoader)
    {
        ArgumentNullException.ThrowIfNull(documentLoader);
        _documentLoader = documentLoader;
    }

    /// <inheritdoc />
    public byte[] CanonicalizeJsonLd(JsonElement document, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
    {
        if (document.ValueKind != JsonValueKind.Object && document.ValueKind != JsonValueKind.Array)
        {
            throw new RdfCanonicalizationException("A JSON-LD document must be a JSON object or array.");
        }

        var json = document.GetRawText();
        var store = ParseJsonLd(json);
        return Encoding.UTF8.GetBytes(Canonicalize(store, hashAlgorithm).SerializedNQuads);
    }

    /// <inheritdoc />
    public string CanonicalizeNQuads(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
    {
        ArgumentNullException.ThrowIfNull(nQuads);
        var store = ParseNQuads(nQuads);
        return Canonicalize(store, hashAlgorithm).SerializedNQuads;
    }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, string> CanonicalizeNQuadsToMap(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
    {
        ArgumentNullException.ThrowIfNull(nQuads);
        var store = ParseNQuads(nQuads);
        var result = Canonicalize(store, hashAlgorithm);

        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in result.IssuedIdentifiersMap)
        {
            // Strip the "_:" blank-node prefix on both sides so the map matches the W3C
            // map fixtures' shape ({ "e0": "c14n0" }).
            map[StripBlankNodePrefix(pair.Key)] = StripBlankNodePrefix(pair.Value);
        }

        return map;
    }

    private TripleStore ParseJsonLd(string json)
    {
        // The audit and the parse expand the input separately, so they must see the same contexts:
        // a loader that answered differently the second time could otherwise get past the audit
        // input the parse then drops. Each context is loaded once per canonicalization.
        var contexts = new Dictionary<string, LoadedContextDocument>(StringComparer.Ordinal);
        var options = new JsonLdProcessorOptions
        {
            DocumentLoader = (uri, _) => LoadRemoteDocument(uri, contexts),
            // Reports what expansion drops (undefined terms, malformed language tags) as warnings
            // instead of discarding it silently (issue #36).
            SafeMode = true,
        };

        var store = new TripleStore();
        string? loss;
        try
        {
            loss = JsonLdLossAudit.FindLoss(json, options);
            if (loss is null)
            {
                // The parse itself is unchanged, so accepted input canonicalizes to the same bytes
                // as before; its warnings back up the audit, and the handler catches respellings.
                var handler = new ExactIriStoreHandler(store);
                var parser = new JsonLdParser(options);
                var warned = false;
                parser.Warning += _ => warned = true;
                parser.Load(handler, new StringReader(json), store.UriFactory);
                loss = warned ? JsonLdLossAudit.IgnoredContent
                    : handler.RespelledIri ? JsonLdLossAudit.RespelledIri
                    : null;
            }
        }
        catch (Exception ex)
        {
            // A fail-closed loader (offline) raises RdfCanonicalizationException; dotNetRDF
            // may wrap it in an RdfParseException — recover and rethrow it unchanged.
            if (Unwrap(ex) is RdfCanonicalizationException recovered)
            {
                throw recovered;
            }

            throw new RdfCanonicalizationException("JSON-LD expansion failed.", ex);
        }

        if (loss is not null)
        {
            throw new JsonLdDataLossException($"The JSON-LD input cannot be canonicalized without losing data: it {loss}.");
        }

        return store;
    }

    private static TripleStore ParseNQuads(string nQuads)
    {
        var store = new TripleStore();
        var handler = new ExactIriStoreHandler(store);
        try
        {
            var parser = new NQuadsParser();
            parser.Load(handler, new StringReader(nQuads), store.UriFactory);
        }
        catch (Exception ex)
        {
            throw new RdfCanonicalizationException("The N-Quads input could not be parsed.", ex);
        }

        if (handler.RespelledIri)
        {
            throw new RdfCanonicalizationException(
                $"The N-Quads input cannot be canonicalized as written: it {JsonLdLossAudit.RespelledIri}.");
        }

        return store;
    }

    private static RdfCanonicalizer.CanonicalizedRdfDataset Canonicalize(
        ITripleStore store, RdfCanonicalizationHashAlgorithm hashAlgorithm)
    {
        try
        {
            var canonicalizer = new RdfCanonicalizer(ToHashName(hashAlgorithm));
            return canonicalizer.Canonicalize(store);
        }
        catch (Exception ex)
        {
            // RDFC-1.0 negative/poison cases (e.g. the clique graph) surface here.
            throw new RdfCanonicalizationException("RDF Dataset Canonicalization (RDFC-1.0) failed.", ex);
        }
    }

    private static string ToHashName(RdfCanonicalizationHashAlgorithm hashAlgorithm) => hashAlgorithm switch
    {
        RdfCanonicalizationHashAlgorithm.Sha256 => "SHA256",
        RdfCanonicalizationHashAlgorithm.Sha384 => "SHA384",
        _ => throw new RdfCanonicalizationException($"Unsupported RDFC-1.0 hash algorithm '{hashAlgorithm}'."),
    };

    private static string StripBlankNodePrefix(string label)
        => label.StartsWith("_:", StringComparison.Ordinal) ? label[2..] : label;

    // Bridges the public IDocumentLoader to dotNetRDF's JSON-LD document-loader callback.
    // Newtonsoft's JToken lives only on this side of the boundary.
    private RemoteDocument LoadRemoteDocument(Uri uri, Dictionary<string, LoadedContextDocument> contexts)
    {
        if (!contexts.TryGetValue(uri.AbsoluteUri, out var loaded))
        {
            loaded = _documentLoader.Load(uri);
            contexts.Add(uri.AbsoluteUri, loaded);
        }

        // A fresh token per load: the processor must not see one expansion's state in the other.
        JToken token;
        try
        {
            token = JToken.Parse(loaded.Content);
        }
        catch (Exception ex)
        {
            throw new RdfCanonicalizationException($"The context '{uri.AbsoluteUri}' did not contain valid JSON.", ex);
        }

        return new RemoteDocument
        {
            Document = token,
            DocumentUrl = loaded.DocumentUrl,
        };
    }

    // dotNetRDF wraps a document-loader exception in an RdfParseException; recover our own.
    private static RdfCanonicalizationException? Unwrap(Exception ex)
    {
        for (Exception? current = ex; current is not null; current = current.InnerException)
        {
            if (current is RdfCanonicalizationException found)
            {
                return found;
            }
        }

        return null;
    }
}
