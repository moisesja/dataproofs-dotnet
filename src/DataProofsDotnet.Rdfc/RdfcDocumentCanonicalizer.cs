using System.Text;
using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Rdfc.Internal;
using VDS.RDF;
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
/// <c>@index</c> (including a set object's, which expansion drops silently), or has an IRI the canonical N-Quads would spell differently (dot segments,
/// percent-encoded unreserved or non-ASCII characters, upper-case scheme or host, a default
/// port), resolves a relative IRI against <c>@base</c> (dotNetRDF resolves with <see cref="Uri"/>,
/// which respells it before any check could compare), or has two distinct terms the store would
/// merge (dotNetRDF's node equality compares parsed URI components, so <c>https://e.example</c> and
/// <c>https://e.example/</c> would be one subject, datatype or graph). A <c>@base</c> counts in the
/// input and in a scoped context a loaded context defines. A language tag must be ASCII letters,
/// digits and hyphens, and a number must fit a double. JSON whose meaning RFC 8259 leaves
/// unpredictable (an unpaired-surrogate escape, a duplicate member name, invalid UTF-8, nesting past
/// 64) is refused with <see cref="RdfCanonicalizationException"/>, as the suites already do. Accepted input canonicalizes to exactly the bytes it did before, and every IRI in the
/// output is spelled as in the input. N-Quads input with an IRI that would be respelled, terms the
/// store would merge, or an unpaired surrogate is rejected too. JSON-LD constructs that produce no RDF by definition (a <c>null</c> value, a
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

        // The JSON whose meaning RFC 8259 leaves unpredictable, which the JSON-LD processor would resolve
        // silently: an unpaired-surrogate escape (read as U+FFFD), a duplicate member name (the last one
        // wins), invalid UTF-8, or nesting past 64. The suites check before calling, but this is public
        // API (adversarial review, F4; the issue #33 check, which also strips comments and trailing commas).
        if (!JsonInputCheck.TryAccept(document, out var accepted, out var problem))
        {
            throw new RdfCanonicalizationException($"The JSON-LD input {problem}.");
        }

        var json = accepted.GetRawText();
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
        // The audit and the parse expand the input separately, so they must see the same contexts.
        var contexts = new JsonLdContextCache(_documentLoader);

        var store = new TripleStore();
        string? loss;
        try
        {
            loss = JsonLdLossAudit.FindLoss(json, contexts);
            if (loss is null)
            {
                // The parse itself is unchanged, so accepted input canonicalizes to the same bytes
                // as before; its warnings back up the audit, and the handler catches respellings.
                var handler = new ExactIriStoreHandler(store);
                var parser = new JsonLdParser(contexts.Options(ContextView.AsLoaded));
                var warned = false;
                parser.Warning += _ => warned = true;
                parser.Load(handler, new StringReader(json), store.UriFactory);
                loss = warned ? JsonLdLossAudit.IgnoredContent
                    : handler.RespelledIri ? JsonLdLossAudit.RespelledIri
                    : handler.UnpairedSurrogate ? JsonLdLossAudit.UnpairedSurrogate
                    : handler.MergedStatements ? JsonLdLossAudit.MergedTerms
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
            throw new JsonLdDataLossException(DataLossMessage(loss));
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

        var problem = handler.RespelledIri ? JsonLdLossAudit.RespelledIri
            : handler.UnpairedSurrogate ? JsonLdLossAudit.UnpairedSurrogate
            : handler.MergedStatements ? JsonLdLossAudit.MergedTerms
            : null;
        if (problem is not null)
        {
            throw new RdfCanonicalizationException($"The N-Quads input cannot be canonicalized as written: it {problem}.");
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

    private static string DataLossMessage(string loss)
        => $"The JSON-LD input cannot be canonicalized without losing data: it {loss}.";

    private static string ToHashName(RdfCanonicalizationHashAlgorithm hashAlgorithm) => hashAlgorithm switch
    {
        RdfCanonicalizationHashAlgorithm.Sha256 => "SHA256",
        RdfCanonicalizationHashAlgorithm.Sha384 => "SHA384",
        _ => throw new RdfCanonicalizationException($"Unsupported RDFC-1.0 hash algorithm '{hashAlgorithm}'."),
    };

    private static string StripBlankNodePrefix(string label)
        => label.StartsWith("_:", StringComparison.Ordinal) ? label[2..] : label;

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
