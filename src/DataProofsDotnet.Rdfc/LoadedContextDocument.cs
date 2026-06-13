namespace DataProofsDotnet.Rdfc;

/// <summary>
/// A JSON-LD context document returned by an <see cref="IDocumentLoader"/> (FR-10):
/// the raw JSON contents plus the URL it was served from. The contents are a plain
/// <see cref="string"/> so no <c>dotNetRDF</c> or <c>Newtonsoft</c> type appears in the
/// loader's public surface (FR-9/AC-7); the canonicalizer re-parses them internally.
/// </summary>
public sealed record LoadedContextDocument
{
    /// <summary>Creates a loaded document.</summary>
    /// <param name="documentUrl">The (possibly redirect-resolved) URL the document was served from.</param>
    /// <param name="content">The raw JSON-LD context document contents.</param>
    public LoadedContextDocument(Uri documentUrl, string content)
    {
        ArgumentNullException.ThrowIfNull(documentUrl);
        ArgumentNullException.ThrowIfNull(content);
        DocumentUrl = documentUrl;
        Content = content;
    }

    /// <summary>The URL the document was served from (after any redirect).</summary>
    public Uri DocumentUrl { get; }

    /// <summary>The raw JSON-LD context document contents.</summary>
    public string Content { get; }
}
