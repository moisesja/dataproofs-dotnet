using System.Net;
using System.Net.Http;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// FR-10 document-loader posture: the offline-default loader serves the version-pinned bundled
/// contexts and FAILS CLOSED on anything outside that set (no network), and the caching network
/// loader is never the default — it must be explicitly constructed to opt into retrieval.
/// </summary>
public sealed class DocumentLoaderTests
{
    [Theory]
    [InlineData("https://www.w3.org/ns/credentials/v2")]
    [InlineData("https://w3id.org/security/multikey/v1")]
    [InlineData("https://w3id.org/security/bbs/v1")]
    [InlineData("https://w3id.org/security/data-integrity/v2")]
    public void OfflineLoader_ServesBundledContext(string url)
    {
        var loaded = OfflineDocumentLoader.Instance.Load(new Uri(url));

        loaded.DocumentUrl.AbsoluteUri.Should().Be(url);
        // The served bytes are valid JSON-LD with an @context member.
        using var document = JsonDocument.Parse(loaded.Content);
        document.RootElement.TryGetProperty("@context", out _).Should().BeTrue();
    }

    [Fact]
    public void OfflineLoader_BundledContextUrls_AreAllServable()
    {
        foreach (var url in OfflineDocumentLoader.BundledContextUrls)
        {
            var act = () => OfflineDocumentLoader.Instance.Load(new Uri(url));
            act.Should().NotThrow($"bundled URL {url} must be servable");
        }
    }

    [Fact]
    public void OfflineLoader_FailsClosed_OnUnknownContext()
    {
        var act = () => OfflineDocumentLoader.Instance.Load(new Uri("https://example.com/not-bundled/v1"));

        act.Should().Throw<RdfCanonicalizationException>()
            .WithMessage("*not among the offline document loader's bundled contexts*");
    }

    [Fact]
    public void OfflineLoader_FailsClosed_WithinCanonicalization_OnUnknownContext()
    {
        // The fail-closed posture surfaces as RdfCanonicalizationException through the public
        // canonicalizer too (no silent network reach for an unbundled @context).
        var canonicalizer = new RdfcDocumentCanonicalizer();
        var document = JsonDocument.Parse("""{"@context":"https://example.com/unbundled/v1","name":"x"}""").RootElement;

        var act = () => canonicalizer.CanonicalizeJsonLd(document);

        act.Should().Throw<RdfCanonicalizationException>();
    }

    [Fact]
    public void CachingNetworkLoader_IsNotTheDefault()
    {
        // The canonicalizer's default loader is the offline loader; the caching loader is never
        // wired automatically. Proven by: the default canonicalizer fails closed on an unbundled
        // context (it would otherwise have fetched it).
        var canonicalizer = new RdfcDocumentCanonicalizer();
        var document = JsonDocument.Parse("""{"@context":"https://example.com/unbundled/v1","name":"x"}""").RootElement;

        canonicalizer.Invoking(c => c.CanonicalizeJsonLd(document))
            .Should().Throw<RdfCanonicalizationException>();
    }

    [Fact]
    public void CachingNetworkLoader_ServesBundledContextsOffline_WithoutNetwork()
    {
        // Even the opt-in caching loader serves the bundled set offline (no HTTP). A client that
        // refuses every request proves no network is reached for bundled contexts.
        using var httpClient = new HttpClient(new RefusingHandler());
        using var loader = new CachingNetworkDocumentLoader(httpClient);

        var loaded = loader.Load(new Uri("https://www.w3.org/ns/credentials/v2"));

        loaded.Content.Should().Contain("@context");
    }

    [Fact]
    public void CachingNetworkLoader_MustBeExplicitlyConstructed_ToReachNetwork()
    {
        // An unbundled context goes to the network ONLY because the caller deliberately built a
        // CachingNetworkDocumentLoader. The refusing handler turns the attempted fetch into an
        // RdfCanonicalizationException — demonstrating the network path is exercised here but
        // never by the default offline loader.
        using var httpClient = new HttpClient(new RefusingHandler());
        using var loader = new CachingNetworkDocumentLoader(httpClient);

        var act = () => loader.Load(new Uri("https://example.com/unbundled/v1"));

        act.Should().Throw<RdfCanonicalizationException>()
            .WithMessage("*Failed to retrieve context*");
    }

    // An HttpMessageHandler that refuses every request, proving no real network call is made.
    // The loader uses the synchronous Send path, so both overloads must refuse.
    private sealed class RefusingHandler : HttpMessageHandler
    {
        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("network access refused by test handler");

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("network access refused by test handler");
    }
}
