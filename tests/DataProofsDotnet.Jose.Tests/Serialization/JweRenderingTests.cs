using System.Text.Json;
using DataProofsDotnet.Jose.Encryption;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Serialization;

/// <summary>
/// Issue #27: the General JSON JWE used to be rendered from an anonymous type with default
/// <see cref="JsonSerializerOptions"/>, which the System.Text.Json source generator cannot describe.
/// The <c>JsonObject</c> rendering that replaced it must emit the same bytes: the same member order and
/// the default HTML-safe escaping of the unprotected <c>kid</c> — unlike the JWS renderers' relaxed
/// encoder, a pre-existing inconsistency preserved on purpose because emitted bytes must not change.
/// </summary>
public sealed class JweRenderingTests
{
    [Fact]
    public void BuildA256Kw_GeneralJson_KeepsMemberOrderAndDefaultEscaping()
    {
        const string kid = "kek+1<é>&'";
        var crypto = new JoseCryptoProvider();
        var kek = new Jwk { Kty = "oct", K = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)), Kid = kid };

        var packed = JweBuilder.BuildA256Kw("hello"u8, [kek], JoseAlgorithms.A256Gcm, crypto);

        using var document = JsonDocument.Parse(packed);
        document.RootElement.EnumerateObject().Select(p => p.Name).Should().Equal("protected", "recipients", "iv", "ciphertext", "tag");
        var recipient = document.RootElement.GetProperty("recipients").EnumerateArray().Should().ContainSingle().Subject;
        recipient.EnumerateObject().Select(p => p.Name).Should().Equal("header", "encrypted_key");
        recipient.GetProperty("header").EnumerateObject().Select(p => p.Name).Should().Equal("kid");

        // The exact former rendering of the unprotected header object, produced by the exact former code.
        var formerHeader = JsonSerializer.Serialize(new { kid });
        formerHeader.Should().Contain("\\u002B", "the default encoder escapes '+', and that is what 1.3.x emitted");
        packed.Should().Contain(formerHeader);
        packed.Should().NotContain(" ").And.NotContain("\n");

        JweParser.PeekRecipients(packed).RecipientKids.Should().Equal(kid);
    }
}
