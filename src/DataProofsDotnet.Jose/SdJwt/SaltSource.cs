namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Supplies the random salt for each Disclosure (RFC 9901 §4.2 RECOMMENDS at least 128 bits of
/// entropy). The salt is base64url-no-pad encoded. Randomness routes through the
/// <see cref="IJoseCryptoProvider.Fill(System.Span{byte})"/> CSPRNG, never <c>System.Random</c>
/// (NFR-5).
/// </summary>
internal static class SaltSource
{
    /// <summary>The salt entropy in bytes (128 bits, matching the RFC 9901 worked examples).</summary>
    public const int SaltByteLength = 16;

    /// <summary>Generate a fresh base64url-no-pad salt of <see cref="SaltByteLength"/> random bytes.</summary>
    /// <param name="cryptoProvider">The provider whose CSPRNG fills the salt buffer.</param>
    public static string Generate(IJoseCryptoProvider cryptoProvider)
    {
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        Span<byte> buffer = stackalloc byte[SaltByteLength];
        cryptoProvider.Fill(buffer);
        return Base64Url.Encode(buffer);
    }
}
