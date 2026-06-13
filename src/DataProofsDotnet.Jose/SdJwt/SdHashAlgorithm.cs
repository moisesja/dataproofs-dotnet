using System.Text;
using NetCrypto;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// The hash function an SD-JWT uses for disclosure digests and the Key Binding JWT
/// <c>sd_hash</c>, named by the <c>_sd_alg</c> claim (RFC 9901 §4.1.1). Values are the IANA
/// "Named Information Hash Algorithm" identifiers (<c>sha-256</c>, <c>sha-384</c>,
/// <c>sha-512</c>); when <c>_sd_alg</c> is absent the default is <c>sha-256</c> (RFC 9901 §4.1.1).
/// </summary>
/// <remarks>
/// Every hash routes through NetCrypto's <see cref="Hash"/> API (PRD §2.2 / NFR — no
/// <c>System.Security.Cryptography</c> hashing primitive in <c>src/</c>). Only the SHA-2 family
/// NetCrypto exposes is supported; any other <c>_sd_alg</c> is rejected with
/// <see cref="MalformedJoseException"/> rather than silently downgraded
/// (RFC 9901 §10 security consideration on hash-algorithm choice).
/// </remarks>
public static class SdHashAlgorithm
{
    /// <summary>The IANA name for SHA-256 (the SD-JWT default when <c>_sd_alg</c> is absent).</summary>
    public const string Sha256 = "sha-256";

    /// <summary>The IANA name for SHA-384.</summary>
    public const string Sha384 = "sha-384";

    /// <summary>The IANA name for SHA-512.</summary>
    public const string Sha512 = "sha-512";

    /// <summary>The default <c>_sd_alg</c> value used when the SD-JWT omits the claim (RFC 9901 §4.1.1).</summary>
    public const string Default = Sha256;

    /// <summary>True when <paramref name="sdAlg"/> is a hash algorithm this library can compute via NetCrypto.</summary>
    /// <param name="sdAlg">An <c>_sd_alg</c> value, or <c>null</c>.</param>
    public static bool IsSupported(string? sdAlg) => sdAlg is Sha256 or Sha384 or Sha512;

    /// <summary>
    /// Compute the base64url-no-pad digest of an ASCII disclosure string under the named
    /// algorithm: <c>base64url(hash(ASCII(disclosure)))</c> (RFC 9901 §4.2.5).
    /// </summary>
    /// <param name="sdAlg">The <c>_sd_alg</c> value naming the hash function.</param>
    /// <param name="encodedDisclosure">The base64url-encoded disclosure string.</param>
    /// <exception cref="MalformedJoseException">When <paramref name="sdAlg"/> is not a supported SHA-2 algorithm.</exception>
    public static string ComputeDigest(string sdAlg, string encodedDisclosure)
    {
        ArgumentNullException.ThrowIfNull(encodedDisclosure);
        // RFC 9901 §4.2.5: the digest input is the ASCII bytes of the base64url Disclosure string.
        var input = Encoding.ASCII.GetBytes(encodedDisclosure);
        return Base64Url.Encode(Hash(sdAlg, input));
    }

    /// <summary>
    /// Compute the base64url-no-pad <c>sd_hash</c> over the ASCII bytes of the presented SD-JWT
    /// up to and including the final <c>~</c> (RFC 9901 §7.3).
    /// </summary>
    /// <param name="sdAlg">The <c>_sd_alg</c> value naming the hash function.</param>
    /// <param name="sdJwtWithTrailingTilde">The presented SD-JWT (issuer JWT plus disclosures, KB-JWT excluded) ending in <c>~</c>.</param>
    /// <exception cref="MalformedJoseException">When <paramref name="sdAlg"/> is not a supported SHA-2 algorithm.</exception>
    public static string ComputeSdHash(string sdAlg, string sdJwtWithTrailingTilde)
    {
        ArgumentNullException.ThrowIfNull(sdJwtWithTrailingTilde);
        var input = Encoding.ASCII.GetBytes(sdJwtWithTrailingTilde);
        return Base64Url.Encode(Hash(sdAlg, input));
    }

    private static byte[] Hash(string sdAlg, ReadOnlySpan<byte> data) => sdAlg switch
    {
        Sha256 => NetCrypto.Hash.Sha256(data),
        Sha384 => NetCrypto.Hash.Sha384(data),
        Sha512 => NetCrypto.Hash.Sha512(data),
        _ => throw new MalformedJoseException(
            $"Unsupported SD-JWT '_sd_alg' value '{sdAlg}'. Supported: sha-256, sha-384, sha-512 (RFC 9901 §4.1.1)."),
    };
}
