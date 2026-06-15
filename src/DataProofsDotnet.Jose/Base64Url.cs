using System.Text;
using SystemBase64Url = System.Buffers.Text.Base64Url;

namespace DataProofsDotnet.Jose;

/// <summary>
/// Base64url-no-pad codec used throughout JOSE: protected-header serialization, JWS
/// signature/payload bytes, JWE encrypted-key/iv/ciphertext/tag, JWK key fields, and
/// <c>apu</c>/<c>apv</c> values.
/// </summary>
/// <remarks>
/// Thin wrapper over <c>System.Buffers.Text.Base64Url</c> (.NET 9+ BCL). One source of truth
/// so every site that handles JOSE bytes encodes and decodes identically; ad-hoc
/// <c>Convert.ToBase64String(...).Replace(...)</c> calls would each drift.
/// Ported from didcomm-dotnet <c>DidComm.Jose.Base64Url</c> (PRD §1.4 item 2).
/// </remarks>
public static class Base64Url
{
    /// <summary>Encode <paramref name="bytes"/> to base64url without padding.</summary>
    /// <param name="bytes">Bytes to encode.</param>
    public static string Encode(ReadOnlySpan<byte> bytes) => SystemBase64Url.EncodeToString(bytes);

    /// <summary>Encode a UTF-8 string's bytes to base64url without padding.</summary>
    /// <param name="utf8String">String to UTF-8-encode and then base64url-encode.</param>
    public static string EncodeUtf8(string utf8String)
    {
        ArgumentNullException.ThrowIfNull(utf8String);
        return Encode(Encoding.UTF8.GetBytes(utf8String));
    }

    /// <summary>Decode <paramref name="value"/> from base64url without padding to bytes.</summary>
    /// <param name="value">Base64url string (no padding).</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is null or empty.</exception>
    /// <exception cref="FormatException">When <paramref name="value"/> is not valid base64url.</exception>
    public static byte[] Decode(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);

        // Strict base64url-no-pad alphabet (RFC 4648 §5): A–Z a–z 0–9 '-' '_'. The BCL decoder
        // silently tolerates interior/surrounding ASCII whitespace and '=' padding, and accepts the
        // standard-base64 '+'/'/' — none of which are valid base64url. JOSE boundaries are always
        // strict no-pad, so reject anything outside the alphabet rather than decode it leniently
        // (the documented "valid base64url" contract; avoids encoding ambiguity).
        foreach (char c in value)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok)
                throw new FormatException("Value is not valid base64url (no padding or whitespace permitted).");
        }

        return SystemBase64Url.DecodeFromChars(value.AsSpan());
    }

    /// <summary>Decode a base64url string and return the bytes interpreted as a UTF-8 string.</summary>
    /// <param name="value">Base64url string.</param>
    public static string DecodeUtf8(string value) => Encoding.UTF8.GetString(Decode(value));
}
