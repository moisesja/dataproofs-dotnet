using System.Text;
using NetCrypto;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// DIDComm-compatible <c>apv</c> recipe:
/// <c>apv = base64url-no-pad( SHA-256( sorted-recipient-kids-joined-with('.') ) )</c>.
/// The protected header's <c>apv</c> commits the JWE to its recipient list — a peer that
/// re-encodes the envelope without updating <c>apv</c> fails the receive-side re-derivation
/// check. Generic JOSE leaves <c>apv</c> content open (RFC 7518 §4.6.1.3); this helper pins
/// the profile of the didcomm porting source (PRD §1.4 item 2, AC-5). Hashing routes through
/// NetCrypto (PRD §2.2).
/// </summary>
public static class ApvComputer
{
    /// <summary>Compute the base64url-no-pad string form of <c>apv</c>.</summary>
    /// <param name="recipientKids">Recipient kids in any order; sorted lexicographically before hashing.</param>
    public static string Compute(IEnumerable<string> recipientKids)
        => Base64Url.Encode(ComputeBytes(recipientKids));

    /// <summary>Compute the raw 32-byte hash form of <c>apv</c> (used as the KDF <c>PartyVInfo</c>).</summary>
    /// <param name="recipientKids">Recipient kids in any order.</param>
    /// <exception cref="ArgumentException">When <paramref name="recipientKids"/> is empty.</exception>
    public static byte[] ComputeBytes(IEnumerable<string> recipientKids)
    {
        ArgumentNullException.ThrowIfNull(recipientKids);
        var sorted = recipientKids.OrderBy(k => k, StringComparer.Ordinal).ToArray();
        if (sorted.Length == 0)
            throw new ArgumentException("apv requires at least one recipient kid.", nameof(recipientKids));
        var joined = string.Join('.', sorted);
        // UTF-8 (not ASCII): recipient kids are typically DID URLs whose grammar is ASCII, but
        // Encoding.ASCII silently maps any non-ASCII byte to '?', which would alias two distinct
        // kid lists onto the same apv commitment. UTF-8 preserves every byte; identical for the
        // ASCII case, so the send/receive re-derivation still matches.
        return Hash.Sha256(Encoding.UTF8.GetBytes(joined));
    }
}
