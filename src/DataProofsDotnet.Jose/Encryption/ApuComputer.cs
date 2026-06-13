namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// DIDComm-compatible <c>apu</c> recipe for the ECDH-1PU path:
/// <c>apu = base64url-no-pad( utf8( skid ) )</c>. Absent for ECDH-ES. Generic JOSE leaves
/// <c>apu</c> content open (RFC 7518 §4.6.1.2); this helper pins the profile the didcomm
/// porting source uses so 1PU envelopes built here interoperate with that ecosystem
/// (PRD §1.4 item 2, AC-5).
/// </summary>
public static class ApuComputer
{
    /// <summary>Compute the protected-header <c>apu</c> string form for the supplied <paramref name="skid"/>.</summary>
    /// <param name="skid">The sender key identifier.</param>
    /// <exception cref="ArgumentException">When <paramref name="skid"/> is null or empty.</exception>
    public static string Compute(string skid)
    {
        ArgumentException.ThrowIfNullOrEmpty(skid);
        return Base64Url.EncodeUtf8(skid);
    }
}
