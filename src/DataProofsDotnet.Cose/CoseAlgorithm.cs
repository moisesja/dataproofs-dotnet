namespace DataProofsDotnet.Cose;

/// <summary>
/// COSE signature algorithms supported in v1 (FR-19) — the same algorithm set as FR-13,
/// mapped to the IANA COSE Algorithms registry identifiers.
/// </summary>
public enum CoseAlgorithm
{
    /// <summary>EdDSA (RFC 9053 §2.2); Ed25519 keys only in v1. COSE algorithm identifier -8.</summary>
    EdDsa = -8,

    /// <summary>ECDSA with SHA-256 on P-256 (RFC 9053 §2.1). COSE algorithm identifier -7.</summary>
    ES256 = -7,

    /// <summary>ECDSA with SHA-384 on P-384 (RFC 9053 §2.1). COSE algorithm identifier -35.</summary>
    ES384 = -35,

    /// <summary>ECDSA with SHA-256 on secp256k1 (RFC 8812 §3.2). COSE algorithm identifier -47.</summary>
    ES256K = -47,
}
