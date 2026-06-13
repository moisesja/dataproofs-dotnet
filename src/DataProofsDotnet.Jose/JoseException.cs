namespace DataProofsDotnet.Jose;

/// <summary>
/// Base exception for every failure raised by the <c>DataProofsDotnet.Jose</c> package.
/// </summary>
/// <remarks>
/// Two concrete subtypes split the failure domains the same way the didcomm-dotnet porting
/// source does (PRD §1.4 item 2, AC-5): <see cref="MalformedJoseException"/> for structural /
/// input-shape errors and <see cref="JoseCryptoException"/> for cryptographic failures
/// (signature did not verify, AEAD tag mismatch, key unwrap failure). The split is
/// load-bearing — callers and the ported parity tests dispatch on the type.
/// </remarks>
public class JoseException : Exception
{
    /// <summary>Create the exception with a message.</summary>
    /// <param name="message">Human-readable description of the failure.</param>
    public JoseException(string message) : base(message) { }

    /// <summary>Create the exception with a message and inner cause.</summary>
    /// <param name="message">Human-readable description of the failure.</param>
    /// <param name="innerException">Underlying cause.</param>
    public JoseException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Raised when a JOSE structure (JWS/JWE serialization, protected header, JWK) is malformed:
/// missing required members, invalid base64url, invalid JSON, unsupported critical extensions.
/// </summary>
public sealed class MalformedJoseException : JoseException
{
    /// <summary>Create the exception with a message.</summary>
    /// <param name="message">Human-readable description of the structural failure.</param>
    public MalformedJoseException(string message) : base(message) { }

    /// <summary>Create the exception with a message and inner cause.</summary>
    /// <param name="message">Human-readable description of the structural failure.</param>
    /// <param name="innerException">Underlying cause (e.g. a <see cref="FormatException"/>).</param>
    public MalformedJoseException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Raised when a cryptographic operation over a structurally valid JOSE object fails:
/// no signature verifies, AEAD tag mismatch, AES-KW integrity failure, key/algorithm binding
/// violations, unresolvable keys.
/// </summary>
public sealed class JoseCryptoException : JoseException
{
    /// <summary>Create the exception with a message.</summary>
    /// <param name="message">Human-readable description of the cryptographic failure.</param>
    public JoseCryptoException(string message) : base(message) { }

    /// <summary>Create the exception with a message and inner cause.</summary>
    /// <param name="message">Human-readable description of the cryptographic failure.</param>
    /// <param name="innerException">Underlying cause (e.g. a CryptographicException from NetCrypto).</param>
    public JoseCryptoException(string message, Exception innerException) : base(message, innerException) { }
}
