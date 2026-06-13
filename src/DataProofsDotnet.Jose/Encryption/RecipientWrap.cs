namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// One JWE recipient entry: the recipient key identifier and the AES-KW-wrapped CEK that only
/// the matching private (or symmetric) key can unwrap. Multi-recipient JWEs carry one of these
/// per kid. Ported from didcomm-dotnet <c>DidComm.Jose.Encryption.RecipientWrap</c>
/// (PRD §1.4 item 2).
/// </summary>
/// <param name="Kid">The recipient key identifier.</param>
/// <param name="EncryptedKey">The CEK wrapped under the per-recipient KEK (AES-KW output).</param>
internal sealed record RecipientWrap(string Kid, byte[] EncryptedKey);
