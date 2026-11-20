# Provenance — RFC 7515 Appendix B (`x5c` example)

- **Origin URL:** https://www.rfc-editor.org/rfc/rfc7515.txt
- **Document version:** RFC 7515, "JSON Web Signature (JWS)", May 2015 (final; RFCs do not change)
- **Retrieval date:** 2026-11-19
- **Local transformation:** the JSON array printed in Appendix B was copied with the display line breaks and
  indentation removed (the RFC says they are "for display purposes only"), and wrapped in an object as
  `{"source": "RFC 7515 Appendix B", "x5c": [...]}`. Each of the three strings decodes as canonical base64 to a DER
  certificate (1250, 1279 and 747 octets): Go Daddy Secure Certification Authority, Go Daddy Class 2 Certification
  Authority, and the ValiCert Class 2 Policy Validation Authority root, all with RSA keys.
- **Used by:** `tests/DataProofsDotnet.Jose.Tests/X509/X5cReviewRound1Tests.cs` (issue #46): a real-world chain whose
  structure the strict reading must accept, and whose RSA end-entity key is `X5C_UNSUPPORTED_KEY`.

## Fixture count: 1 file

| File | SHA-256 of vendored copy |
|---|---|
| `appendix-b-x5c.json` | `03577255a60f7731940a22db6123ef0f1c2472fac0db3b7013f2006c86241855` |
