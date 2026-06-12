using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;

namespace DataProofsDotnet.Cose.Internal;

/// <summary>
/// CWT claims-set CBOR encoding/decoding (RFC 8392 §3). Emission is canonical (integer claim
/// keys ascending, dates as integer epoch seconds); decoding accepts integer and floating-point
/// numeric dates per the RFC. CBOR types never escape this type (AC-7).
/// </summary>
internal static class CwtClaimsCodec
{
    private const long IssKey = 1;
    private const long SubKey = 2;
    private const long AudKey = 3;
    private const long ExpKey = 4;
    private const long NbfKey = 5;
    private const long IatKey = 6;
    private const long CtiKey = 7;

    internal static byte[] Encode(CwtClaims claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        int count = (claims.Issuer is not null ? 1 : 0)
            + (claims.Subject is not null ? 1 : 0)
            + (claims.Audience is not null ? 1 : 0)
            + (claims.ExpirationTime is not null ? 1 : 0)
            + (claims.NotBefore is not null ? 1 : 0)
            + (claims.IssuedAt is not null ? 1 : 0)
            + (claims.CwtId is not null ? 1 : 0);
        writer.WriteStartMap(count);
        if (claims.Issuer is not null)
        {
            writer.WriteInt64(IssKey);
            writer.WriteTextString(claims.Issuer);
        }

        if (claims.Subject is not null)
        {
            writer.WriteInt64(SubKey);
            writer.WriteTextString(claims.Subject);
        }

        if (claims.Audience is not null)
        {
            writer.WriteInt64(AudKey);
            writer.WriteTextString(claims.Audience);
        }

        WriteDate(writer, ExpKey, claims.ExpirationTime);
        WriteDate(writer, NbfKey, claims.NotBefore);
        WriteDate(writer, IatKey, claims.IssuedAt);
        if (claims.CwtId is { } cti)
        {
            writer.WriteInt64(CtiKey);
            writer.WriteByteString(cti.Span);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static void WriteDate(CborWriter writer, long key, DateTimeOffset? value)
    {
        if (value is { } date)
        {
            writer.WriteInt64(key);
            writer.WriteInt64(date.ToUnixTimeSeconds()); // sub-second precision truncates (NumericDate)
        }
    }

    internal static bool TryDecode(ReadOnlyMemory<byte> encodedClaimsSet, [NotNullWhen(true)] out CwtClaims? claims, [NotNullWhen(false)] out string? error)
    {
        claims = null;
        error = null;
        string? issuer = null, subject = null, audience = null;
        DateTimeOffset? exp = null, nbf = null, iat = null;
        byte[]? cwtId = null;
        try
        {
            var reader = new CborReader(encodedClaimsSet, CborConformanceMode.Lax);
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.PeekState())
                {
                    case CborReaderState.UnsignedInteger:
                    case CborReaderState.NegativeInteger:
                        long key = reader.ReadInt64();
                        switch (key)
                        {
                            case IssKey:
                                issuer = reader.ReadTextString();
                                break;
                            case SubKey:
                                subject = reader.ReadTextString();
                                break;
                            case AudKey:
                                audience = reader.ReadTextString();
                                break;
                            case ExpKey:
                                exp = ReadNumericDate(reader);
                                break;
                            case NbfKey:
                                nbf = ReadNumericDate(reader);
                                break;
                            case IatKey:
                                iat = ReadNumericDate(reader);
                                break;
                            case CtiKey:
                                cwtId = reader.ReadByteString();
                                break;
                            default:
                                reader.SkipValue(); // unregistered integer claim key: ignored in v1
                                break;
                        }

                        break;

                    case CborReaderState.TextString:
                        reader.ReadTextString();
                        reader.SkipValue(); // text claim keys (RFC 8392 §3) are not modeled in v1
                        break;

                    default:
                        error = "CWT claim keys must be integers or text strings (RFC 8392 §3).";
                        return false;
                }
            }

            reader.ReadEndMap();
            if (reader.BytesRemaining > 0)
            {
                error = "Trailing bytes follow the CWT claims map.";
                return false;
            }
        }
        catch (CborContentException ex)
        {
            error = $"Malformed CWT claims set: {ex.Message}";
            return false;
        }
        catch (InvalidOperationException ex)
        {
            error = $"A CWT claim has an unexpected CBOR type: {ex.Message}";
            return false;
        }
        catch (OverflowException)
        {
            error = "A CWT claim integer is outside the supported range.";
            return false;
        }

        claims = new CwtClaims
        {
            Issuer = issuer,
            Subject = subject,
            Audience = audience,
            ExpirationTime = exp,
            NotBefore = nbf,
            IssuedAt = iat,
            // The explicit null check matters: the implicit byte[] conversion would otherwise
            // wrap a null array as a non-null empty memory.
            CwtId = cwtId is null ? null : (ReadOnlyMemory<byte>?)cwtId,
        };
        return true;
    }

    private static DateTimeOffset ReadNumericDate(CborReader reader)
    {
        switch (reader.PeekState())
        {
            case CborReaderState.UnsignedInteger:
            case CborReaderState.NegativeInteger:
                return DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64());

            case CborReaderState.HalfPrecisionFloat:
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
                double seconds = reader.ReadDouble();
                if (!double.IsFinite(seconds) || Math.Abs(seconds) > 253402300799d) // 9999-12-31T23:59:59Z
                {
                    throw new CborContentException("A CWT numeric date is not a finite value in the representable range.");
                }

                return DateTimeOffset.FromUnixTimeMilliseconds(checked((long)(seconds * 1000d)));

            default:
                throw new CborContentException("CWT date claims (exp/nbf/iat) must be integer or floating-point numeric dates (RFC 8392 §2).");
        }
    }
}
