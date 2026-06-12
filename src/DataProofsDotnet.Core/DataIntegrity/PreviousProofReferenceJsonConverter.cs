using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// Shape-preserving converter for <see cref="PreviousProofReference"/>: a bare string
/// round-trips as a string, an array round-trips as an array (even with one element).
/// </summary>
internal sealed class PreviousProofReferenceJsonConverter : JsonConverter<PreviousProofReference>
{
    public override PreviousProofReference Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.String:
                var single = reader.GetString();
                if (string.IsNullOrEmpty(single))
                {
                    throw new JsonException("previousProof must be a non-empty string.");
                }

                return PreviousProofReference.FromSingle(single);

            case JsonTokenType.StartArray:
                var values = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType != JsonTokenType.String)
                    {
                        throw new JsonException("previousProof array entries must be strings.");
                    }

                    var value = reader.GetString();
                    if (string.IsNullOrEmpty(value))
                    {
                        throw new JsonException("previousProof array entries must be non-empty strings.");
                    }

                    values.Add(value);
                }

                if (values.Count == 0)
                {
                    throw new JsonException("previousProof array must contain at least one proof id.");
                }

                return PreviousProofReference.FromValues(values);

            default:
                throw new JsonException("previousProof must be a string or an array of strings.");
        }
    }

    public override void Write(Utf8JsonWriter writer, PreviousProofReference value, JsonSerializerOptions options)
    {
        if (value.IsArrayForm)
        {
            writer.WriteStartArray();
            foreach (var id in value.Values)
            {
                writer.WriteStringValue(id);
            }

            writer.WriteEndArray();
        }
        else
        {
            writer.WriteStringValue(value.Values[0]);
        }
    }
}
