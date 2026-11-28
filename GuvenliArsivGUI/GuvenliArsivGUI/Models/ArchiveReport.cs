using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GuvenliArsivGUI.Models
{
    public class ArchiveReport
    {
        [JsonPropertyName("file_name")]
        public string FileName { get; set; } = string.Empty;

        [JsonPropertyName("file_path")]
        public string? FilePath { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("risk_level")]
        public string RiskLevel { get; set; } = "UNKNOWN";

        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }

        [JsonPropertyName("analysis_time_ms")]
        public double AnalysisTimeMs { get; set; }

        [JsonPropertyName("total_files")]
        public int TotalFiles { get; set; }

        [JsonPropertyName("compressed_size")]
        public long CompressedSize { get; set; }

        [JsonPropertyName("uncompressed_size")]
        public long UncompressedSize { get; set; }

        [JsonPropertyName("compression_ratio")]
        public double? CompressionRatio { get; set; }

        [JsonPropertyName("file_types")]
        public Dictionary<string, int> FileTypes { get; set; } = new();

        [JsonPropertyName("nested_archives")]
        public List<string> NestedArchives { get; set; } = new();

        [JsonPropertyName("nested_archive_reports")]
        public List<ArchiveReport> NestedArchiveReports { get; set; } = new();

        [JsonPropertyName("suspicious_paths")]
        public List<string> SuspiciousPaths { get; set; } = new();

        [JsonPropertyName("encrypted_files")]
        public List<string> EncryptedFiles { get; set; } = new();

        [JsonPropertyName("symlink_files")]
        public List<string> SymlinkFiles { get; set; } = new();

        [JsonPropertyName("suspicious_files")]
        public List<string> SuspiciousFiles { get; set; } = new();

        [JsonPropertyName("double_extension_files")]
        public List<string> DoubleExtensionFiles { get; set; } = new();

        [JsonPropertyName("high_ratio_files")]
        [JsonConverter(typeof(FlexibleStringListConverter))]
        public List<string> HighRatioFiles { get; set; } = new();

        [JsonPropertyName("overlapping_entries")]
        [JsonConverter(typeof(FlexibleStringListConverter))]
        public List<string> OverlappingEntries { get; set; } = new();

        [JsonPropertyName("disguised_files")]
        [JsonConverter(typeof(FlexibleStringListConverter))]
        public List<string> DisguisedFiles { get; set; } = new();

        [JsonPropertyName("file_hashes")]
        public Dictionary<string, string> FileHashes { get; set; } = new();

        [JsonPropertyName("threat_intel")]
        public ThreatIntelReport? ThreatIntel { get; set; }

        [JsonPropertyName("warnings")]
        public List<string> Warnings { get; set; } = new();

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        // --- UI Yardımcı Özellikleri ---

        [JsonIgnore]
        public string RiskLevelTr => RiskLevel?.ToUpperInvariant() switch
        {
            "HIGH" => "YÜKSEK",
            "MEDIUM" => "ORTA",
            "LOW" => "DÜŞÜK",
            "ERROR" => "HATA",
            _ => "BİLİNMİYOR"
        };

        [JsonIgnore]
        public string CompressionRatioDisplay =>
            !CompressionRatio.HasValue || double.IsInfinity(CompressionRatio.Value) || double.IsNaN(CompressionRatio.Value)
                ? "∞"
                : $"{CompressionRatio.Value:F2}x";
    }

    public class ThreatIntelReport
    {
        [JsonPropertyName("archive_sha256")]
        public string? ArchiveSha256 { get; set; }

        [JsonPropertyName("yara_status")]
        public string? YaraStatus { get; set; }

        [JsonPropertyName("yara_matches")]
        [JsonConverter(typeof(FlexibleStringListConverter))]
        public List<string> YaraMatches { get; set; } = new();

        [JsonPropertyName("virustotal")]
        public VirusTotalReport? VirusTotal { get; set; }
    }

    public class VirusTotalReport
    {
        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("malicious")]
        public int Malicious { get; set; }

        [JsonPropertyName("suspicious")]
        public int Suspicious { get; set; }

        [JsonPropertyName("harmless")]
        public int Harmless { get; set; }

        [JsonPropertyName("undetected")]
        public int Undetected { get; set; }

        [JsonPropertyName("permalink")]
        public string? Permalink { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }
    }

    /// <summary>
    /// JSON dizisindeki öğeler string veya nesne (dict) gelse de okunabilir metne dönüştürür.
    /// </summary>
    public class FlexibleStringListConverter : JsonConverter<List<string>>
    {
        public override List<string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var list = new List<string>();
            if (reader.TokenType != JsonTokenType.StartArray)
            {
                reader.Skip();
                return list;
            }

            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                if (reader.TokenType == JsonTokenType.String)
                {
                    var val = reader.GetString();
                    if (!string.IsNullOrWhiteSpace(val)) list.Add(val);
                }
                else if (reader.TokenType == JsonTokenType.StartObject)
                {
                    using var doc = JsonDocument.ParseValue(ref reader);
                    var props = doc.RootElement.EnumerateObject()
                        .Select(p => $"{p.Name}: {p.Value}")
                        .ToList();
                    list.Add(string.Join(" | ", props));
                }
                else
                {
                    reader.Skip();
                }
            }
            return list;
        }

        public override void Write(Utf8JsonWriter writer, List<string> value, JsonSerializerOptions options)
        {
            JsonSerializer.Serialize(writer, value, options);
        }
    }
}