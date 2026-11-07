using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace GuvenliArsivGUI.Models
{
    public class ArchiveReport
    {
        [JsonPropertyName("file_name")]
        public string FileName { get; set; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("risk_level")]
        public string RiskLevel { get; set; } = "UNKNOWN";

        [JsonPropertyName("total_files")]
        public int TotalFiles { get; set; }

        [JsonPropertyName("compressed_size")]
        public long CompressedSize { get; set; }

        [JsonPropertyName("uncompressed_size")]
        public long UncompressedSize { get; set; }

        [JsonPropertyName("compression_ratio")]
        public double CompressionRatio { get; set; }

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

        [JsonPropertyName("warnings")]
        public List<string> Warnings { get; set; } = new();

        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }
}