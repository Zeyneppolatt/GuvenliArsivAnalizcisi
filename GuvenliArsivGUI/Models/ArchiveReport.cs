using System;
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

        [JsonPropertyName("high_ratio_files")]
        public List<string> HighRatioFiles { get; set; } = new();

        [JsonPropertyName("overlapping_entries")]
        public List<string> OverlappingEntries { get; set; } = new();

        [JsonPropertyName("disguised_files")]
        public List<string> DisguisedFiles { get; set; } = new();

        [JsonPropertyName("file_hashes")]
        public List<FileHashInfo> FileHashes { get; set; } = new();

        [JsonPropertyName("warnings")]
        public List<string> Warnings { get; set; } = new();

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("threat_intel")]
        public ThreatIntelInfo? ThreatIntel { get; set; }

        [JsonIgnore]
        public string RiskLevelTr => RiskLevel switch
        {
            "HIGH" => "YÜKSEK",
            "MEDIUM" => "ORTA",
            "LOW" => "DÜŞÜK",
            _ => "BİLİNMİYOR"
        };

        [JsonIgnore]
        public string CompressionRatioDisplay =>
            double.IsInfinity(CompressionRatio) ? "∞" :
            double.IsNaN(CompressionRatio) ? "-" :
            $"{CompressionRatio:F2}x";
    }

    public class FileHashInfo
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = string.Empty;
    }

    public class ThreatIntelInfo
    {
        [JsonPropertyName("safe_mode")]
        public bool SafeMode { get; set; }

        [JsonPropertyName("archive_sha256")]
        public string? ArchiveSha256 { get; set; }

        [JsonPropertyName("archive_vt")]
        public VirusTotalResult? ArchiveVt { get; set; }

        [JsonPropertyName("yara_scan")]
        public YaraScanResult? YaraScan { get; set; }

        [JsonPropertyName("vt_malicious_count")]
        public int VtMaliciousCount { get; set; }

        [JsonPropertyName("yara_match_count")]
        public int YaraMatchCount { get; set; }
    }

    public class VirusTotalResult
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("reason")]
        public string? Reason { get; set; }

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
    }

    public class YaraScanResult
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("matches")]
        public List<YaraMatchInfo> Matches { get; set; } = new();
    }

    public class YaraMatchInfo
    {
        [JsonPropertyName("file_name")]
        public string FileName { get; set; } = string.Empty;

        [JsonPropertyName("rule")]
        public string Rule { get; set; } = string.Empty;

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;
    }
}