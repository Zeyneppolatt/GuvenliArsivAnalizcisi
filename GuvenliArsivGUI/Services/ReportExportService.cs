using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using GuvenliArsivGUI.Models;

namespace GuvenliArsivGUI.Services
{
    public class ReportExportService
    {
        private static readonly JsonSerializerOptions ExportJsonOptions = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public async Task ExportToJsonAsync(string filePath, IEnumerable<ArchiveReport> reports)
        {
            string json = JsonSerializer.Serialize(reports, ExportJsonOptions);
            await File.WriteAllTextAsync(filePath, json, Encoding.UTF8);
        }

        public async Task ExportToCsvAsync(string filePath, IEnumerable<ArchiveReport> reports)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Dosya Adı;Durum;Risk Seviyesi;Risk Skoru;Toplam Dosya;Sıkıştırılmış (Bayt);Açılmış (Bayt);Sıkıştırma Oranı;Süre (ms);Uyarı Sayısı;Arşiv SHA-256");

            foreach (var r in reports)
            {
                string sha256 = r.ThreatIntel?.ArchiveSha256 ?? "";
                string safeName = EscapeCsv(r.FileName);
                sb.AppendLine($"{safeName};{r.Status};{r.RiskLevelTr};{r.RiskScore};{r.TotalFiles};{r.CompressedSize};{r.UncompressedSize};{r.CompressionRatioDisplay};{r.AnalysisTimeMs:F1};{r.Warnings.Count};{sha256}");
            }

            // Excel'de Türkçe karakterlerin bozulmaması için UTF-8 BOM ile yazılır
            await File.WriteAllTextAsync(filePath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        }

        private static string EscapeCsv(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(';') || value.Contains('"') || value.Contains('\n'))
            {
                return $"\"{value.Replace("\"", "\"\"")}\"";
            }
            return value;
        }
    }
}