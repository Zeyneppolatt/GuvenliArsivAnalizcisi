using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using GuvenliArsivGUI.Models;

namespace GuvenliArsivGUI.Services
{
    public class ZipAnalyzerService
    {
        private readonly string _pythonExePath;
        private readonly string _mainScriptPath;

        public ZipAnalyzerService(string pythonProjectDirectory)
        {
            _mainScriptPath = Path.Combine(pythonProjectDirectory, "main.py");

            string localVenv = Path.Combine(pythonProjectDirectory, ".venv", "Scripts", "python.exe");
            string parentDir = Directory.GetParent(pythonProjectDirectory)?.FullName ?? pythonProjectDirectory;
            string parentVenv = Path.Combine(parentDir, ".venv", "Scripts", "python.exe");

            _pythonExePath = File.Exists(localVenv) ? localVenv : parentVenv;
        }

        public async Task<List<ArchiveReport>> AnalyzeAsync(string targetZipOrFolderPath)
        {
            if (!File.Exists(_pythonExePath))
                throw new FileNotFoundException("Sanal ortam python.exe bulunamadı.", _pythonExePath);

            if (!File.Exists(_mainScriptPath))
                throw new FileNotFoundException("main.py dosyası bulunamadı.", _mainScriptPath);

            var startInfo = new ProcessStartInfo
            {
                FileName = _pythonExePath,
                Arguments = $"\"{_mainScriptPath}\" \"{targetZipOrFolderPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            // Python'un Windows konsolunda Türkçe karakterleri UTF-8 basmasını zorunlu kılar
            startInfo.Environment["PYTHONUTF8"] = "1";
            startInfo.Environment["PYTHONIOENCODING"] = "utf-8";

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            string jsonOutput = await process.StandardOutput.ReadToEndAsync();
            string errorOutput = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            jsonOutput = jsonOutput.Trim();

            // Eğer geçerli bir JSON çıktısı döndüyse (UNKNOWN/ERROR statülü arşivler olsa bile) bunu parse et
            if (!string.IsNullOrEmpty(jsonOutput) && (jsonOutput.StartsWith("[") || jsonOutput.StartsWith("{")))
            {
                if (jsonOutput.StartsWith("["))
                {
                    return JsonSerializer.Deserialize<List<ArchiveReport>>(jsonOutput) ?? new List<ArchiveReport>();
                }
                else
                {
                    var singleReport = JsonSerializer.Deserialize<ArchiveReport>(jsonOutput);
                    return singleReport != null ? new List<ArchiveReport> { singleReport } : new List<ArchiveReport>();
                }
            }

            // Gerçek bir Python çökmesi (Syntax/Path hatası vb.) olduysa hata fırlat
            string detail = !string.IsNullOrWhiteSpace(errorOutput) ? errorOutput : jsonOutput;
            throw new Exception($"Python analiz hatası (Kod {process.ExitCode}):\n{detail}");
        }
    }
}