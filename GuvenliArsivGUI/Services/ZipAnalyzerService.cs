using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using GuvenliArsivGUI.Models;

namespace GuvenliArsivGUI.Services
{
    public class ZipAnalyzerService
    {
        private string? _resolvedEnginePath;
        private bool _isPackagedExe;

        public string? CustomEnginePath { get; private set; }
        public bool IsEngineAvailable => !string.IsNullOrWhiteSpace(_resolvedEnginePath) && File.Exists(_resolvedEnginePath);

        public string ActiveEngineDescription
        {
            get
            {
                if (!IsEngineAvailable) return "Motor bulunamadı";
                string fileName = Path.GetFileName(_resolvedEnginePath!);
                return _isPackagedExe ? $"Paket Motor ({fileName})" : $"Python ({fileName})";
            }
        }

        public ZipAnalyzerService(string? customEnginePath = null)
        {
            SetCustomEnginePath(customEnginePath);
        }

        public void SetCustomEnginePath(string? customPath)
        {
            CustomEnginePath = string.IsNullOrWhiteSpace(customPath) ? null : customPath;
            ResolveEngine();
        }

        private void ResolveEngine()
        {
            _resolvedEnginePath = null;
            _isPackagedExe = false;

            if (!string.IsNullOrWhiteSpace(CustomEnginePath) && File.Exists(CustomEnginePath))
            {
                _resolvedEnginePath = Path.GetFullPath(CustomEnginePath);
                _isPackagedExe = _resolvedEnginePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                return;
            }

            string baseDir = AppContext.BaseDirectory;
            string bundledExe = Path.Combine(baseDir, "engine", "zipanalyzer.exe");
            if (File.Exists(bundledExe))
            {
                _resolvedEnginePath = bundledExe;
                _isPackagedExe = true;
                return;
            }

            var dir = new DirectoryInfo(baseDir);
            while (dir != null)
            {
                string candidateMain = Path.Combine(dir.FullName, "main.py");
                if (File.Exists(candidateMain))
                {
                    _resolvedEnginePath = candidateMain;
                    _isPackagedExe = false;
                    return;
                }
                dir = dir.Parent;
            }
        }

        private string ResolvePythonInterpreter(string scriptDirectory)
        {
            var dir = new DirectoryInfo(scriptDirectory);
            while (dir != null)
            {
                string venvPython = Path.Combine(dir.FullName, ".venv", "Scripts", "python.exe");
                if (File.Exists(venvPython))
                    return venvPython;

                string venvPythonAlt = Path.Combine(dir.FullName, "venv", "Scripts", "python.exe");
                if (File.Exists(venvPythonAlt))
                    return venvPythonAlt;

                dir = dir.Parent;
            }
            return "python";
        }

        public async Task<List<ArchiveReport>> AnalyzeAsync(
            IEnumerable<string> targetPaths,
            bool recursive,
            bool safeMode,
            string? vtApiKey,
            CancellationToken cancellationToken = default)
        {
            if (!IsEngineAvailable)
                throw new FileNotFoundException("Analiz motoru (main.py veya zipanalyzer.exe) bulunamadı.");

            var validPaths = targetPaths.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
            var allReports = new List<ArchiveReport>();

            foreach (var path in validPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var batch = await AnalyzeSingleTargetAsync(path, safeMode, vtApiKey, cancellationToken);
                allReports.AddRange(batch);
            }

            return allReports;
        }

        private async Task<List<ArchiveReport>> AnalyzeSingleTargetAsync(
            string targetPath,
            bool safeMode,
            string? vtApiKey,
            CancellationToken cancellationToken)
        {
            string engineDir = Path.GetDirectoryName(_resolvedEnginePath!)!;
            var psi = new ProcessStartInfo
            {
                WorkingDirectory = engineDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            if (_isPackagedExe)
            {
                psi.FileName = _resolvedEnginePath!;
            }
            else
            {
                psi.FileName = ResolvePythonInterpreter(engineDir);
                psi.ArgumentList.Add(_resolvedEnginePath!);
            }

            // Python çıktısının Windows'ta CP1254 yerine kesinlikle UTF-8 olmasını sağla
            psi.Environment["PYTHONIOENCODING"] = "utf-8";
            psi.Environment["PYTHONUTF8"] = "1";

            // main.py CLI argümanları: [--unsafe-mode] path
            if (!safeMode)
                psi.ArgumentList.Add("--unsafe-mode");

            if (!string.IsNullOrWhiteSpace(vtApiKey))
                psi.Environment["VT_API_KEY"] = vtApiKey.Trim();

            psi.ArgumentList.Add(targetPath);

            using var process = new Process { StartInfo = psi };
            process.Start();

            using var registration = cancellationToken.Register(() =>
            {
                try
                {
                    if (!process.HasExited)
                        process.Kill(entireProcessTree: true);
                }
                catch { }
            });

            Task<string> stdOutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> stdErrTask = process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            string stdOut = await stdOutTask;
            string stdErr = await stdErrTask;

            if (string.IsNullOrWhiteSpace(stdOut))
            {
                throw new Exception($"Analiz motorundan çıktı alınamadı (Çıkış Kodu: {process.ExitCode}).\nHata: {stdErr}");
            }

            try
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals
                };

                string trimmed = stdOut.Trim();
                if (trimmed.StartsWith("["))
                {
                    return JsonSerializer.Deserialize<List<ArchiveReport>>(trimmed, options) ?? new List<ArchiveReport>();
                }
                else
                {
                    var single = JsonSerializer.Deserialize<ArchiveReport>(trimmed, options);
                    return single != null ? new List<ArchiveReport> { single } : new List<ArchiveReport>();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Motor çıktısı JSON olarak ayrıştırılamadı: {ex.Message}\nHam Çıktı: {stdOut}");
            }
        }
    }
}