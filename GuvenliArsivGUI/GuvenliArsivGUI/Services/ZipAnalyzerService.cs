using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals
        };

        private string? _executablePath;
        private string? _scriptPath;
        private string? _workingDirectory;

        public bool IsConfigured => !string.IsNullOrWhiteSpace(_executablePath) && !string.IsNullOrWhiteSpace(_workingDirectory);

        public string ActiveEngineDisplay { get; private set; } = "Motor seçilmedi";

        public ZipAnalyzerService(string? savedEnginePath = null)
        {
            // 1. Öncelik: Kullanıcının daha önce seçip kaydettiği yol
            if (!string.IsNullOrWhiteSpace(savedEnginePath) && File.Exists(savedEnginePath))
            {
                ConfigureEngine(savedEnginePath);
                return;
            }

            string baseDir = AppContext.BaseDirectory;

            // 2. Öncelik: Paketlenmiş bağımsız motor (engine/zipanalyzer.exe)
            string bundledExe = Path.Combine(baseDir, "engine", "zipanalyzer.exe");
            if (File.Exists(bundledExe))
            {
                ConfigureEngine(bundledExe);
                return;
            }

            // 3. Öncelik: Geliştirme ortamında yukarı klasörlerde main.py arama
            string? repoRoot = FindRepoRoot(baseDir);
            if (repoRoot != null)
            {
                ConfigureEngine(Path.Combine(repoRoot, "main.py"));
            }
        }

        public void ConfigureEngine(string selectedPath)
        {
            if (string.IsNullOrWhiteSpace(selectedPath) || !File.Exists(selectedPath))
            {
                throw new FileNotFoundException("Seçilen motor dosyası bulunamadı.", selectedPath);
            }

            string fullPath = Path.GetFullPath(selectedPath);
            string directory = Path.GetDirectoryName(fullPath)!;

            if (fullPath.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
            {
                _workingDirectory = directory;
                _scriptPath = fullPath;

                string venvPython = Path.Combine(directory, ".venv", "Scripts", "python.exe");
                _executablePath = File.Exists(venvPython) ? venvPython : "python";
                ActiveEngineDisplay = $"Python ({Path.GetFileName(fullPath)})";
            }
            else
            {
                _workingDirectory = directory;
                _scriptPath = null;
                _executablePath = fullPath;
                ActiveEngineDisplay = Path.GetFileName(fullPath);
            }
        }

        public async Task<List<ArchiveReport>> AnalyzeAsync(
            string targetPath,
            string? vtApiKey = null,
            bool safeMode = true,
            CancellationToken cancellationToken = default)
        {
            if (!IsConfigured || _executablePath == null || _workingDirectory == null)
            {
                throw new InvalidOperationException("Analiz motoru yapılandırılmamış. Lütfen 'Motor Seç' butonundan main.py veya zipanalyzer.exe dosyasını seçin.");
            }

            if (string.IsNullOrWhiteSpace(targetPath) || (!File.Exists(targetPath) && !Directory.Exists(targetPath)))
            {
                throw new FileNotFoundException("Analiz edilecek hedef dosya veya klasör bulunamadı.", targetPath);
            }

            var psi = new ProcessStartInfo
            {
                FileName = _executablePath,
                WorkingDirectory = _workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            if (_scriptPath != null)
            {
                psi.ArgumentList.Add(_scriptPath);
            }

            psi.ArgumentList.Add(targetPath);

            if (!safeMode)
            {
                psi.ArgumentList.Add("--unsafe-mode");
            }

            psi.Environment["PYTHONUTF8"] = "1";
            if (!string.IsNullOrWhiteSpace(vtApiKey))
            {
                psi.Environment["VT_API_KEY"] = vtApiKey.Trim();
            }

            using var process = new Process { StartInfo = psi };

            if (!process.Start())
            {
                throw new InvalidOperationException("Analiz motoru süreci başlatılamadı.");
            }

            await using var registration = cancellationToken.Register(() =>
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                }
            });

            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken);

            string stdout = (await stdoutTask).Trim();
            string stderr = (await stderrTask).Trim();

            if (string.IsNullOrWhiteSpace(stdout))
            {
                throw new InvalidOperationException(
                    $"Analiz motorundan çıktı alınamadı (Çıkış Kodu: {process.ExitCode}).\n{(string.IsNullOrWhiteSpace(stderr) ? "" : $"Hata: {stderr}")}");
            }

            try
            {
                if (stdout.StartsWith('['))
                {
                    return JsonSerializer.Deserialize<List<ArchiveReport>>(stdout, JsonOptions) ?? new List<ArchiveReport>();
                }

                if (stdout.StartsWith('{'))
                {
                    var single = JsonSerializer.Deserialize<ArchiveReport>(stdout, JsonOptions);
                    return single != null ? new List<ArchiveReport> { single } : new List<ArchiveReport>();
                }
            }
            catch (JsonException jex)
            {
                throw new InvalidOperationException(
                    $"Motor çıktısı JSON olarak ayrıştırılamadı: {jex.Message}\nHam Çıktı: {stdout}", jex);
            }

            throw new InvalidOperationException(
                $"Motor beklenmeyen bir çıktı üretti (Kod {process.ExitCode}):\n{stdout}\n{stderr}");
        }

        private static string? FindRepoRoot(string startDir)
        {
            var dir = new DirectoryInfo(startDir);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "main.py")))
                {
                    return dir.FullName;
                }
                dir = dir.Parent;
            }
            return null;
        }
    }
}