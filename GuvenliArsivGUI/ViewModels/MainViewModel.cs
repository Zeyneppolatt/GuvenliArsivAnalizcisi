using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using GuvenliArsivGUI.Models;
using GuvenliArsivGUI.Services;

namespace GuvenliArsivGUI.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".7z", ".rar", ".tar", ".gz"
        };

        private readonly ZipAnalyzerService _analyzerService;
        private readonly IDialogService _dialogService;
        private readonly ReportExportService _exportService;
        private readonly AppSettingsService _settingsService;
        private readonly AppSettings _settings;
        private CancellationTokenSource? _activeCts;

        private bool _isBusy;
        private string _statusMessage = string.Empty;
        private string _vtApiKey = string.Empty;
        private bool _safeMode = true;
        private ArchiveReport? _selectedReport;

        public MainViewModel(
            ZipAnalyzerService analyzerService,
            IDialogService dialogService,
            ReportExportService exportService,
            AppSettingsService settingsService,
            AppSettings settings)
        {
            _analyzerService = analyzerService;
            _dialogService = dialogService;
            _exportService = exportService;
            _settingsService = settingsService;
            _settings = settings;
            _safeMode = settings.SafeMode;

            _statusMessage = _analyzerService.IsConfigured
                ? "Analiz için seçim yapın veya arşiv/klasör sürükleyip bırakın..."
                : "Analiz motoru otomatik bulunamadı. Lütfen '⚙ Motor Seç' butonundan main.py veya zipanalyzer.exe seçin.";

            SelectFilesCommand = new RelayCommand(async () => await SelectAndAnalyzeFilesAsync(), () => !IsBusy && _analyzerService.IsConfigured);
            SelectFolderCommand = new RelayCommand(async () => await SelectAndAnalyzeFolderAsync(), () => !IsBusy && _analyzerService.IsConfigured);
            SelectEngineCommand = new RelayCommand(SelectAndSaveEngine, () => !IsBusy);
            CancelAnalysisCommand = new RelayCommand(CancelAnalysis, () => IsBusy);
            ExportJsonCommand = new RelayCommand(async () => await ExportReportsAsync(isJson: true), () => !IsBusy && Reports.Count > 0);
            ExportCsvCommand = new RelayCommand(async () => await ExportReportsAsync(isJson: false), () => !IsBusy && Reports.Count > 0);
            ClearReportsCommand = new RelayCommand(ClearReports, () => !IsBusy && Reports.Count > 0);
        }

        public ObservableCollection<ArchiveReport> Reports { get; } = new();

        public string ActiveEngineText => $"Motor: {_analyzerService.ActiveEngineDisplay}";

        public bool IsBusy
        {
            get => _isBusy;
            private set
            {
                if (SetProperty(ref _isBusy, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
        }

        public string VtApiKey
        {
            get => _vtApiKey;
            set => SetProperty(ref _vtApiKey, value);
        }

        public bool SafeMode
        {
            get => _safeMode;
            set
            {
                if (SetProperty(ref _safeMode, value))
                {
                    _settings.SafeMode = value;
                    _settingsService.Save(_settings);
                }
            }
        }

        public ArchiveReport? SelectedReport
        {
            get => _selectedReport;
            set
            {
                if (SetProperty(ref _selectedReport, value))
                {
                    OnPropertyChanged(nameof(HasSelectedReport));
                    OnPropertyChanged(nameof(DetailHeader));
                    OnPropertyChanged(nameof(DetailStats));
                    OnPropertyChanged(nameof(SelectedScoreCard));
                    OnPropertyChanged(nameof(SelectedTimeCard));
                    OnPropertyChanged(nameof(SelectedRatioCard));
                    OnPropertyChanged(nameof(SelectedFilesCard));
                    OnPropertyChanged(nameof(SelectedWarnings));
                    OnPropertyChanged(nameof(TechnicalFindingsText));
                }
            }
        }

        public bool HasSelectedReport => SelectedReport != null;

        public string DetailHeader => SelectedReport == null
            ? string.Empty
            : $"{SelectedReport.FileName}  [{SelectedReport.RiskLevelTr}]";

        public string DetailStats => SelectedReport == null
            ? string.Empty
            : $"Sıkıştırılmış: {FormatBytes(SelectedReport.CompressedSize)}  |  Açılmış: {FormatBytes(SelectedReport.UncompressedSize)}  |  Durum: {SelectedReport.Status}";

        public string SelectedScoreCard => SelectedReport == null ? "-" : $"{SelectedReport.RiskScore} / 100";
        public string SelectedTimeCard => SelectedReport == null ? "-" : $"{SelectedReport.AnalysisTimeMs:F1} ms";
        public string SelectedRatioCard => SelectedReport == null ? "-" : SelectedReport.CompressionRatioDisplay;
        public string SelectedFilesCard => SelectedReport == null ? "-" : $"{SelectedReport.TotalFiles} öğe";
        
        public IEnumerable<string> SelectedWarnings
        {
            get
            {
                if (SelectedReport == null) return Enumerable.Empty<string>();
                return SelectedReport.Warnings.Count > 0
                    ? SelectedReport.Warnings
                    : new[] { "Herhangi bir güvenlik uyarısı tespit edilmedi." };
            }
        }

        public string TechnicalFindingsText => SelectedReport == null ? string.Empty : BuildTechnicalFindings(SelectedReport);

        public ICommand SelectFilesCommand { get; }
        public ICommand SelectFolderCommand { get; }
        public ICommand SelectEngineCommand { get; }
        public ICommand CancelAnalysisCommand { get; }
        public ICommand ExportJsonCommand { get; }
        public ICommand ExportCsvCommand { get; }
        public ICommand ClearReportsCommand { get; }

        private void SelectAndSaveEngine()
        {
            string? selectedPath = _dialogService.OpenEngineFile();
            if (string.IsNullOrWhiteSpace(selectedPath)) return;

            try
            {
                _analyzerService.ConfigureEngine(selectedPath);
                _settings.CustomEnginePath = selectedPath;
                _settingsService.Save(_settings);

                OnPropertyChanged(nameof(ActiveEngineText));
                CommandManager.InvalidateRequerySuggested();
                StatusMessage = $"Motor başarıyla ayarlandı ve kaydedildi: {_analyzerService.ActiveEngineDisplay}";
            }
            catch (Exception ex)
            {
                _dialogService.ShowError("Motor Seçim Hatası", ex.Message);
            }
        }

        public async Task HandleDroppedPathsAsync(string[]? droppedPaths)
        {
            if (!_analyzerService.IsConfigured)
            {
                StatusMessage = "Önce '⚙ Motor Seç' butonundan analiz motorunu seçmelisiniz.";
                return;
            }

            if (IsBusy)
            {
                StatusMessage = "Devam eden bir analiz var. Lütfen bitmesini bekleyin veya iptal edin.";
                return;
            }

            if (droppedPaths == null || droppedPaths.Length == 0)
                return;

            var validTargets = new List<string>();
            var skippedFiles = new List<string>();

            foreach (var path in droppedPaths)
            {
                if (Directory.Exists(path))
                {
                    validTargets.Add(path);
                }
                else if (File.Exists(path))
                {
                    if (SupportedExtensions.Contains(Path.GetExtension(path)))
                        validTargets.Add(path);
                    else
                        skippedFiles.Add(Path.GetFileName(path));
                }
            }

            if (validTargets.Count == 0)
            {
                StatusMessage = "Desteklenen arşiv dosyası (.zip, .7z, .rar, .tar, .gz) veya klasör bulunamadı.";
                return;
            }

            await AnalyzeTargetsAsync(validTargets);

            if (skippedFiles.Count > 0)
            {
                StatusMessage += $" ({skippedFiles.Count} desteklenmeyen dosya atlandı)";
            }
        }

        private async Task SelectAndAnalyzeFilesAsync()
        {
            var files = _dialogService.OpenArchiveFiles();
            if (files is { Length: > 0 })
            {
                await AnalyzeTargetsAsync(files);
            }
        }

        private async Task SelectAndAnalyzeFolderAsync()
        {
            var folder = _dialogService.OpenFolder();
            if (!string.IsNullOrWhiteSpace(folder))
            {
                await AnalyzeTargetsAsync(new[] { folder });
            }
        }

        public async Task AnalyzeTargetsAsync(IReadOnlyList<string> targets)
        {
            if (IsBusy || !_analyzerService.IsConfigured || targets.Count == 0) return;

            IsBusy = true;
            _activeCts = new CancellationTokenSource();
            var token = _activeCts.Token;

            Reports.Clear();
            SelectedReport = null;

            try
            {
                for (int i = 0; i < targets.Count; i++)
                {
                    token.ThrowIfCancellationRequested();

                    string currentTarget = targets[i];
                    string displayName = Path.GetFileName(currentTarget.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    StatusMessage = targets.Count > 1
                        ? $"Analiz ediliyor ({i + 1}/{targets.Count}): {displayName}..."
                        : $"Analiz ediliyor: {displayName}...";

                    var batchResults = await _analyzerService.AnalyzeAsync(currentTarget, VtApiKey, SafeMode, token);

                    foreach (ArchiveReport report in batchResults)
                    {
                        Reports.Add(report);
                        SelectedReport ??= report;
                    }
                }

                StatusMessage = $"Analiz tamamlandı. Toplam {Reports.Count} arşiv incelendi.";
            }
            catch (OperationCanceledException)
            {
                StatusMessage = $"Analiz kullanıcı tarafından iptal edildi. ({Reports.Count} arşiv tamamlanmıştı)";
            }
            catch (Exception ex)
            {
                StatusMessage = "Analiz sırasında hata oluştu.";
                _dialogService.ShowError("Analiz Hatası", ex.Message);
            }
            finally
            {
                _activeCts?.Dispose();
                _activeCts = null;
                IsBusy = false;
            }
        }

        public void CancelAnalysis()
        {
            if (IsBusy && _activeCts is { IsCancellationRequested: false })
            {
                StatusMessage = "Analiz iptal ediliyor...";
                _activeCts.Cancel();
            }
        }

        private void ClearReports()
        {
            Reports.Clear();
            SelectedReport = null;
            StatusMessage = "Sonuç listesi temizlendi.";
        }

        private async Task ExportReportsAsync(bool isJson)
        {
            if (Reports.Count == 0) return;

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string defaultName = $"GuvenliArsiv_Rapor_{timestamp}.{(isJson ? "json" : "csv")}";
            string filter = isJson ? "JSON Raporu (*.json)|*.json" : "CSV Tablosu (*.csv)|*.csv";

            string? path = _dialogService.SaveReportFile(defaultName, filter);
            if (string.IsNullOrWhiteSpace(path)) return;

            try
            {
                if (isJson)
                    await _exportService.ExportToJsonAsync(path, Reports);
                else
                    await _exportService.ExportToCsvAsync(path, Reports);

                StatusMessage = $"Rapor kaydedildi: {Path.GetFileName(path)}";
            }
            catch (Exception ex)
            {
                _dialogService.ShowError("Dışa Aktarma Hatası", $"Dosya kaydedilemedi:\n{ex.Message}");
            }
        }

        private static string BuildTechnicalFindings(ArchiveReport r)
        {
            var sb = new StringBuilder();

            if (!string.IsNullOrWhiteSpace(r.Error))
            {
                sb.AppendLine("[Motor Hata Mesajı]");
                sb.AppendLine($"  {r.Error}");
                sb.AppendLine();
            }

            if (r.ThreatIntel != null)
            {
                sb.AppendLine("[Tehdit İstihbaratı & Bütünlük]");
                if (!string.IsNullOrWhiteSpace(r.ThreatIntel.ArchiveSha256))
                    sb.AppendLine($"  Arşiv SHA-256 : {r.ThreatIntel.ArchiveSha256}");

                if (!string.IsNullOrWhiteSpace(r.ThreatIntel.YaraStatus))
                    sb.AppendLine($"  YARA Durumu   : {r.ThreatIntel.YaraStatus} (Eşleşme: {r.ThreatIntel.YaraMatches.Count})");

                if (r.ThreatIntel.VirusTotal is { } vt)
                {
                    sb.AppendLine($"  VirusTotal    : {vt.Status ?? "Bilinmiyor"} (Zararlı: {vt.Malicious}, Şüpheli: {vt.Suspicious}, Temiz: {vt.Harmless})");
                    if (!string.IsNullOrWhiteSpace(vt.Message))
                        sb.AppendLine($"  VT Notu       : {vt.Message}");
                }
                sb.AppendLine();
            }

            AppendCategory(sb, "Yüksek Sıkıştırma Oranlı Dosyalar (Zip Bomb)", r.HighRatioFiles);
            AppendCategory(sb, "Çakışan Arşiv Kayıtları (Overlap Bomb)", r.OverlappingEntries);
            AppendCategory(sb, "Maskelenmiş / Sahte Uzantılı Dosyalar", r.DisguisedFiles);
            AppendCategory(sb, "Şüpheli Dosya Yolları (Path Traversal)", r.SuspiciousPaths);
            AppendCategory(sb, "Çift Uzantılı Dosyalar", r.DoubleExtensionFiles);
            AppendCategory(sb, "Şüpheli Uzantılı Dosyalar", r.SuspiciousFiles);
            AppendCategory(sb, "Sembolik Bağlantılar (Symlink)", r.SymlinkFiles);
            AppendCategory(sb, "Şifreli Dosyalar", r.EncryptedFiles);
            AppendCategory(sb, "İç İçe Arşivler", r.NestedArchives);

            if (r.NestedArchiveReports.Count > 0)
            {
                sb.AppendLine("[İç İçe Arşiv Alt Raporları]");
                foreach (var nested in r.NestedArchiveReports)
                {
                    sb.AppendLine($"  • {nested.FileName} -> Risk: {nested.RiskLevelTr} (Skor: {nested.RiskScore}, Dosya: {nested.TotalFiles})");
                }
                sb.AppendLine();
            }

            if (r.FileHashes.Count > 0)
            {
                sb.AppendLine("[Dosya SHA-256 Özetleri]");
                foreach (var kv in r.FileHashes)
                {
                    sb.AppendLine($"  • {kv.Key}: {kv.Value}");
                }
                sb.AppendLine();
            }

            return sb.Length > 0 ? sb.ToString().Trim() : "Ek teknik bulgu kaydı yok.";
        }

        private static void AppendCategory(StringBuilder sb, string title, List<string> items)
        {
            if (items == null || items.Count == 0) return;
            sb.AppendLine($"[{title}]");
            foreach (var item in items)
            {
                sb.AppendLine($"  - {item}");
            }
            sb.AppendLine();
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F2} MB";
        }
    }
}