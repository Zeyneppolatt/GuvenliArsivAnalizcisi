using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using GuvenliArsivGUI.Models;
using GuvenliArsivGUI.Services;
using Microsoft.Win32;

namespace GuvenliArsivGUI.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly ZipAnalyzerService _analyzerService;
        private readonly AppSettingsService _settingsService;
        private CancellationTokenSource? _cts;

        private bool _isBusy;
        private bool _safeMode = true;
        private string _vtApiKey = string.Empty;
        private string _statusMessage = "Analiz için arşiv veya klasör seçin ya da pencereye sürükleyip bırakın.";
        private ArchiveReport? _selectedReport;

        public ObservableCollection<ArchiveReport> Reports { get; } = new();

        public RelayCommand SelectFilesCommand { get; }
        public RelayCommand SelectFolderCommand { get; }
        public RelayCommand SelectEngineCommand { get; }
        public RelayCommand CancelAnalysisCommand { get; }
        public RelayCommand ExportJsonCommand { get; }
        public RelayCommand ExportCsvCommand { get; }
        public RelayCommand ClearReportsCommand { get; }

        public MainViewModel()
        {
            _settingsService = new AppSettingsService();
            var settings = _settingsService.Load();

            _analyzerService = new ZipAnalyzerService(settings.CustomEnginePath);
            _safeMode = settings.SafeMode;
            _vtApiKey = settings.VtApiKey ?? string.Empty;

            SelectFilesCommand = new RelayCommand(_ => SelectFiles(), _ => !IsBusy);
            SelectFolderCommand = new RelayCommand(_ => SelectFolder(), _ => !IsBusy);
            SelectEngineCommand = new RelayCommand(_ => SelectEngine(), _ => !IsBusy);
            CancelAnalysisCommand = new RelayCommand(_ => CancelAnalysis(), _ => IsBusy);
            ExportJsonCommand = new RelayCommand(_ => ExportJson(), _ => !IsBusy && Reports.Count > 0);
            ExportCsvCommand = new RelayCommand(_ => ExportCsv(), _ => !IsBusy && Reports.Count > 0);
            ClearReportsCommand = new RelayCommand(_ => ClearReports(), _ => !IsBusy && Reports.Count > 0);

            if (!_analyzerService.IsEngineAvailable)
            {
                StatusMessage = "Uyarı: Analiz motoru bulunamadı. Lütfen üst çubuktan '⚙ Motor Seç' ile main.py veya zipanalyzer.exe seçin.";
            }
        }

        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                if (SetProperty(ref _isBusy, value))
                {
                    RefreshCommands();
                }
            }
        }

        public bool SafeMode
        {
            get => _safeMode;
            set
            {
                if (SetProperty(ref _safeMode, value))
                {
                    SaveCurrentSettings();
                }
            }
        }

        public string VtApiKey
        {
            get => _vtApiKey;
            set
            {
                if (SetProperty(ref _vtApiKey, value))
                {
                    SaveCurrentSettings();
                }
            }
        }

        public string ActiveEngineText => _analyzerService.ActiveEngineDescription;

        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
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
                    : new[] { "Kritik uyarı bulunmadı." };
            }
        }

        public string TechnicalFindingsText
        {
            get
            {
                if (SelectedReport == null) return string.Empty;
                var sb = new StringBuilder();

                if (!string.IsNullOrWhiteSpace(SelectedReport.Error))
                    sb.AppendLine($"[HATA] {SelectedReport.Error}\n");

                if (SelectedReport.ThreatIntel != null)
                {
                    var ti = SelectedReport.ThreatIntel;
                    sb.AppendLine($"• Güvenli Mod: {(ti.SafeMode ? "Aktif" : "Kapalı")}");
                    if (!string.IsNullOrWhiteSpace(ti.ArchiveSha256))
                        sb.AppendLine($"• Arşiv SHA-256: {ti.ArchiveSha256}");

                    if (ti.YaraScan != null)
                    {
                        sb.AppendLine($"• YARA Taraması ({ti.YaraScan.Status}): {ti.YaraMatchCount} eşleşme");
                        foreach (var m in ti.YaraScan.Matches)
                            sb.AppendLine($"   - [{m.Severity}] {m.Rule} -> {m.FileName} ({m.Description})");
                    }

                    if (ti.ArchiveVt != null)
                    {
                        var vtInfo = ti.ArchiveVt.Status == "OK"
                            ? $"Zararlı={ti.ArchiveVt.Malicious}, Şüpheli={ti.ArchiveVt.Suspicious}"
                            : (ti.ArchiveVt.Reason ?? ti.ArchiveVt.Status);
                        sb.AppendLine($"• VirusTotal Durumu: {vtInfo}");
                    }
                    sb.AppendLine();
                }

                if (SelectedReport.FileTypes.Count > 0)
                    sb.AppendLine("• Dosya Türleri: " + string.Join(", ", SelectedReport.FileTypes.Select(kv => $"{kv.Key} ({kv.Value})")));

                if (SelectedReport.SuspiciousPaths.Count > 0)
                    sb.AppendLine("• Şüpheli Yollar (Zip Slip):\n  - " + string.Join("\n  - ", SelectedReport.SuspiciousPaths));

                if (SelectedReport.DoubleExtensionFiles.Count > 0)
                    sb.AppendLine("• Çift Uzantılı Dosyalar:\n  - " + string.Join("\n  - ", SelectedReport.DoubleExtensionFiles));

                if (SelectedReport.DisguisedFiles.Count > 0)
                    sb.AppendLine("• Uzantısı Gizlenmiş Dosyalar:\n  - " + string.Join("\n  - ", SelectedReport.DisguisedFiles));

                if (SelectedReport.HighRatioFiles.Count > 0)
                    sb.AppendLine("• Yüksek Sıkıştırma Oranlı Dosyalar:\n  - " + string.Join("\n  - ", SelectedReport.HighRatioFiles));

                if (SelectedReport.OverlappingEntries.Count > 0)
                    sb.AppendLine("• Çakışan Kayıtlar (Overlap Bomb):\n  - " + string.Join("\n  - ", SelectedReport.OverlappingEntries));

                if (SelectedReport.EncryptedFiles.Count > 0)
                    sb.AppendLine("• Şifreli Dosyalar:\n  - " + string.Join("\n  - ", SelectedReport.EncryptedFiles));

                if (SelectedReport.SymlinkFiles.Count > 0)
                    sb.AppendLine("• Sembolik Bağlantılar:\n  - " + string.Join("\n  - ", SelectedReport.SymlinkFiles));

                if (SelectedReport.NestedArchives.Count > 0)
                    sb.AppendLine("• İç İçe Arşivler:\n  - " + string.Join("\n  - ", SelectedReport.NestedArchives));

                if (SelectedReport.FileHashes.Count > 0)
                {
                    sb.AppendLine("• İçerik SHA-256 Özetleri:");
                    foreach (var fh in SelectedReport.FileHashes)
                        sb.AppendLine($"  - {fh.Name} ({FormatBytes(fh.Size)}): {fh.Sha256}");
                }

                return sb.Length > 0 ? sb.ToString().TrimEnd() : "Ek teknik bulgu tespit edilmedi.";
            }
        }

        private void SelectEngine()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Analiz Motorunu Seçin (main.py veya zipanalyzer.exe)",
                Filter = "Motor Dosyaları (main.py;*.exe)|main.py;*.exe|Python Betiği (*.py)|*.py|Çalıştırılabilir Dosya (*.exe)|*.exe|Tüm Dosyalar (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                _analyzerService.SetCustomEnginePath(dialog.FileName);
                OnPropertyChanged(nameof(ActiveEngineText));
                SaveCurrentSettings();
                StatusMessage = $"Motor güncellendi: {ActiveEngineText}";
            }
        }

        private async void SelectFiles()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Analiz Edilecek Arşiv Dosyalarını Seçin",
                Filter = "Desteklenen Arşivler (*.zip;*.7z;*.rar;*.tar;*.gz;*.tgz)|*.zip;*.7z;*.rar;*.tar;*.gz;*.tgz|Tüm Dosyalar (*.*)|*.*",
                Multiselect = true
            };

            if (dialog.ShowDialog() == true && dialog.FileNames.Length > 0)
            {
                await RunAnalysisAsync(dialog.FileNames, recursive: false);
            }
        }

        private async void SelectFolder()
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Taranacak Klasörü Seçin"
            };

            if (dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(dialog.FolderName))
            {
                await RunAnalysisAsync(new[] { dialog.FolderName }, recursive: true);
            }
        }

        public async Task HandleDroppedPathsAsync(string[] droppedPaths)
        {
            if (IsBusy || droppedPaths == null || droppedPaths.Length == 0)
                return;

            bool hasDirectory = droppedPaths.Any(Directory.Exists);
            await RunAnalysisAsync(droppedPaths, recursive: hasDirectory);
        }

        private void CancelAnalysis()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                StatusMessage = "Analiz iptal ediliyor...";
                _cts.Cancel();
            }
        }

        private async Task RunAnalysisAsync(IEnumerable<string> targetPaths, bool recursive)
        {
            if (!_analyzerService.IsEngineAvailable)
            {
                MessageBox.Show(
                    "Analiz motoru (main.py veya zipanalyzer.exe) bulunamadı.\nLütfen üst çubuktan '⚙ Motor Seç' butonuna tıklayarak motor konumunu seçin.",
                    "Motor Bulunamadı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            IsBusy = true;
            _cts = new CancellationTokenSource();
            StatusMessage = "Analiz motoru çalışıyor, lütfen bekleyin...";

            try
            {
                var results = await _analyzerService.AnalyzeAsync(
                    targetPaths,
                    recursive,
                    SafeMode,
                    VtApiKey,
                    _cts.Token);

                foreach (var report in results)
                {
                    var existing = Reports.FirstOrDefault(r =>
                        string.Equals(r.FileName, report.FileName, StringComparison.OrdinalIgnoreCase));
                    if (existing != null)
                        Reports.Remove(existing);

                    Reports.Add(report);
                }

                if (Reports.Count > 0 && SelectedReport == null)
                    SelectedReport = Reports[0];

                int highRiskCount = Reports.Count(r => r.RiskLevel == "HIGH");
                StatusMessage = $"Analiz tamamlandı. Toplam {Reports.Count} arşiv listeleniyor ({highRiskCount} yüksek riskli).";
            }
            catch (OperationCanceledException)
            {
                StatusMessage = "Analiz kullanıcı tarafından iptal edildi.";
            }
            catch (Exception ex)
            {
                StatusMessage = "Analiz sırasında hata oluştu.";
                MessageBox.Show(ex.Message, "Analiz Hatası", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
                IsBusy = false;
            }
        }

        private void ClearReports()
        {
            Reports.Clear();
            SelectedReport = null;
            StatusMessage = "Liste temizlendi.";
            RefreshCommands();
        }

        private void ExportJson()
        {
            var dialog = new SaveFileDialog
            {
                Title = "Raporu JSON Olarak Kaydet",
                Filter = "JSON Dosyası (*.json)|*.json",
                FileName = $"arsiv_analiz_raporu_{DateTime.Now:yyyyMMdd_HHmm}.json"
            };

            if (dialog.ShowDialog() == true)
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    NumberHandling = System.Text.Json.Serialization.JsonNumberHandling.AllowNamedFloatingPointLiterals
                };
                string json = JsonSerializer.Serialize(Reports, options);
                File.WriteAllText(dialog.FileName, json, Encoding.UTF8);
                StatusMessage = $"JSON raporu kaydedildi: {Path.GetFileName(dialog.FileName)}";
            }
        }

        private void ExportCsv()
        {
            var dialog = new SaveFileDialog
            {
                Title = "Raporu CSV Olarak Kaydet",
                Filter = "CSV Dosyası (*.csv)|*.csv",
                FileName = $"arsiv_analiz_raporu_{DateTime.Now:yyyyMMdd_HHmm}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                var sb = new StringBuilder();
                sb.AppendLine("ArsivAdi;Durum;RiskSeviyesi;RiskSkoru;AnalizSuresiMs;DosyaSayisi;SikistirilmisBoyut;AcilmisBoyut;SikistirmaOrani;Uyarilar");

                foreach (var r in Reports)
                {
                    string warningsJoined = string.Join(" | ", r.Warnings).Replace(";", ",");
                    string fileNameClean = r.FileName.Replace(";", ",");
                    sb.AppendLine($"{fileNameClean};{r.Status};{r.RiskLevelTr};{r.RiskScore};{r.AnalysisTimeMs:F1};{r.TotalFiles};{r.CompressedSize};{r.UncompressedSize};{r.CompressionRatioDisplay};{warningsJoined}");
                }

                File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
                StatusMessage = $"CSV raporu kaydedildi: {Path.GetFileName(dialog.FileName)}";
            }
        }

        private void SaveCurrentSettings()
        {
            _settingsService.Save(new AppSettings
            {
                CustomEnginePath = _analyzerService.CustomEnginePath,
                SafeMode = _safeMode,
                VtApiKey = _vtApiKey
            });
        }

        private void RefreshCommands()
        {
            SelectFilesCommand.RaiseCanExecuteChanged();
            SelectFolderCommand.RaiseCanExecuteChanged();
            SelectEngineCommand.RaiseCanExecuteChanged();
            CancelAnalysisCommand.RaiseCanExecuteChanged();
            ExportJsonCommand.RaiseCanExecuteChanged();
            ExportCsvCommand.RaiseCanExecuteChanged();
            ClearReportsCommand.RaiseCanExecuteChanged();
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double len = bytes;
            while (len >= 1024 && order < units.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {units[order]}";
        }
    }
}