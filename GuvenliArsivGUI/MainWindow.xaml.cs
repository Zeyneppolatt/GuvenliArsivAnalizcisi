using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using GuvenliArsivGUI.Models;
using GuvenliArsivGUI.Services;

namespace GuvenliArsivGUI
{
    public partial class MainWindow : Window
    {
        private readonly ZipAnalyzerService _analyzerService;

        public MainWindow()
        {
            InitializeComponent();

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // 3 üst klasör (arkadaşlarının klonladığı standart yapı) ve 4 üst klasör (senin iç içe klasör yapın)
            string[] candidateRoots =
            {
        Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..")),
        Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..\.."))
    };

            string pythonProjectPath = string.Empty;

            foreach (var root in candidateRoots)
            {
                string nestedPath = Path.Combine(root, "GuvenliArsivAnalizcisi-main", "GuvenliArsivAnalizcisi-main");
                string flatPath = Path.Combine(root, "GuvenliArsivAnalizcisi-main");

                if (Directory.Exists(nestedPath))
                {
                    pythonProjectPath = nestedPath;
                    break;
                }
                if (Directory.Exists(flatPath))
                {
                    pythonProjectPath = flatPath;
                    break;
                }
            }

            _analyzerService = new ZipAnalyzerService(pythonProjectPath);
        }

        private async void BtnSelectFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "ZIP Arşivleri (*.zip)|*.zip|Tüm Dosyalar (*.*)|*.*",
                Title = "Analiz Edilecek ZIP Dosyasını Seçin"
            };

            if (dialog.ShowDialog() == true)
            {
                await RunAnalysisAsync(dialog.FileName);
            }
        }

        private async void BtnSelectFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "ZIP Dosyalarını İçeren Klasörü Seçin"
            };

            if (dialog.ShowDialog() == true)
            {
                await RunAnalysisAsync(dialog.FolderName);
            }
        }

        private void Window_DragOver(object sender, DragEventArgs e)
        {
            e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
            e.Handled = true;
        }

        private async void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] droppedPaths = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (droppedPaths != null && droppedPaths.Length > 0)
                {
                    await RunAnalysisAsync(droppedPaths[0]);
                }
            }
        }

        private async Task RunAnalysisAsync(string targetPath)
        {
            try
            {
                BtnSelectFile.IsEnabled = false;
                BtnSelectFolder.IsEnabled = false;
                ProgressAnalyze.Visibility = Visibility.Visible;
                TxtStatus.Text = $"Analiz ediliyor: {targetPath} ...";

                List<ArchiveReport> results = await _analyzerService.AnalyzeAsync(targetPath);

                GridReports.ItemsSource = results;
                TxtStatus.Text = $"Analiz tamamlandı. Toplam {results.Count} arşiv incelendi.";

                if (results.Count > 0)
                {
                    GridReports.SelectedIndex = 0;
                }
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Analiz sırasında hata oluştu.";
                MessageBox.Show($"Hata Detayı:\n{ex.Message}", "Analiz Hatası", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnSelectFile.IsEnabled = true;
                BtnSelectFolder.IsEnabled = true;
                ProgressAnalyze.Visibility = Visibility.Collapsed;
            }
        }

        private void GridReports_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (GridReports.SelectedItem is not ArchiveReport report)
            {
                PanelDetailContent.Visibility = Visibility.Collapsed;
                TxtDetailPlaceholder.Visibility = Visibility.Visible;
                return;
            }

            TxtDetailPlaceholder.Visibility = Visibility.Collapsed;
            PanelDetailContent.Visibility = Visibility.Visible;

            TxtDetailTitle.Text = $"{report.FileName}  [{report.RiskLevel}]";
            TxtDetailStats.Text = $"Dosya Sayısı: {report.TotalFiles}  |  Sıkıştırılmış: {FormatBytes(report.CompressedSize)}  |  Açılmış: {FormatBytes(report.UncompressedSize)}  |  Oran: {report.CompressionRatio:F2}x";

            ListWarnings.ItemsSource = report.Warnings.Any()
                ? report.Warnings
                : new List<string> { "Herhangi bir güvenlik uyarısı tespit edilmedi." };

            var sb = new StringBuilder();
            AppendCategory(sb, "Şüpheli Dosya Yolları (Path Traversal)", report.SuspiciousPaths);
            AppendCategory(sb, "Çift Uzantılı Dosyalar", report.DoubleExtensionFiles);
            AppendCategory(sb, "Şüpheli Uzantılı Dosyalar", report.SuspiciousFiles);
            AppendCategory(sb, "Sembolik Bağlantılar (Symlink)", report.SymlinkFiles);
            AppendCategory(sb, "Şifreli Dosyalar", report.EncryptedFiles);
            AppendCategory(sb, "İç İçe Arşivler", report.NestedArchives);

            if (report.NestedArchiveReports.Any())
            {
                sb.AppendLine("--- İç İçe Arşiv Alt Raporları ---");
                foreach (var nested in report.NestedArchiveReports)
                {
                    sb.AppendLine($"• {nested.FileName} -> Risk: {nested.RiskLevel} (Dosya: {nested.TotalFiles})");
                }
                sb.AppendLine();
            }

            if (sb.Length == 0)
            {
                sb.AppendLine("Ek teknik bulgu kaydı yok.");
            }

            TxtTechnicalFindings.Text = sb.ToString().Trim();
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