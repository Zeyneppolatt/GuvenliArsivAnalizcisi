using System.Windows;
using Microsoft.Win32;

namespace GuvenliArsivGUI.Services
{
    public class WpfDialogService : IDialogService
    {
        public string[]? OpenArchiveFiles()
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Arşiv Dosyaları (*.zip;*.7z;*.rar;*.tar;*.gz)|*.zip;*.7z;*.rar;*.tar;*.gz|ZIP Arşivleri (*.zip)|*.zip|Tüm Dosyalar (*.*)|*.*",
                Title = "Analiz Edilecek Arşiv Dosyalarını Seçin",
                Multiselect = true
            };
            return dialog.ShowDialog() == true ? dialog.FileNames : null;
        }

        public string? OpenFolder()
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Taranacak Klasörü Seçin"
            };
            return dialog.ShowDialog() == true ? dialog.FolderName : null;
        }

        public string? SaveReportFile(string defaultFileName, string filter)
        {
            var dialog = new SaveFileDialog
            {
                FileName = defaultFileName,
                Filter = filter,
                Title = "Analiz Raporunu Kaydet"
            };
            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }

        public string? OpenEngineFile()
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Analiz Motoru (main.py; zipanalyzer.exe)|main.py;zipanalyzer.exe|Python Betiği (*.py)|*.py|Çalıştırılabilir Dosya (*.exe)|*.exe",
                Title = "Analiz Motorunu Seçin (main.py veya zipanalyzer.exe)"
            };
            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }
        public void ShowError(string title, string message)
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        public void ShowInfo(string title, string message)
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}