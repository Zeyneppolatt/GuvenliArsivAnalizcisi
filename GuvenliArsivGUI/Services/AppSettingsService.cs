using System;
using System.IO;
using System.Text.Json;

namespace GuvenliArsivGUI.Services
{
    public class AppSettings
    {
        public string? CustomEnginePath { get; set; }
        public bool SafeMode { get; set; } = true;
        public string? VtApiKey { get; set; }
    }

    public class AppSettingsService
    {
        private readonly string _settingsFilePath;

        public AppSettingsService()
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appDir = Path.Combine(appData, "GuvenliArsivAnalizcisi");
            Directory.CreateDirectory(appDir);
            _settingsFilePath = Path.Combine(appDir, "settings.json");
        }

        public AppSettings Load()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    string json = File.ReadAllText(_settingsFilePath);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch
            {
                // Bozuk ayar dosyasında varsayılanlarla devam et
            }
            return new AppSettings();
        }

        public void Save(AppSettings settings)
        {
            try
            {
                string json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_settingsFilePath, json);
            }
            catch
            {
                // Yazma izni yoksa sessizce geç
            }
        }
    }
}