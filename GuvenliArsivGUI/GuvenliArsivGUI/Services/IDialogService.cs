namespace GuvenliArsivGUI.Services
{
    public interface IDialogService
    {
        string[]? OpenArchiveFiles();
        string? OpenFolder();
        string? OpenEngineFile();
        string? SaveReportFile(string defaultFileName, string filter);
        void ShowError(string title, string message);
        void ShowInfo(string title, string message);
    }
}