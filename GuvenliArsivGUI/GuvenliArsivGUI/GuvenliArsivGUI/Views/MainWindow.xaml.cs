using System.ComponentModel;
using System.Windows;
using GuvenliArsivGUI.Services;
using GuvenliArsivGUI.ViewModels;

namespace GuvenliArsivGUI.Views
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _viewModel;

        public MainWindow()
        {
            InitializeComponent();

            var settingsService = new AppSettingsService();
            var settings = settingsService.Load();
            var analyzerService = new ZipAnalyzerService(settings.CustomEnginePath);

            _viewModel = new MainViewModel(
                analyzerService,
                new WpfDialogService(),
                new ReportExportService(),
                settingsService,
                settings);

            DataContext = _viewModel;
        }

        private void Window_DragOver(object sender, DragEventArgs e)
        {
            e.Effects = !_viewModel.IsBusy && e.Data.GetDataPresent(DataFormats.FileDrop)
                ? DragDropEffects.Copy
                : DragDropEffects.None;
            e.Handled = true;
        }

        private async void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var droppedPaths = e.Data.GetData(DataFormats.FileDrop) as string[];
                await _viewModel.HandleDroppedPathsAsync(droppedPaths);
            }
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            _viewModel.CancelAnalysis();
            base.OnClosing(e);
        }
    }
}