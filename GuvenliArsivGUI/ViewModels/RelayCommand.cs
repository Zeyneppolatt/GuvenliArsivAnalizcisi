using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace GuvenliArsivGUI.ViewModels
{
    public class RelayCommand : ICommand
    {
        private readonly Action _execute;
        private readonly Func<bool>? _canExecute;

        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

        public void Execute(object? parameter) => _execute();

        public void RaiseCanExecuteChanged() => CommandManager.InvalidateRequerySuggested();
    }

    public class AsyncRelayCommand : ICommand
    {
        private readonly Func<CancellationToken, Task> _execute;
        private readonly Func<bool>? _canExecute;
        private CancellationTokenSource? _cts;
        private bool _isExecuting;

        public AsyncRelayCommand(Func<CancellationToken, Task> execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool IsExecuting => _isExecuting;

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public bool CanExecute(object? parameter) => !_isExecuting && (_canExecute?.Invoke() ?? true);

        public async void Execute(object? parameter)
        {
            if (!CanExecute(parameter)) return;

            _isExecuting = true;
            _cts = new CancellationTokenSource();
            CommandManager.InvalidateRequerySuggested();

            try
            {
                await _execute(_cts.Token);
            }
            finally
            {
                _isExecuting = false;
                _cts?.Dispose();
                _cts = null;
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public void Cancel()
        {
            if (_isExecuting && _cts is { IsCancellationRequested: false })
            {
                _cts.Cancel();
            }
        }
    }
}