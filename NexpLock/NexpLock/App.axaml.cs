using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NexpLock.Commands;
using NexpLock.Interfaces;
using NexpLock.Runners;
using NexpLock.Services;
using NexpLock.Subscriptions;
using NexpLock.Utilities;
using NexpLock.ViewModels;
using NexpLock.Views;
using NexpSafe.Interfaces;
using NexpSafe.Services;

namespace NexpLock;

public class App : Application
{
    private IServiceProvider? _serviceProvider;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
        
        ConfigureServices();
    }

    public override async void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktopLifetime)
            await CreateAndShowMainWindowAsync(desktopLifetime);

        base.OnFrameworkInitializationCompleted();
    }

    private void ConfigureServices()
    {
        var services = new ServiceCollection();

        services.AddLogging();

        var vaultLoggerInstance = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        }).CreateLogger<VaultService>();

        var storageLoggerInstance = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        }).CreateLogger<StorageService>();

        Task.Run(async () =>
        {
            await DirectoryInitializer.EnsureRequiredDirectoriesExist();
        });

        services.TryAddSingleton<NexpWindow>();
        services.TryAddSingleton<NexpWindowViewModel>();

        services.TryAddSingleton<IWindowService, WindowService>();
        services.TryAddSingleton<IFileDialogService, FileDialogService>();

        services.TryAddSingleton<IKeyService, KeyService>();
        services.TryAddSingleton<IEncryptionService, EncryptionService>();
        services.TryAddSingleton<IEncryptionOperationRunner, EncryptionOperationRunner>();
        services.TryAddSingleton<IEncryptionOperationSubscriptions, EncryptionOperationSubscriptions>();

        services.TryAddSingleton<NexpWindowCommandManager>();

        services.AddSingleton<IVaultService, VaultService>(_ => new VaultService(vaultLoggerInstance));
        services.AddSingleton<IStorageService, StorageService>(_ =>
        {
            var provider = services.BuildServiceProvider();
            var vaultService = provider.GetRequiredService<IVaultService>();
            return new StorageService(vaultService, storageLoggerInstance);
        });

        services.AddTransient<CancellationTokenSource>(_ => new CancellationTokenSource());

        _serviceProvider = services.BuildServiceProvider();
    }


    private async Task CreateAndShowMainWindowAsync(IClassicDesktopStyleApplicationLifetime desktopLifetime)
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (_serviceProvider is null) throw new InvalidOperationException(Constants.Exception.NoServiceProvider);

            var mainWindow = _serviceProvider.GetRequiredService<NexpWindow>();
            WindowHelper.AdjustWindowSize(mainWindow);

            mainWindow.DataContext = _serviceProvider.GetRequiredService<NexpWindowViewModel>();
            desktopLifetime.MainWindow = mainWindow;
            mainWindow.Show();
        });
    }
}