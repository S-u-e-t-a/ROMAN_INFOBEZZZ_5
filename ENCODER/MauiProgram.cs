﻿using ENCODER.Alert;

using Microsoft.Extensions.Logging;

using ENCODER.Ciphers;


namespace ENCODER;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder.UseMauiApp<App>()
               .ConfigureFonts(fonts =>
               {
                   fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                   fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
               });
        builder.Services.AddSingleton<IAlertService, AlertService>();
        RegisterViewsAndViewModels(builder.Services);
    #if DEBUG
        builder.Logging.AddDebug();
    #endif

        return builder.Build();
    }

    static void RegisterViewsAndViewModels(in IServiceCollection services)
    {
        
    }
}
