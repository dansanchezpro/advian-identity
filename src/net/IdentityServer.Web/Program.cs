using IdentityServer.Web;
using IdentityServer.Web.Configuration;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Configure IdentityServer settings from appsettings.json
var identityServerSettings = builder.Configuration
    .GetSection("IdentityServer")
    .Get<IdentityServerSettings>() ?? new IdentityServerSettings();

builder.Services.AddSingleton(identityServerSettings);

// Configure HttpClient for calling the backend API
builder.Services.AddScoped(sp =>
{
    var settings = sp.GetRequiredService<IdentityServerSettings>();
    var httpClient = new HttpClient
    {
        BaseAddress = new Uri(settings.ApiUrl)
    };
    // IMPORTANT: This allows cookies to be sent with cross-origin requests
    // Note: In Blazor WASM, we can't directly set credentials, but we'll handle it via fetch options
    return httpClient;
});

await builder.Build().RunAsync();
