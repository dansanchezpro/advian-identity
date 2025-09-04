using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SampleApp1;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

builder.Services.AddOidcAuthentication(options =>
{
    // Basic OIDC configuration pointing to API bridge endpoint
    options.ProviderOptions.Authority = "https://localhost:5000";
    options.ProviderOptions.ClientId = "sampleapp1";
    options.ProviderOptions.ResponseType = "code";

    //Segun articulo de microsoft
    options.ProviderOptions.PostLogoutRedirectUri = "https://localhost:7001/authentication/logout-callback";
    options.ProviderOptions.RedirectUri = "https://localhost:7001/authentication/login-callback";

    // Explicit endpoint configuration to bypass discovery cache
    options.ProviderOptions.MetadataUrl = "https://localhost:5000/.well-known/openid_configuration";

    // Scopes
    options.ProviderOptions.DefaultScopes.Clear();
    options.ProviderOptions.DefaultScopes.Add("openid");
    options.ProviderOptions.DefaultScopes.Add("profile");
    options.ProviderOptions.DefaultScopes.Add("email");

    // User claims mapping - using standard OIDC claim names
    options.UserOptions.NameClaim = "name";
    options.UserOptions.RoleClaim = "role";
    
    // Token validation parameters
    options.ProviderOptions.AdditionalProviderParameters.Add("audience", "sampleapp1");
});

var host = builder.Build();
await host.RunAsync();
