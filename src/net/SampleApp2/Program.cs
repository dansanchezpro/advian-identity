using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SampleApp2;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

builder.Services.AddOidcAuthentication(options =>
{
    options.ProviderOptions.Authority = "https://localhost:5000";
    options.ProviderOptions.ClientId = "sampleapp2";
    options.ProviderOptions.ResponseType = "code";

    options.ProviderOptions.PostLogoutRedirectUri = "https://localhost:7002/authentication/logout-callback";
    options.ProviderOptions.RedirectUri = "https://localhost:7002/authentication/login-callback";

    options.ProviderOptions.MetadataUrl = "https://localhost:5000/.well-known/openid_configuration";

    options.ProviderOptions.DefaultScopes.Clear();
    options.ProviderOptions.DefaultScopes.Add("openid");
    options.ProviderOptions.DefaultScopes.Add("profile");
    options.ProviderOptions.DefaultScopes.Add("email");
    options.ProviderOptions.DefaultScopes.Add("offline_access");

    options.UserOptions.NameClaim = "name";
    options.UserOptions.RoleClaim = "role";
    
    options.ProviderOptions.AdditionalProviderParameters.Add("audience", "sampleapp2");
});

var host = builder.Build();
await host.RunAsync();
