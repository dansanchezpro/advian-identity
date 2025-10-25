using IdentityServer.Api.Data;
using IdentityServer.Api.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Configure Entity Framework with In-Memory Database
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseInMemoryDatabase("IdentityServerDb"));

// Register services
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddSingleton<IRsaKeyService, RsaKeyService>();

// Cookie authentication is configured in AddAuthentication section below

// Add CORS - specific configuration for Blazor WebAssembly
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
                "https://localhost:7001", // SampleApp1
                "https://localhost:7002", // SampleApp2
                "https://localhost:7003", // SampleApp3
                "https://localhost:7000", // Identity UI
                "https://localhost:6001"  // SampleBack1 API
              )
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
    
    // Add a more permissive policy for development
    options.AddPolicy("Development", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Configure external authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Cookie.Name = "IdentityServer.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // For localhost testing
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.Domain = ".localhost"; // Share cookie across localhost ports
    });

// External OAuth providers are handled manually in AuthController
// .AddGoogle and .AddMicrosoftAccount middleware removed to avoid conflicts with custom implementation

// Configure JWT settings
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JWT"));
builder.Configuration["JWT:SecretKey"] = "MyVerySecretKeyForJWTTokenGeneration123456789";

var app = builder.Build();

// Seed the database
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
    await DbSeeder.SeedAsync(context);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Enable static files serving
app.UseStaticFiles();

// Add comprehensive request logging middleware
app.Use(async (context, next) =>
{
    var method = context.Request.Method;
    var path = context.Request.Path;
    var queryString = context.Request.QueryString;
    var userAgent = context.Request.Headers["User-Agent"].FirstOrDefault() ?? "Unknown";
    var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? "No-Origin";
    var contentType = context.Request.Headers["Content-Type"].FirstOrDefault() ?? "No-Content-Type";
    
    Console.WriteLine($"════════════════════════════════════════════════════════════════════");
    Console.WriteLine($"[REQUEST] {DateTime.Now:HH:mm:ss.fff} - {method} {path}{queryString}");
    Console.WriteLine($"[REQUEST] Origin: {origin}");
    Console.WriteLine($"[REQUEST] Content-Type: {contentType}");
    Console.WriteLine($"[REQUEST] User-Agent: {userAgent}");
    
    // Log request body for POST requests (but limit size)
    if (method == "POST" && context.Request.ContentLength.HasValue && context.Request.ContentLength > 0)
    {
        context.Request.EnableBuffering();
        var buffer = new byte[Math.Min(context.Request.ContentLength.Value, 2000)];
        await context.Request.Body.ReadAsync(buffer, 0, buffer.Length);
        context.Request.Body.Position = 0;
        
        var bodyContent = System.Text.Encoding.UTF8.GetString(buffer);
        Console.WriteLine($"[REQUEST] Body Preview: {bodyContent}");
    }
    
    Console.WriteLine($"════════════════════════════════════════════════════════════════════");
    
    await next();
    
    Console.WriteLine($"[RESPONSE] {DateTime.Now:HH:mm:ss.fff} - {method} {path} → Status: {context.Response.StatusCode}");
});

// Use very permissive CORS for development
app.UseCors(policy =>
{
    policy.AllowAnyOrigin()
          .AllowAnyMethod()
          .AllowAnyHeader();
});

// Disable HTTPS redirection for development to avoid certificate issues
 app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

public class JwtSettings
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpirationMinutes { get; set; } = 60;
}
