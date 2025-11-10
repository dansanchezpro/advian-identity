using IdentityServer.Core.Data;
using IdentityServer.Core.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Configure Entity Framework
if (builder.Environment.IsDevelopment())
{
    // Development: Use In-Memory Database for testing
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseInMemoryDatabase("IdentityServerDb"));
}
else
{
    // Production: Use SQL Server from configuration
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));
}

// Register services
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddSingleton<IRsaKeyService, RsaKeyService>();

// Cookie authentication is configured in AddAuthentication section below

// Add CORS configuration
builder.Services.AddCors(options =>
{
    if (builder.Environment.IsDevelopment())
    {
        // Development: Allow specific origins with credentials
        // NOTE: AllowAnyOrigin() is NOT compatible with AllowCredentials()
        // so we need to specify origins explicitly
        options.AddDefaultPolicy(policy =>
        {
            policy.WithOrigins(
                      "https://localhost:7000",  // Identity UI
                      "http://localhost:7000",
                      "https://localhost:7001",  // Sample App 1
                      "http://localhost:7001",
                      "https://localhost:7002",  // Sample App 2
                      "http://localhost:7002",
                      "https://localhost:7003",  // Sample App 3
                      "http://localhost:7003"
                  )
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();  // ← CRITICAL: Permite cookies cross-origin
        });
    }
    else
    {
        // Production: Use specific origins from configuration
        var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                             ?? Array.Empty<string>();

        options.AddDefaultPolicy(policy =>
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();  // ← CRITICAL: Permite cookies cross-origin
        });
    }
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

// Configure JWT settings
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JWT"));
builder.Configuration["JWT:SecretKey"] = "MyVerySecretKeyForJWTTokenGeneration123456789";

// Configure Rate Limiting for authentication endpoints
builder.Services.AddRateLimiter(options =>
{
    // Policy for authentication endpoints: 5 attempts per 15 minutes
    options.AddPolicy("auth", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(15),
                PermitLimit = 5,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0 // No queueing, reject immediately
            }));

    // Global policy: 100 requests per minute (prevents abuse)
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // Use IP address for rate limiting
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        return RateLimitPartition.GetFixedWindowLimiter(ipAddress, _ => new FixedWindowRateLimiterOptions
        {
            Window = TimeSpan.FromMinutes(1),
            PermitLimit = 100,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
    });

    // Customize rejection response
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = "application/json";

        var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfterValue)
            ? retryAfterValue.TotalSeconds
            : 900; // 15 minutes default

        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "too_many_requests",
            error_description = "Too many attempts. Please try again later.",
            retry_after_seconds = retryAfter
        }, cancellationToken);
    };
});

var app = builder.Build();

// Seed the database only in development
if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
    {
        var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        await DbSeeder.SeedAsync(context);
    }
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

// Use CORS with the configured policy
app.UseCors();

// Enable rate limiting middleware
app.UseRateLimiter();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }))
   .WithName("HealthCheck")
   .WithOpenApi();

app.Run();

public class JwtSettings
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpirationMinutes { get; set; } = 60;
}
