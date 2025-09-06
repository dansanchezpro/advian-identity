using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Configure CORS for Blazor WebAssembly clients
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
                "https://localhost:7001", // SampleApp1
                "https://localhost:7002", // SampleApp2  
                "https://localhost:7003", // SampleApp3
                "https://localhost:7000"  // Identity UI
              )
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Configure JWT Bearer Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        // Configure to validate tokens from our Identity Server
        options.Authority = "https://localhost:5000";
        options.RequireHttpsMetadata = true;
        options.Audience = "sampleback1";
        
        // Configure token validation parameters
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:5000",
            ValidateAudience = false, // We'll be flexible with audience for demo
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero
        };

        // Add event handlers for debugging
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var userId = context.Principal?.FindFirst("sub")?.Value;
                var email = context.Principal?.FindFirst("email")?.Value;
                Console.WriteLine($"[SAMPLEBACK1] Token validated for user: {email} (ID: {userId})");
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"[SAMPLEBACK1] Authentication failed: {context.Exception.Message}");
                return Task.CompletedTask;
            },
            OnMessageReceived = context =>
            {
                var token = context.Token;
                if (!string.IsNullOrEmpty(token))
                {
                    Console.WriteLine($"[SAMPLEBACK1] Received token: {token[..50]}...");
                }
                return Task.CompletedTask;
            }
        };

        // Use OIDC discovery to get keys
        options.MetadataAddress = "https://localhost:5000/.well-known/openid_configuration";
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Add comprehensive request logging middleware
app.Use(async (context, next) =>
{
    var method = context.Request.Method;
    var path = context.Request.Path;
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    
    Console.WriteLine($"════════════════════════════════════════════════════════════════════");
    Console.WriteLine($"[SAMPLEBACK1] {DateTime.Now:HH:mm:ss.fff} - {method} {path}");
    Console.WriteLine($"[SAMPLEBACK1] Authorization: {(authHeader != null ? "Bearer ***" : "None")}");
    Console.WriteLine($"[SAMPLEBACK1] Origin: {context.Request.Headers["Origin"].FirstOrDefault() ?? "No-Origin"}");
    Console.WriteLine($"════════════════════════════════════════════════════════════════════");
    
    await next();
    
    Console.WriteLine($"[SAMPLEBACK1] {DateTime.Now:HH:mm:ss.fff} - {method} {path} → Status: {context.Response.StatusCode}");
});

app.UseCors();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Configure to run on port 6001
app.Urls.Add("https://localhost:6001");

app.Run();
