using IdentityServer.Core.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace IdentityServer.Core.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(IdentityDbContext context)
    {
        await context.Database.EnsureCreatedAsync();

        if (!await context.Users.AnyAsync())
        {
            var users = new[]
            {
                new User
                {
                    Email = "admin@example.com",
                    PasswordHash = HashPassword("Admin123!"),
                    FirstName = "Admin",
                    LastName = "User",
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                },
                new User
                {
                    Email = "user@example.com",
                    PasswordHash = HashPassword("User123!"),
                    FirstName = "Test",
                    LastName = "User",
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                }
            };

            await context.Users.AddRangeAsync(users);
        }

        if (!await context.Clients.AnyAsync())
        {
            var clients = new[]
            {
                new Client
                {
                    ClientId = "sampleapp1",
                    ClientSecret = "", // Public client - no secret
                    ClientName = "Sample Application 1",
                    RedirectUris = new List<string> { "https://localhost:7001/authentication/login-callback" },
                    PostLogoutRedirectUris = new List<string> { "https://localhost:7001/" },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access", "api1" },
                    AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 300, // 5 minutes for testing
                    AuthorizationCodeLifetime = 300,
                    RefreshTokenLifetime = 2592000
                },
                new Client
                {
                    ClientId = "sampleapp2",
                    ClientSecret = "", // Public client - no secret
                    ClientName = "Sample Application 2",
                    RedirectUris = new List<string> { "https://localhost:7002/authentication/login-callback" },
                    PostLogoutRedirectUris = new List<string> { "https://localhost:7002/" },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access", "api2" },
                    AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 300, // 5 minutes for testing
                    AuthorizationCodeLifetime = 300,
                    RefreshTokenLifetime = 2592000
                },
                new Client
                {
                    ClientId = "sampleapp3",
                    ClientSecret = "", // Public client - no secret
                    ClientName = "Sample Application 3",
                    RedirectUris = new List<string> { "https://localhost:7003/authentication/login-callback" },
                    PostLogoutRedirectUris = new List<string> { "https://localhost:7003/" },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access", "api3" },
                    AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 300, // 5 minutes for testing
                    AuthorizationCodeLifetime = 300,
                    RefreshTokenLifetime = 2592000
                },
                new Client
                {
                    ClientId = "identityserver-ui",
                    ClientSecret = "identityserver-ui-secret",
                    ClientName = "Identity Server UI",
                    RedirectUris = new List<string> { "https://localhost:7000/authentication/login-callback" },
                    PostLogoutRedirectUris = new List<string> { "https://localhost:7000/" },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "identity-api" },
                    AllowedGrantTypes = new List<string> { "authorization_code" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    AccessTokenLifetime = 300, // 5 minutes for testing
                    AuthorizationCodeLifetime = 300
                },
                new Client
                {
                    ClientId = "mobileapp",
                    ClientSecret = "", // Public client - no secret required for mobile
                    ClientName = "Mobile Application",
                    RedirectUris = new List<string> {
                        "mobileapp://auth",
                        "exp://192.168.1.100:8081/--/auth", // Expo development
                        "exp://localhost:8081/--/auth"
                    },
                    PostLogoutRedirectUris = new List<string> {
                        "mobileapp://logout",
                        "exp://192.168.1.100:8081/--/logout",
                        "exp://localhost:8081/--/logout"
                    },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access", "api1" },
                    AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 300, // 5 minutes for testing
                    AuthorizationCodeLifetime = 300,
                    RefreshTokenLifetime = 2592000 // 30 days
                },
                new Client
                {
                    ClientId = "desktopapp",
                    ClientSecret = "", // Public client - no secret required for desktop
                    ClientName = "Desktop Application",
                    RedirectUris = new List<string> {
                        "http://localhost:8080/callback",
                        "desktopapp://auth"
                    },
                    PostLogoutRedirectUris = new List<string> {
                        "http://localhost:8080/",
                        "desktopapp://logout"
                    },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access", "api1" },
                    AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 300, // 5 minutes for testing
                    AuthorizationCodeLifetime = 300,
                    RefreshTokenLifetime = 2592000 // 30 days
                }
            };

            await context.Clients.AddRangeAsync(clients);
        }

        await context.SaveChangesAsync();
    }

    private static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + "salt"));
        return Convert.ToBase64String(hashedBytes);
    }
}
