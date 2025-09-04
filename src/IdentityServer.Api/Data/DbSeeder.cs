using IdentityServer.Api.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace IdentityServer.Api.Data;

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
                    AllowedScopes = new List<string> { "openid", "profile", "email", "api1" },
                    AllowedGrantTypes = new List<string> { "authorization_code" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 3600,
                    AuthorizationCodeLifetime = 300
                },
                new Client
                {
                    ClientId = "sampleapp2",
                    ClientSecret = "", // Public client - no secret
                    ClientName = "Sample Application 2",
                    RedirectUris = new List<string> { "https://localhost:7002/authentication/login-callback" },
                    PostLogoutRedirectUris = new List<string> { "https://localhost:7002/" },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "api2" },
                    AllowedGrantTypes = new List<string> { "authorization_code" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 3600,
                    AuthorizationCodeLifetime = 300
                },
                new Client
                {
                    ClientId = "sampleapp3",
                    ClientSecret = "", // Public client - no secret
                    ClientName = "Sample Application 3",
                    RedirectUris = new List<string> { "https://localhost:7003/authentication/login-callback" },
                    PostLogoutRedirectUris = new List<string> { "https://localhost:7003/" },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "api3" },
                    AllowedGrantTypes = new List<string> { "authorization_code" },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    IsPublicClient = true,
                    AccessTokenLifetime = 3600,
                    AuthorizationCodeLifetime = 300
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
                    AccessTokenLifetime = 3600,
                    AuthorizationCodeLifetime = 300
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