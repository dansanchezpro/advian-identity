using IdentityServer.Api.Models;
using IdentityServer.Api.Data;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace IdentityServer.Api.Services;

public interface IUserService
{
    Task<User?> ValidateCredentialsAsync(string email, string password);
    Task<User?> FindByEmailAsync(string email);
    Task<User?> FindByIdAsync(int id);
    Task<User?> FindByExternalLoginAsync(string provider, string providerKey);
    Task<User> CreateUserAsync(string email, string firstName, string lastName, string? password = null);
    Task AddExternalLoginAsync(int userId, string provider, string providerKey, string displayName);
}

public class UserService : IUserService
{
    private readonly IdentityDbContext _context;

    public UserService(IdentityDbContext context)
    {
        _context = context;
    }

    public async Task<User?> ValidateCredentialsAsync(string email, string password)
    {
        var user = await FindByEmailAsync(email);
        if (user == null || !user.IsActive)
            return null;

        var hashedPassword = HashPassword(password);
        return user.PasswordHash == hashedPassword ? user : null;
    }

    public async Task<User?> FindByEmailAsync(string email)
    {
        return await _context.Users
            .Include(u => u.ExternalLogins)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> FindByIdAsync(int id)
    {
        return await _context.Users
            .Include(u => u.ExternalLogins)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> FindByExternalLoginAsync(string provider, string providerKey)
    {
        var externalLogin = await _context.ExternalLogins
            .Include(el => el.User)
            .FirstOrDefaultAsync(el => el.Provider == provider && el.ProviderKey == providerKey);

        return externalLogin?.User;
    }

    public async Task<User> CreateUserAsync(string email, string firstName, string lastName, string? password = null)
    {
        var user = new User
        {
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            PasswordHash = password != null ? HashPassword(password) : string.Empty,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }

    public async Task AddExternalLoginAsync(int userId, string provider, string providerKey, string displayName)
    {
        var externalLogin = new ExternalLogin
        {
            UserId = userId,
            Provider = provider,
            ProviderKey = providerKey,
            ProviderDisplayName = displayName
        };

        _context.ExternalLogins.Add(externalLogin);
        await _context.SaveChangesAsync();
    }

    private static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + "salt"));
        return Convert.ToBase64String(hashedBytes);
    }
}