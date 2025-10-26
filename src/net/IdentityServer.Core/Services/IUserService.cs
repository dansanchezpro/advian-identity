using IdentityServer.Core.Models;

namespace IdentityServer.Core.Services;

public interface IUserService
{
    Task<User?> ValidateCredentialsAsync(string email, string password);
    Task<User?> FindByEmailAsync(string email);
    Task<User?> FindByIdAsync(int id);
    Task<User?> FindByExternalLoginAsync(string provider, string providerKey);
    Task<User> CreateUserAsync(string email, string firstName, string lastName, string? password = null);
    Task<User> RegisterUserAsync(string email, string firstName, string lastName, string password, DateTime? dateOfBirth = null);
    Task AddExternalLoginAsync(int userId, string provider, string providerKey, string displayName);
}
