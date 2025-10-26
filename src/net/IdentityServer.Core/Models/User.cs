namespace IdentityServer.Core.Models;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string? GoogleId { get; set; }
    public string? ProfilePicture { get; set; }
    public DateTime? DateOfBirth { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; } = true;
    public List<ExternalLogin> ExternalLogins { get; set; } = new();
}

public class ExternalLogin
{
    public int Id { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string ProviderKey { get; set; } = string.Empty;
    public string ProviderDisplayName { get; set; } = string.Empty;
    public int UserId { get; set; }
    public User User { get; set; } = null!;
}

public class UserSession
{
    public int Id { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public int UserId { get; set; }
    public User User { get; set; } = null!;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsActive { get; set; } = true;
}
