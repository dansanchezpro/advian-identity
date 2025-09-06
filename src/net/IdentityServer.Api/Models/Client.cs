namespace IdentityServer.Api.Models;

public class Client
{
    public int Id { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutRedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new();
    public List<string> AllowedGrantTypes { get; set; } = new();
    public bool RequirePkce { get; set; } = true;
    public bool AllowPlainTextPkce { get; set; } = false;
    public bool IsPublicClient { get; set; } = false;
    public int AccessTokenLifetime { get; set; } = 3600;
    public int AuthorizationCodeLifetime { get; set; } = 300;
    public int RefreshTokenLifetime { get; set; } = 2592000; // 30 days
}

public class AuthorizationCode
{
    public int Id { get; set; }
    public string Code { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public int UserId { get; set; }
    public List<string> Scopes { get; set; } = new();
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public string RedirectUri { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsUsed { get; set; } = false;
}

public class AccessToken
{
    public int Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public int UserId { get; set; }
    public List<string> Scopes { get; set; } = new();
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsRevoked { get; set; } = false;
}

public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public int UserId { get; set; }
    public List<string> Scopes { get; set; } = new();
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsRevoked { get; set; } = false;
    public string? JwtId { get; set; }
}