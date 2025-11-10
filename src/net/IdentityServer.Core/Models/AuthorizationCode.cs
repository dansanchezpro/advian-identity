namespace IdentityServer.Core.Models;

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
