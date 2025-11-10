namespace IdentityServer.Core.Models;

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
