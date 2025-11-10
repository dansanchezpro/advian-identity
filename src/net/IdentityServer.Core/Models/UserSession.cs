namespace IdentityServer.Core.Models;

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
