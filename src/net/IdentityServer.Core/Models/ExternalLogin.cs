namespace IdentityServer.Core.Models;

public class ExternalLogin
{
    public int Id { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string ProviderKey { get; set; } = string.Empty;
    public string ProviderDisplayName { get; set; } = string.Empty;
    public int UserId { get; set; }
    public User User { get; set; } = null!;
}
