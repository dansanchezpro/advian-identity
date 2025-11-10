namespace IdentityServer.Core.Models;

public class AuthenticateResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public UserInfo? User { get; set; }
}

public class UserInfo
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
}
