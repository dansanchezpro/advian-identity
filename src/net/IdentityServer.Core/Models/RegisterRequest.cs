namespace IdentityServer.Core.Models;

public class RegisterRequest
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
    public DateTime? DateOfBirth { get; set; }
    public bool AcceptTerms { get; set; }
}

public class RegisterResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public UserInfo? User { get; set; }
}
