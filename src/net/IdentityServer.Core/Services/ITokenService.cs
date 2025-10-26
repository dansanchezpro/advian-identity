using IdentityServer.Core.Models;

namespace IdentityServer.Core.Services;

public interface ITokenService
{
    Task<string> GenerateAuthorizationCodeAsync(string clientId, int userId, List<string> scopes, string redirectUri, string? codeChallenge = null, string? codeChallengeMethod = null);
    Task<(bool IsValid, AuthorizationCode? Code)> ValidateAuthorizationCodeAsync(string code, string clientId, string? codeVerifier = null);
    Task<string> GenerateAccessTokenAsync(string clientId, int userId, List<string> scopes);
    Task<bool> ValidateAccessTokenAsync(string token);
    string GenerateJwtToken(int userId, string email, string firstName, string lastName, List<string> scopes, string issuer, string audience, int lifetimeMinutes = 60);
    Task<string> GenerateRefreshTokenAsync(string clientId, int userId, List<string> scopes, string? jwtId = null);
    Task<(bool IsValid, RefreshToken? Token)> ValidateRefreshTokenAsync(string token, string clientId);
    Task RevokeRefreshTokenAsync(string token);
}
