using IdentityServer.Core.Models;
using IdentityServer.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace IdentityServer.Core.Services;

public class TokenService : ITokenService
{
    private readonly IdentityDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly IRsaKeyService _rsaKeyService;

    public TokenService(IdentityDbContext context, IConfiguration configuration, IRsaKeyService rsaKeyService)
    {
        _context = context;
        _configuration = configuration;
        _rsaKeyService = rsaKeyService;
    }

    public async Task<string> GenerateAuthorizationCodeAsync(string clientId, int userId, List<string> scopes, string redirectUri, string? codeChallenge = null, string? codeChallengeMethod = null)
    {
        var code = Guid.NewGuid().ToString("N");
        var authCode = new AuthorizationCode
        {
            Code = code,
            ClientId = clientId,
            UserId = userId,
            Scopes = scopes,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            CreatedAt = DateTime.UtcNow
        };

        _context.AuthorizationCodes.Add(authCode);
        await _context.SaveChangesAsync();
        return code;
    }

    public async Task<(bool IsValid, AuthorizationCode? Code)> ValidateAuthorizationCodeAsync(string code, string clientId, string? codeVerifier = null)
    {
        var authCode = await _context.AuthorizationCodes
            .FirstOrDefaultAsync(ac => ac.Code == code && ac.ClientId == clientId && !ac.IsUsed);

        if (authCode == null || authCode.ExpiresAt < DateTime.UtcNow)
            return (false, null);

        if (!string.IsNullOrEmpty(authCode.CodeChallenge) && !string.IsNullOrEmpty(codeVerifier))
        {
            var computedChallenge = authCode.CodeChallengeMethod?.ToLower() == "s256"
                ? Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier)))
                : codeVerifier;

            if (computedChallenge != authCode.CodeChallenge)
                return (false, null);
        }

        authCode.IsUsed = true;
        await _context.SaveChangesAsync();

        return (true, authCode);
    }

    public async Task<string> GenerateAccessTokenAsync(string clientId, int userId, List<string> scopes)
    {
        var token = Guid.NewGuid().ToString("N");
        var accessToken = new AccessToken
        {
            Token = token,
            ClientId = clientId,
            UserId = userId,
            Scopes = scopes,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            CreatedAt = DateTime.UtcNow
        };

        _context.AccessTokens.Add(accessToken);
        await _context.SaveChangesAsync();
        return token;
    }

    public async Task<bool> ValidateAccessTokenAsync(string token)
    {
        var accessToken = await _context.AccessTokens
            .FirstOrDefaultAsync(at => at.Token == token && !at.IsRevoked);

        return accessToken != null && accessToken.ExpiresAt > DateTime.UtcNow;
    }

    public string GenerateJwtToken(int userId, string email, string firstName, string lastName, List<string> scopes, string issuer, string audience, int lifetimeMinutes = 60)
    {
        var credentials = _rsaKeyService.GetSigningCredentials();

        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(lifetimeMinutes);

        var claims = new List<Claim>
        {
            // Standard JWT claims
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new(JwtRegisteredClaimNames.Email, email),
            new(JwtRegisteredClaimNames.GivenName, firstName),
            new(JwtRegisteredClaimNames.FamilyName, lastName),
            new(JwtRegisteredClaimNames.Name, $"{firstName} {lastName}"),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expires).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

            // Additional claims for Blazor OIDC compatibility
            new("email", email),
            new("given_name", firstName),
            new("family_name", lastName),
            new("name", $"{firstName} {lastName}"),
            new("preferred_username", email)
        };

        foreach (var scope in scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            IssuedAt = now,
            NotBefore = now,
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        token.Header["kid"] = "default-rsa-key";

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> GenerateRefreshTokenAsync(string clientId, int userId, List<string> scopes, string? jwtId = null)
    {
        var token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"); // 64 chars

        var client = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        var refreshTokenLifetime = client?.RefreshTokenLifetime ?? 2592000; // 30 days default

        var refreshToken = new RefreshToken
        {
            Token = token,
            ClientId = clientId,
            UserId = userId,
            Scopes = scopes,
            JwtId = jwtId,
            ExpiresAt = DateTime.UtcNow.AddSeconds(refreshTokenLifetime),
            CreatedAt = DateTime.UtcNow
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
        return token;
    }

    public async Task<(bool IsValid, RefreshToken? Token)> ValidateRefreshTokenAsync(string token, string clientId)
    {
        var refreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token && rt.ClientId == clientId && !rt.IsRevoked);

        if (refreshToken == null || refreshToken.ExpiresAt < DateTime.UtcNow)
            return (false, null);

        return (true, refreshToken);
    }

    public async Task RevokeRefreshTokenAsync(string token)
    {
        var refreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken != null)
        {
            refreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();
        }
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }
}
