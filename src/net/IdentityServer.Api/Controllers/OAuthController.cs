using Microsoft.AspNetCore.Mvc;
using IdentityServer.Core.Services;
using IdentityServer.Core.Data;
using IdentityServer.Core.Models;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace IdentityServer.Api.Controllers;

[ApiController]
[Route("connect")]
public class OAuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;
    private readonly IdentityDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<OAuthController> _logger;

    public OAuthController(IUserService userService, ITokenService tokenService,  IdentityDbContext context, IConfiguration configuration, ILogger<OAuthController> logger)
    {
        _userService = userService;
        _tokenService = tokenService;
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string response_type,
        [FromQuery] string scope,
        [FromQuery] string? state = null,
        [FromQuery] string? code_challenge = null,
        [FromQuery] string? code_challenge_method = null,
        [FromQuery] string? prompt = null)
    {
        // Processing OAuth authorization request
        
        if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(redirect_uri) || 
            response_type != "code" || string.IsNullOrEmpty(scope))
        {
            return BadRequest(new { error = "invalid_request" });
        }

        var client = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == client_id);
        if (client == null)
        {
            _logger.LogError("Client not found: {ClientId}", client_id);
            return BadRequest(new { error = "invalid_client", error_description = "Client not found" });
        }

        // Validate redirect_uri against registered URIs
        var isValidRedirect = await ValidateRedirectUri(client_id, redirect_uri);
        if (!isValidRedirect)
        {
            return BadRequest(new {
                error = "invalid_request",
                error_description = "The redirect_uri is not registered for this client"
            });
        }

        var scopes = scope.Split(' ').ToList();
        if (!scopes.All(s => client.AllowedScopes.Contains(s)))
        {
            return BadRequest(new { error = "invalid_scope" });
        }

        // Check if user is authenticated via .NET Authentication
        if (HttpContext.User.Identity?.IsAuthenticated == true)
        {
            var userIdClaim = HttpContext.User.FindFirst("UserId")?.Value;
            if (!string.IsNullOrEmpty(userIdClaim) && int.TryParse(userIdClaim, out var userId))
            {
                _logger.LogInformation("Found valid authenticated user {UserId}. Generating code directly.", userId);

                // User is already authenticated, generate authorization code directly
                var code = await _tokenService.GenerateAuthorizationCodeAsync(
                    client_id, userId, scopes, redirect_uri,
                    code_challenge, code_challenge_method);

                var redirectUrl = $"{redirect_uri}?code={code}";
                if (!string.IsNullOrEmpty(state))
                    redirectUrl += $"&state={Uri.EscapeDataString(state)}";

                _logger.LogInformation("SSO redirect to: {RedirectUrl}", redirectUrl);
                return Redirect(redirectUrl);
            }
        }

        // Check id_token_hint for silent authentication
        var idTokenHint = Request.Query["id_token_hint"].FirstOrDefault();
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jsonToken = tokenHandler.ReadJwtToken(idTokenHint);
                var subClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                
                if (!string.IsNullOrEmpty(subClaim) && int.TryParse(subClaim, out var hintUserId))
                {
                    _logger.LogInformation("Valid id_token_hint found for user {HintUserId}. Generating code directly.", hintUserId);

                    var code = await _tokenService.GenerateAuthorizationCodeAsync(
                        client_id, hintUserId, scopes, redirect_uri,
                        code_challenge, code_challenge_method);

                    var redirectUrl = $"{redirect_uri}?code={code}";
                    if (!string.IsNullOrEmpty(state))
                        redirectUrl += $"&state={Uri.EscapeDataString(state)}";

                    _logger.LogInformation("SSO redirect via id_token_hint to: {RedirectUrl}", redirectUrl);
                    return Redirect(redirectUrl);
                }
            }
            catch (Exception ex)
            {
                _logger.LogInformation("Failed to parse id_token_hint: {Message}", ex.Message);
            }
        }

        _logger.LogInformation("No authenticated session found");

        // Handle prompt=none for silent authentication
        if (prompt == "none")
        {
            _logger.LogInformation("Silent authentication requested but no valid session found");
            var errorRedirect = $"{redirect_uri}?error=login_required";
            if (!string.IsNullOrEmpty(state))
                errorRedirect += $"&state={Uri.EscapeDataString(state)}";
            return Redirect(errorRedirect);
        }

        // No valid session found, redirect to login
        var identityServerUrl = $"{Request.Scheme}://{Request.Host}";
        var loginUrl = $"{identityServerUrl.Replace(":5000", ":7000")}/login?" +
            $"client_id={client_id}&redirect_uri={Uri.EscapeDataString(redirect_uri)}&" +
            $"response_type={response_type}&scope={Uri.EscapeDataString(scope)}";

        if (!string.IsNullOrEmpty(state))
            loginUrl += $"&state={Uri.EscapeDataString(state)}";
        if (!string.IsNullOrEmpty(code_challenge))
            loginUrl += $"&code_challenge={Uri.EscapeDataString(code_challenge)}";
        if (!string.IsNullOrEmpty(code_challenge_method))
            loginUrl += $"&code_challenge_method={Uri.EscapeDataString(code_challenge_method)}";
        if (!string.IsNullOrEmpty(prompt))
            loginUrl += $"&prompt={Uri.EscapeDataString(prompt)}";

        _logger.LogInformation("No valid session, redirecting to login: {LoginUrl}", loginUrl);
        return Redirect(loginUrl);
    }

    [HttpOptions("token")]
    public IActionResult TokenOptions()
    {
        return Ok();
    }

    [HttpPost("token")]
    public async Task<IActionResult> Token()
    {
        _logger.LogInformation("Token endpoint called");
        var form = await Request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();

        if (grantType != "authorization_code" && grantType != "refresh_token")
        {
            return BadRequest(new { error = "unsupported_grant_type" });
        }

        var client = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null)
        {
            return Unauthorized(new { error = "invalid_client" });
        }

        // For public clients, client secret validation is skipped
        if (!client.IsPublicClient && client.ClientSecret != clientSecret)
        {
            return Unauthorized(new { error = "invalid_client" });
        }

        if (grantType == "authorization_code")
        {
            return await HandleAuthorizationCodeGrant(form, client);
        }
        else if (grantType == "refresh_token")
        {
            return await HandleRefreshTokenGrant(form, client);
        }

        return BadRequest(new { error = "unsupported_grant_type" });
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrant(IFormCollection form, Client client)
    {
        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        _logger.LogInformation("Token exchange - Code: {Code}, ClientId: {ClientId}, RedirectUri: {RedirectUri}, CodeVerifier: {CodeVerifier}", code, client.ClientId, redirectUri, codeVerifier);

        var (isValid, authCode) = await _tokenService.ValidateAuthorizationCodeAsync(code, client.ClientId, codeVerifier);

        _logger.LogInformation("Code validation - IsValid: {IsValid}, AuthCode: {AuthCode}", isValid, (authCode != null ? "found" : "null"));
        if (authCode != null)
        {
            _logger.LogInformation("AuthCode - RedirectUri: {AuthCodeRedirectUri}, Expected: {RedirectUri}, Match: {Match}", authCode.RedirectUri, redirectUri, authCode.RedirectUri == redirectUri);
        }
        
        if (!isValid || authCode == null || authCode.RedirectUri != redirectUri)
        {
            _logger.LogInformation("Token exchange failed - IsValid: {IsValid}, AuthCode null: {AuthCodeNull}, RedirectUri match: {RedirectUriMatch}", isValid, authCode == null, authCode?.RedirectUri == redirectUri);
            return BadRequest(new { error = "invalid_grant" });
        }

        var user = await _userService.FindByIdAsync(authCode.UserId);
        _logger.LogInformation("User lookup - UserId: {UserId}, User found: {UserFound}", authCode.UserId, user != null);
        if (user == null)
        {
            _logger.LogInformation("FAILED: User not found for UserId: {UserId}", authCode.UserId);
            return BadRequest(new { error = "invalid_grant" });
        }

        var issuer = $"{Request.Scheme}://{Request.Host}";
        var jwtId = Guid.NewGuid().ToString();

        _logger.LogInformation("Generating tokens - Issuer: {Issuer}, ClientId: {ClientId}, Lifetime: {Lifetime} min", issuer, client.ClientId, client.AccessTokenLifetime / 60);

        string accessToken;
        string idToken;

        try
        {
            accessToken = _tokenService.GenerateJwtToken(
                user.Id, user.Email, user.FirstName, user.LastName,
                authCode.Scopes, issuer, client.ClientId, client.AccessTokenLifetime / 60);

            _logger.LogInformation("Access token generated - Length: {Length}", accessToken.Length);

            idToken = _tokenService.GenerateJwtToken(
                user.Id, user.Email, user.FirstName, user.LastName,
                new List<string> { "openid" }, issuer, client.ClientId, client.AccessTokenLifetime / 60);

            _logger.LogInformation("Token generated successfully - AccessToken length: {AccessTokenLength}, IDToken length: {IdTokenLength}", accessToken.Length, idToken.Length);
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to generate JWT tokens: {Message}", ex.Message);
            _logger.LogError("Stack trace: {StackTrace}", ex.StackTrace);
            return BadRequest(new { error = "token_generation_failed", error_description = ex.Message });
        }

        // Generate refresh token if offline_access scope is requested
        string? refreshToken = null;
        if (authCode.Scopes.Contains("offline_access"))
        {
            refreshToken = await _tokenService.GenerateRefreshTokenAsync(client.ClientId, user.Id, authCode.Scopes, jwtId);
            _logger.LogInformation("Refresh token generated - Length: {Length}", refreshToken.Length);
        }

        var tokenResponse = new Dictionary<string, object>
        {
            { "access_token", accessToken },
            { "id_token", idToken },
            { "token_type", "Bearer" },
            { "expires_in", client.AccessTokenLifetime },
            { "scope", string.Join(" ", authCode.Scopes) }
        };

        if (refreshToken != null)
        {
            tokenResponse["refresh_token"] = refreshToken;
        }

        _logger.LogInformation("Returning token response: {TokenResponse}", System.Text.Json.JsonSerializer.Serialize(tokenResponse));
        return Ok(tokenResponse);
    }

    private async Task<IActionResult> HandleRefreshTokenGrant(IFormCollection form, Client client)
    {
        var refreshToken = form["refresh_token"].ToString();
        var requestedScope = form["scope"].ToString(); // Optional: can request subset of original scopes

        _logger.LogInformation("Refresh token grant - RefreshToken: {RefreshToken}..., ClientId: {ClientId}", refreshToken[..10], client.ClientId);

        var (isValid, refreshTokenEntity) = await _tokenService.ValidateRefreshTokenAsync(refreshToken, client.ClientId);
        if (!isValid || refreshTokenEntity == null)
        {
            _logger.LogInformation("Refresh token validation failed");
            return BadRequest(new { error = "invalid_grant" });
        }

        var user = await _userService.FindByIdAsync(refreshTokenEntity.UserId);
        if (user == null)
        {
            _logger.LogInformation("User not found for refresh token");
            return BadRequest(new { error = "invalid_grant" });
        }

        // Determine scopes (use requested scopes if provided and valid, otherwise use original scopes)
        var scopes = refreshTokenEntity.Scopes;
        if (!string.IsNullOrEmpty(requestedScope))
        {
            var requestedScopes = requestedScope.Split(' ').ToList();
            // Only allow scopes that were originally granted
            var validScopes = requestedScopes.Where(s => refreshTokenEntity.Scopes.Contains(s)).ToList();
            if (validScopes.Count > 0)
            {
                scopes = validScopes;
            }
        }

        var issuer = $"{Request.Scheme}://{Request.Host}";
        var jwtId = Guid.NewGuid().ToString();

        var accessToken = _tokenService.GenerateJwtToken(
            user.Id, user.Email, user.FirstName, user.LastName, 
            scopes, issuer, client.ClientId, client.AccessTokenLifetime / 60);

        var idToken = _tokenService.GenerateJwtToken(
            user.Id, user.Email, user.FirstName, user.LastName,
            new List<string> { "openid" }, issuer, client.ClientId, client.AccessTokenLifetime / 60);

        // Revoke old refresh token
        await _tokenService.RevokeRefreshTokenAsync(refreshToken);

        // Generate new refresh token
        var newRefreshToken = await _tokenService.GenerateRefreshTokenAsync(client.ClientId, user.Id, scopes, jwtId);

        _logger.LogInformation("New tokens generated via refresh - AccessToken length: {AccessTokenLength}, RefreshToken length: {RefreshTokenLength}", accessToken.Length, newRefreshToken.Length);

        var tokenResponse = new
        {
            access_token = accessToken,
            id_token = idToken,
            refresh_token = newRefreshToken,
            token_type = "Bearer",
            expires_in = client.AccessTokenLifetime,
            scope = string.Join(" ", scopes)
        };

        _logger.LogInformation("Returning refresh token response");
        return Ok(tokenResponse);
    }

    [HttpPost("generate-code")]
    public async Task<IActionResult> GenerateCode([FromBody] GenerateCodeRequest request)
    {
        _logger.LogInformation("Generate code request - ClientId: {ClientId}, UserId: {UserId}, RedirectUri: {RedirectUri}, Scope: {Scope}", request.ClientId, request.UserId, request.RedirectUri, request.Scope);
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == request.ClientId);
        if (client == null)
        {
            return BadRequest(new { error = "invalid_client" });
        }

        var user = await _userService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return BadRequest(new { error = "invalid_user" });
        }

        var scopes = request.Scope?.Split(' ').ToList() ?? new List<string>();
        var code = await _tokenService.GenerateAuthorizationCodeAsync(
            request.ClientId, request.UserId, scopes, request.RedirectUri,
            request.CodeChallenge, request.CodeChallengeMethod);

        var redirectUrl = $"{request.RedirectUri}?code={code}";
        if (!string.IsNullOrEmpty(request.State))
            redirectUrl += $"&state={Uri.EscapeDataString(request.State)}";

        return Ok(new { RedirectUrl = redirectUrl, Code = code });
    }

    [HttpGet("userinfo")]
    public async Task<IActionResult> UserInfo([FromServices] IRsaKeyService rsaKeyService)
    {
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();
        if (authHeader == null || !authHeader.StartsWith("Bearer "))
        {
            return Unauthorized();
        }

        var token = authHeader.Substring("Bearer ".Length);
        
        try
        {
            // Validar JWT token con RSA
            var tokenHandler = new JwtSecurityTokenHandler();
            var rsaKey = rsaKeyService.GetRsaSecurityKey();
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = rsaKey,
                ValidateIssuer = true,
                ValidIssuer = $"{Request.Scheme}://{Request.Host}",
                ValidateAudience = false, // Permitir cualquier audience
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            var claims = principal.Claims;
            
            // Extraer información del usuario del token - usando claim types .NET estándar
            var sub = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            var givenName = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value;
            var familyName = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;
            var name = claims.FirstOrDefault(c => c.Type == "name")?.Value;
            
            // Debug: log all claims
            _logger.LogInformation("All claims in token:");
            foreach (var claim in claims)
            {
                _logger.LogInformation("  {ClaimType} = {ClaimValue}", claim.Type, claim.Value);
            }

            _logger.LogInformation("UserInfo request successful for user: {Sub}, email: {Email}", sub, email);

            
            var response = new
            {
                sub = sub,
                email = email,
                given_name = givenName,
                family_name = familyName,
                name = name
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogInformation("UserInfo token validation failed: {Message}", ex.Message);
            return Unauthorized();
        }
    }

    /// <summary>
    /// Validates that a redirect URI is registered for the specified client.
    /// This prevents SSRF (Server-Side Request Forgery) and open redirect attacks.
    /// </summary>
    /// <param name="clientId">The OAuth client ID</param>
    /// <param name="redirectUri">The redirect URI to validate</param>
    /// <returns>True if the redirect URI is registered for this client, false otherwise</returns>
    private async Task<bool> ValidateRedirectUri(string clientId, string redirectUri)
    {
        // Find the client in the database
        var client = await _context.Clients
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientId == clientId);

        if (client == null)
        {
            _logger.LogError("Client not found: {ClientId}", clientId);
            return false;
        }

        // Check if the redirect URI is in the client's registered URIs
        // Perform exact match (case-insensitive) for security
        var isValid = client.RedirectUris.Any(uri =>
            uri.Equals(redirectUri, StringComparison.OrdinalIgnoreCase));

        if (!isValid)
        {
            _logger.LogError("Redirect URI not registered for client {ClientId}", clientId);
            _logger.LogError("Attempted: {RedirectUri}", redirectUri);
            _logger.LogError("Registered URIs: {RegisteredUris}", string.Join(", ", client.RedirectUris));
        }

        return isValid;
    }
}

public class GenerateCodeRequest
{
    public string ClientId { get; set; } = string.Empty;
    public int UserId { get; set; }
    public string RedirectUri { get; set; } = string.Empty;
    public string? Scope { get; set; }
    public string? State { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
}
