using Microsoft.AspNetCore.Mvc;
using IdentityServer.Api.Services;
using IdentityServer.Api.Data;
using IdentityServer.Api.Models;
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

    public OAuthController(IUserService userService, ITokenService tokenService,  IdentityDbContext context, IConfiguration configuration)
    {
        _userService = userService;
        _tokenService = tokenService;
        _context = context;
        _configuration = configuration;
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
        if (client == null || !client.RedirectUris.Contains(redirect_uri))
        {
            return BadRequest(new { error = "invalid_client" });
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
                Console.WriteLine($"[DEBUG] Found valid authenticated user {userId}. Generating code directly.");
                
                // User is already authenticated, generate authorization code directly
                var code = await _tokenService.GenerateAuthorizationCodeAsync(
                    client_id, userId, scopes, redirect_uri,
                    code_challenge, code_challenge_method);

                var redirectUrl = $"{redirect_uri}?code={code}";
                if (!string.IsNullOrEmpty(state))
                    redirectUrl += $"&state={Uri.EscapeDataString(state)}";

                Console.WriteLine($"[DEBUG] SSO redirect to: {redirectUrl}");
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
                    Console.WriteLine($"[DEBUG] Valid id_token_hint found for user {hintUserId}. Generating code directly.");
                    
                    var code = await _tokenService.GenerateAuthorizationCodeAsync(
                        client_id, hintUserId, scopes, redirect_uri,
                        code_challenge, code_challenge_method);

                    var redirectUrl = $"{redirect_uri}?code={code}";
                    if (!string.IsNullOrEmpty(state))
                        redirectUrl += $"&state={Uri.EscapeDataString(state)}";

                    Console.WriteLine($"[DEBUG] SSO redirect via id_token_hint to: {redirectUrl}");
                    return Redirect(redirectUrl);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Failed to parse id_token_hint: {ex.Message}");
            }
        }
        
        Console.WriteLine($"[DEBUG] No authenticated session found");

        // Handle prompt=none for silent authentication
        if (prompt == "none")
        {
            Console.WriteLine($"[DEBUG] Silent authentication requested but no valid session found");
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

        Console.WriteLine($"[DEBUG] No valid session, redirecting to login: {loginUrl}");
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
        Console.WriteLine("[DEBUG] Token endpoint called");
        var form = await Request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();

        if (grantType != "authorization_code")
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

        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        Console.WriteLine($"[DEBUG] Token exchange - Code: {code}, ClientId: {clientId}, RedirectUri: {redirectUri}, CodeVerifier: {codeVerifier}");
        
        var (isValid, authCode) = await _tokenService.ValidateAuthorizationCodeAsync(code, clientId, codeVerifier);
        
        Console.WriteLine($"[DEBUG] Code validation - IsValid: {isValid}, AuthCode: {(authCode != null ? "found" : "null")}");
        if (authCode != null)
        {
            Console.WriteLine($"[DEBUG] AuthCode - RedirectUri: {authCode.RedirectUri}, Expected: {redirectUri}, Match: {authCode.RedirectUri == redirectUri}");
        }
        
        if (!isValid || authCode == null || authCode.RedirectUri != redirectUri)
        {
            Console.WriteLine($"[DEBUG] Token exchange failed - IsValid: {isValid}, AuthCode null: {authCode == null}, RedirectUri match: {authCode?.RedirectUri == redirectUri}");
            return BadRequest(new { error = "invalid_grant" });
        }

        var user = await _userService.FindByIdAsync(authCode.UserId);
        if (user == null)
        {
            return BadRequest(new { error = "invalid_grant" });
        }

        var issuer = $"{Request.Scheme}://{Request.Host}";
        var accessToken = _tokenService.GenerateJwtToken(
            user.Id, user.Email, user.FirstName, user.LastName, 
            authCode.Scopes, issuer, clientId, client.AccessTokenLifetime / 60);

        var idToken = _tokenService.GenerateJwtToken(
            user.Id, user.Email, user.FirstName, user.LastName,
            new List<string> { "openid" }, issuer, clientId, client.AccessTokenLifetime / 60);

        Console.WriteLine($"[DEBUG] Token generated successfully - AccessToken length: {accessToken.Length}, IDToken length: {idToken.Length}");

        var tokenResponse = new
        {
            access_token = accessToken,
            id_token = idToken,
            token_type = "Bearer",
            expires_in = client.AccessTokenLifetime,
            scope = string.Join(" ", authCode.Scopes)
        };
        
        Console.WriteLine($"[DEBUG] Returning token response: {System.Text.Json.JsonSerializer.Serialize(tokenResponse)}");
        return Ok(tokenResponse);
    }

    [HttpPost("generate-code")]
    public async Task<IActionResult> GenerateCode([FromBody] GenerateCodeRequest request)
    {
        Console.WriteLine($"[DEBUG] Generate code request - ClientId: {request.ClientId}, UserId: {request.UserId}, RedirectUri: {request.RedirectUri}, Scope: {request.Scope}");
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
            Console.WriteLine($"[DEBUG] All claims in token:");
            foreach (var claim in claims)
            {
                Console.WriteLine($"  {claim.Type} = {claim.Value}");
            }

            Console.WriteLine($"[DEBUG] UserInfo request successful for user: {sub}, email: {email}");

            
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
            Console.WriteLine($"[DEBUG] UserInfo token validation failed: {ex.Message}");
            return Unauthorized();
        }
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
