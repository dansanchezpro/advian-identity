using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdentityServer.Api.Data;
using IdentityServer.Api.Services;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace IdentityServer.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;
    private readonly IdentityDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthController(IUserService userService, ITokenService tokenService, IdentityDbContext context, IConfiguration configuration)
    {
        _userService = userService;
        _tokenService = tokenService;
        _context = context;
        _configuration = configuration;
    }

    // New OIDC login endpoint - acts as a bridge between SampleApps and Identity Server UI
    [HttpGet("oidc-login")]
    public async Task<IActionResult> OidcLogin(
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string response_type,
        [FromQuery] string scope,
        [FromQuery] string? state = null,
        [FromQuery] string? code_challenge = null,
        [FromQuery] string? code_challenge_method = null,
        [FromQuery] string? prompt = null)
    {
        // OIDC Login bridge endpoint

        // Validate basic OIDC parameters
        if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(redirect_uri) || 
            response_type != "code" || string.IsNullOrEmpty(scope))
        {
            return BadRequest(new { error = "invalid_request" });
        }

        // Validate client
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == client_id);
        if (client == null || !client.RedirectUris.Contains(redirect_uri))
        {
            return BadRequest(new { error = "invalid_client" });
        }

        // Check if user is authenticated via .NET Authentication
        if (HttpContext.User.Identity?.IsAuthenticated == true)
        {
            var userIdClaim = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userIdClaim) && int.TryParse(userIdClaim, out var userId))
            {
                // User authenticated via .NET - generating code directly
                
                // User is already authenticated, generate authorization code directly
                var code = await _tokenService.GenerateAuthorizationCodeAsync(
                    client_id, userId, scope.Split(' ').ToList(), redirect_uri,
                    code_challenge, code_challenge_method);

                var redirectUrl = $"{redirect_uri}?code={code}";
                if (!string.IsNullOrEmpty(state))
                    redirectUrl += $"&state={Uri.EscapeDataString(state)}";

                // SSO redirect
                return Redirect(redirectUrl);
            }
        }
       
        // Handle prompt=none for silent authentication
        if (prompt == "none")
        {
            // Silent authentication requested but no valid session found
            var errorRedirect = $"{redirect_uri}?error=login_required";
            if (!string.IsNullOrEmpty(state))
                errorRedirect += $"&state={Uri.EscapeDataString(state)}";
            return Redirect(errorRedirect);
        }

        // No valid session found, redirect to Identity Server UI with API callback
        var identityServerUiUrl = $"{_configuration["IdentityServer:LoginUrl"]}/login";
        var loginParams = new List<string>
        {
            $"client_id={Uri.EscapeDataString(client_id)}",
            $"redirect_uri={Uri.EscapeDataString(redirect_uri)}",
            $"response_type={Uri.EscapeDataString(response_type)}",
            $"scope={Uri.EscapeDataString(scope)}",
            $"api_callback=true" // Indica que debe hacer POST al API
        };

        if (!string.IsNullOrEmpty(state))
            loginParams.Add($"state={Uri.EscapeDataString(state)}");
        if (!string.IsNullOrEmpty(code_challenge))
            loginParams.Add($"code_challenge={Uri.EscapeDataString(code_challenge)}");
        if (!string.IsNullOrEmpty(code_challenge_method))
            loginParams.Add($"code_challenge_method={Uri.EscapeDataString(code_challenge_method)}");

        var loginUrl = $"{identityServerUiUrl}?{string.Join("&", loginParams)}";
        // Redirecting to UI login with API callback
        
        return Redirect(loginUrl);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userService.ValidateCredentialsAsync(request.Email, request.Password);
        if (user == null)
        {
            return BadRequest(new { error = "invalid_credentials", error_description = "Invalid email or password" });
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName),
            new Claim("name", $"{user.FirstName} {user.LastName}")
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties { IsPersistent = true });

        return Ok(new
        {
            success = true,
            user = new
            {
                id = user.Id,
                email = user.Email,
                firstName = user.FirstName,
                lastName = user.LastName
            }
        });
    }

    [HttpPost("oidc-form-login")]
    public async Task<IActionResult> OidcFormLogin([FromForm] OidcFormLoginRequest request)
    {
        var user = await _userService.ValidateCredentialsAsync(request.Email, request.Password);
        if (user == null)
        {
            return BadRequest("Invalid credentials");
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName),
            new Claim("name", $"{user.FirstName} {user.LastName}")
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties { IsPersistent = true });

        var code = await _tokenService.GenerateAuthorizationCodeAsync(
            request.ClientId, user.Id, request.Scope?.Split(' ').ToList() ?? new List<string>(), request.RedirectUri,
            request.CodeChallenge, request.CodeChallengeMethod);

        var redirectUrl = $"{request.RedirectUri}?code={code}";
        if (!string.IsNullOrEmpty(request.State))
            redirectUrl += $"&state={Uri.EscapeDataString(request.State)}";

        return Redirect(redirectUrl);
    }

    [HttpGet("external/{provider}")]
    public IActionResult ExternalLogin(string provider, [FromQuery] string? returnUrl = null)
    {
        var redirectUrl = Url.Action(nameof(ExternalCallback), "Auth", new { returnUrl }, Request.Scheme);
        
        if (provider.ToLower() == "google")
        {
            var clientId = _configuration["Authentication:Google:ClientId"];
            var authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                $"client_id={clientId}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUrl!)}&" +
                $"response_type=code&" +
                $"scope=openid%20profile%20email&" +
                $"access_type=offline";
            
            return Redirect(authUrl);
        }
        else if (provider.ToLower() == "microsoft")
        {
            var clientId = _configuration["Authentication:Microsoft:ClientId"];
            var authUrl = $"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" +
                $"client_id={clientId}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUrl!)}&" +
                $"response_type=code&" +
                $"scope=openid%20profile%20email&" +
                $"response_mode=query";
            
            return Redirect(authUrl);
        }
        
        return BadRequest("Unsupported provider");
    }

    [HttpGet("external-callback")]
    public async Task<IActionResult> ExternalCallback([FromQuery] string code, [FromQuery] string? state = null, [FromQuery] string? returnUrl = null)
    {
        // This is a simplified version - in production, you'd need to validate the code with the external provider
        
        // For demo purposes, we'll create a mock external user
        var email = "external@example.com";
        var firstName = "External";
        var lastName = "User";
        var provider = "Google"; // or determine from state
        var externalUserId = "external_123";

        var user = await _userService.FindByExternalLoginAsync(provider, externalUserId);
        if (user == null)
        {
            user = await _userService.FindByEmailAsync(email);
            if (user == null)
            {
                user = await _userService.CreateUserAsync(email, firstName, lastName);
            }
            await _userService.AddExternalLoginAsync(user.Id, provider, externalUserId, provider);
        }

        // Create .NET Authentication session
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName),
            new Claim("name", $"{user.FirstName} {user.LastName}")
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties { IsPersistent = true });

        if (string.IsNullOrEmpty(returnUrl))
        {
            return Ok(new
            {
                success = true,
                user = new
                {
                    id = user.Id,
                    email = user.Email,
                    firstName = user.FirstName,
                    lastName = user.LastName
                },
            });
        }

        return Redirect(returnUrl);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        return await HandleLogout();
    }

    [HttpGet("logout")]
    public async Task<IActionResult> OidcLogout([FromQuery] string? post_logout_redirect_uri = null, [FromQuery] string? id_token_hint = null, [FromQuery] string? state = null)
    {
        Console.WriteLine($"[DEBUG] OIDC Logout - post_logout_redirect_uri: {post_logout_redirect_uri}, state: {state}");
        
        // Validate post_logout_redirect_uri if provided
        if (!string.IsNullOrEmpty(post_logout_redirect_uri))
        {
            // For demo purposes, accept any localhost redirect
            var allowedHosts = new[] { "localhost:7001", "localhost:7002", "localhost:7003", "localhost:7000" };
            var uri = new Uri(post_logout_redirect_uri);
            var isValidRedirect = allowedHosts.Any(host => uri.Authority == host);
            
            if (!isValidRedirect)
            {
                return BadRequest(new { error = "invalid_request", error_description = "Invalid post_logout_redirect_uri" });
            }
        }
        
        await HandleLogout();
        
        // Redirect to post_logout_redirect_uri if provided
        if (!string.IsNullOrEmpty(post_logout_redirect_uri))
        {
            var redirectUrl = post_logout_redirect_uri;
            if (!string.IsNullOrEmpty(state))
                redirectUrl += $"?state={Uri.EscapeDataString(state)}";
                
            Console.WriteLine($"[DEBUG] OIDC Logout - Redirecting to: {redirectUrl}");
            return Redirect(redirectUrl);
        }
        
        return Ok(new { success = true, message = "Logged out successfully" });
    }

    private async Task<IActionResult> HandleLogout()
    {
        Console.WriteLine($"[DEBUG] HandleLogout called - User authenticated: {User.Identity?.IsAuthenticated}");
        
        // Use .NET Authentication to sign out
        if (User.Identity?.IsAuthenticated == true)
        {
            // Sign out using .NET Authentication
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            Console.WriteLine($"[DEBUG] User signed out successfully");
        }
        else
        {
            Console.WriteLine($"[DEBUG] No authenticated user to sign out");
        }

        return Ok(new { success = true, message = "Logged out successfully" });
    }
}

public class LoginRequest
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}

public class OidcFormLoginRequest
{
    [Required]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string Password { get; set; } = string.Empty;
    
    [Required]
    public string ClientId { get; set; } = string.Empty;
    
    [Required]
    public string RedirectUri { get; set; } = string.Empty;
    
    public string ResponseType { get; set; } = "code";
    
    public string? Scope { get; set; }
    
    public string? State { get; set; }
    
    public string? CodeChallenge { get; set; }
    
    public string? CodeChallengeMethod { get; set; }
}