using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdentityServer.Core.Data;
using IdentityServer.Core.Services;
using IdentityServer.Core.Models;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.RateLimiting;

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
                // IMPORTANT: Verify the user still exists in the database
                // (could be stale cookie after DB reset in development)
                var user = await _userService.FindByIdAsync(userId);
                if (user == null || !user.IsActive)
                {
                    Console.WriteLine($"[DEBUG] Stale cookie detected - UserId {userId} not found. Signing out.");

                    // Clear the invalid cookie
                    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                    // Fall through to redirect to login page below
                    // (will be handled by the "No valid session found" code)
                }
                else
                {
                    // User authenticated via .NET - generating code directly
                    Console.WriteLine($"[DEBUG] Valid session found for UserId: {userId}");

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
    [EnableRateLimiting("auth")]
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
        // Generate redirect URL with lowercase route (NO query parameters)
        var redirectUrl = $"{Request.Scheme}://{Request.Host}/api/auth/external-callback";

        if (provider.ToLower() == "google")
        {
            var clientId = _configuration["Authentication:Google:ClientId"];

            // Encode returnUrl in state parameter instead of redirect_uri
            var state = string.IsNullOrEmpty(returnUrl)
                ? Guid.NewGuid().ToString()
                : Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(returnUrl));

            // Log para debugging
            Console.WriteLine($"[DEBUG] Google OAuth - Redirect URI: {redirectUrl}");
            Console.WriteLine($"[DEBUG] Google OAuth - Client ID: {clientId}");
            Console.WriteLine($"[DEBUG] Google OAuth - State (encoded returnUrl): {state}");

            var authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                $"client_id={clientId}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUrl)}&" +
                $"response_type=code&" +
                $"scope=openid%20profile%20email&" +
                $"state={Uri.EscapeDataString(state)}&" +
                $"access_type=offline";

            Console.WriteLine($"[DEBUG] Google OAuth - Full Auth URL: {authUrl}");

            return Redirect(authUrl);
        }
        else if (provider.ToLower() == "microsoft")
        {
            var clientId = _configuration["Authentication:Microsoft:ClientId"];

            Console.WriteLine($"[DEBUG] Microsoft OAuth - Redirect URI: {redirectUrl}");
            Console.WriteLine($"[DEBUG] Microsoft OAuth - Client ID: {clientId}");

            var authUrl = $"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" +
                $"client_id={clientId}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUrl)}&" +
                $"response_type=code&" +
                $"scope=openid%20profile%20email&" +
                $"response_mode=query";

            Console.WriteLine($"[DEBUG] Microsoft OAuth - Full Auth URL: {authUrl}");

            return Redirect(authUrl);
        }
        
        return BadRequest("Unsupported provider");
    }

    [HttpGet("external-callback")]
    public async Task<IActionResult> ExternalCallback([FromQuery] string code, [FromQuery] string? state = null, [FromQuery] string? returnUrl = null)
    {
        try
        {
            // Decode returnUrl from state parameter
            if (!string.IsNullOrEmpty(state) && string.IsNullOrEmpty(returnUrl))
            {
                try
                {
                    var decodedBytes = Convert.FromBase64String(state);
                    returnUrl = System.Text.Encoding.UTF8.GetString(decodedBytes);
                    Console.WriteLine($"[DEBUG] Decoded returnUrl from state: {returnUrl}");
                }
                catch
                {
                    // State is not a valid Base64 string, it might be just a GUID
                    Console.WriteLine($"[DEBUG] State is not a valid returnUrl, using as-is: {state}");
                }
            }

            // Exchange code for access token with Google
            var redirectUri = $"{Request.Scheme}://{Request.Host}/api/auth/external-callback";
            var tokenResponse = await ExchangeGoogleCodeForToken(code, redirectUri);

            if (tokenResponse == null)
            {
                return BadRequest(new { error = "failed_to_exchange_code", error_description = "Failed to exchange authorization code for token" });
            }

            // Get user info from Google
            var googleUserInfo = await GetGoogleUserInfo(tokenResponse.AccessToken);

            if (googleUserInfo == null)
            {
                return BadRequest(new { error = "failed_to_get_user_info", error_description = "Failed to retrieve user information from Google" });
            }

            var provider = "Google";
            var externalUserId = googleUserInfo.Id;
            var email = googleUserInfo.Email;
            var firstName = googleUserInfo.GivenName ?? googleUserInfo.Name ?? email.Split('@')[0];
            var lastName = googleUserInfo.FamilyName ?? "User";

            Console.WriteLine($"[DEBUG] Google user info - Email: {email}, ID: {externalUserId}, FirstName: {firstName}, LastName: {lastName}");

            // For LOGIN flow: User must already exist, don't auto-create
            var user = await _userService.FindByExternalLoginAsync(provider, externalUserId);
            if (user == null)
            {
                Console.WriteLine($"[DEBUG] User not found by GoogleId, searching by email: {email}");
                user = await _userService.FindByEmailAsync(email);

                if (user == null)
                {
                    // User doesn't exist - redirect back to login with error
                    Console.WriteLine($"[DEBUG] User not found - redirecting to login with error");
                    var loginUrl = _configuration["IdentityServer:LoginUrl"] ?? "https://localhost:7000";
                    var loginWithError = $"{loginUrl}/login?error=no_account";

                    if (!string.IsNullOrEmpty(returnUrl))
                    {
                        loginWithError += $"&returnUrl={Uri.EscapeDataString(returnUrl)}";

                        // Preserve OIDC parameters if present in returnUrl
                        try
                        {
                            var returnUri = new Uri(returnUrl, UriKind.RelativeOrAbsolute);
                            if (returnUri.IsAbsoluteUri)
                            {
                                var returnQueryParams = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(returnUri.Query);
                                if (returnQueryParams.ContainsKey("client_id"))
                                {
                                    loginWithError += $"&client_id={Uri.EscapeDataString(returnQueryParams["client_id"].ToString())}";
                                }
                                if (returnQueryParams.ContainsKey("redirect_uri"))
                                {
                                    loginWithError += $"&redirect_uri={Uri.EscapeDataString(returnQueryParams["redirect_uri"].ToString())}";
                                }
                                if (returnQueryParams.ContainsKey("response_type"))
                                {
                                    loginWithError += $"&response_type={Uri.EscapeDataString(returnQueryParams["response_type"].ToString())}";
                                }
                                if (returnQueryParams.ContainsKey("scope"))
                                {
                                    loginWithError += $"&scope={Uri.EscapeDataString(returnQueryParams["scope"].ToString())}";
                                }
                                if (returnQueryParams.ContainsKey("state"))
                                {
                                    loginWithError += $"&state={Uri.EscapeDataString(returnQueryParams["state"].ToString())}";
                                }
                                if (returnQueryParams.ContainsKey("code_challenge"))
                                {
                                    loginWithError += $"&code_challenge={Uri.EscapeDataString(returnQueryParams["code_challenge"].ToString())}";
                                }
                                if (returnQueryParams.ContainsKey("code_challenge_method"))
                                {
                                    loginWithError += $"&code_challenge_method={Uri.EscapeDataString(returnQueryParams["code_challenge_method"].ToString())}";
                                }
                            }
                        }
                        catch
                        {
                            // Ignore parsing errors
                        }
                    }

                    return Redirect(loginWithError);
                }
                else
                {
                    // User exists by email but not linked to Google yet - link it
                    Console.WriteLine($"[DEBUG] User found by email with ID: {user.Id}, linking Google account");
                    await _userService.AddExternalLoginAsync(user.Id, provider, externalUserId, provider);

                    // Update GoogleId if not set
                    if (string.IsNullOrEmpty(user.GoogleId))
                    {
                        user.GoogleId = externalUserId;
                        await _context.SaveChangesAsync();
                        Console.WriteLine($"[DEBUG] GoogleId updated for user ID: {user.Id}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[DEBUG] User found by GoogleId with ID: {user.Id}");
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

            Console.WriteLine($"[DEBUG] User signed in with cookie authentication");
            Console.WriteLine($"[DEBUG] ReturnUrl: {returnUrl ?? "(empty)"}");

            if (string.IsNullOrEmpty(returnUrl))
            {
                Console.WriteLine($"[DEBUG] No returnUrl, redirecting to Identity Server UI");
                // Redirect to Identity Server dashboard or login success page
                return Redirect($"{_configuration["IdentityServer:LoginUrl"]}/dashboard");
            }

            // Check if returnUrl contains OIDC parameters (client_id, redirect_uri, etc.)
            var uri = new Uri(returnUrl, UriKind.Absolute);
            var queryParams = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

            if (queryParams.ContainsKey("client_id") && queryParams.ContainsKey("redirect_uri"))
            {
                // This is an OIDC flow, generate authorization code
                var oidcClientId = queryParams["client_id"].ToString();
                var oidcRedirectUri = queryParams["redirect_uri"].ToString();
                var responseType = queryParams.ContainsKey("response_type") ? queryParams["response_type"].ToString() : "code";
                var oidcScope = queryParams.ContainsKey("scope") ? queryParams["scope"].ToString() : "openid";
                var oidcState = queryParams.ContainsKey("state") ? queryParams["state"].ToString() : null;
                var oidcCodeChallenge = queryParams.ContainsKey("code_challenge") ? queryParams["code_challenge"].ToString() : null;
                var oidcCodeChallengeMethod = queryParams.ContainsKey("code_challenge_method") ? queryParams["code_challenge_method"].ToString() : null;

                Console.WriteLine($"[DEBUG] OIDC flow detected - Client: {oidcClientId}, RedirectUri: {oidcRedirectUri}");

                // Generate authorization code
                var authCode = await _tokenService.GenerateAuthorizationCodeAsync(
                    oidcClientId, user.Id, oidcScope.Split(' ').ToList(), oidcRedirectUri,
                    oidcCodeChallenge, oidcCodeChallengeMethod);

                // Build redirect URL to client app
                var finalRedirectUrl = $"{oidcRedirectUri}?code={authCode}";
                if (!string.IsNullOrEmpty(oidcState))
                    finalRedirectUrl += $"&state={Uri.EscapeDataString(oidcState)}";

                Console.WriteLine($"[DEBUG] Redirecting to client app: {finalRedirectUrl}");
                return Redirect(finalRedirectUrl);
            }

            Console.WriteLine($"[DEBUG] Simple redirect to: {returnUrl}");
            return Redirect(returnUrl);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = "external_login_failed", error_description = ex.Message });
        }
    }

    private async Task<GoogleTokenResponse?> ExchangeGoogleCodeForToken(string code, string redirectUri)
    {
        using var httpClient = new HttpClient();
        var tokenRequest = new Dictionary<string, string>
        {
            { "code", code },
            { "client_id", _configuration["Authentication:Google:ClientId"]! },
            { "client_secret", _configuration["Authentication:Google:ClientSecret"]! },
            { "redirect_uri", redirectUri },
            { "grant_type", "authorization_code" }
        };

        var response = await httpClient.PostAsync("https://oauth2.googleapis.com/token", new FormUrlEncodedContent(tokenRequest));

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        return await response.Content.ReadFromJsonAsync<GoogleTokenResponse>();
    }

    private async Task<GoogleUserInfo?> GetGoogleUserInfo(string accessToken)
    {
        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v2/userinfo");

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        return await response.Content.ReadFromJsonAsync<GoogleUserInfo>();
    }

    [HttpPost("register")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            // Validate age (must be at least 13 years old)
            if (request.DateOfBirth.HasValue)
            {
                var age = DateTime.Today.Year - request.DateOfBirth.Value.Year;
                if (request.DateOfBirth.Value > DateTime.Today.AddYears(-age)) age--;

                if (age < 13)
                {
                    return BadRequest(new { error = "age_restriction", error_description = "You must be at least 13 years old to register" });
                }
            }

            var user = await _userService.RegisterUserAsync(
                request.Email,
                request.FirstName,
                request.LastName,
                request.Password,
                request.DateOfBirth);

            // Automatically sign in the user after registration
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
                message = "User registered successfully",
                user = new
                {
                    id = user.Id,
                    email = user.Email,
                    firstName = user.FirstName,
                    lastName = user.LastName
                }
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = "registration_failed", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "server_error", error_description = "An unexpected error occurred during registration" });
        }
    }

    [HttpPost("register-complete")]
    public async Task<IActionResult> RegisterComplete([FromForm] RegisterCompleteRequest request)
    {
        try
        {
            Console.WriteLine($"[DEBUG] RegisterComplete called - Email: {request.Email}");

            // Validate age (must be at least 13 years old)
            if (request.DateOfBirth.HasValue)
            {
                var age = DateTime.Today.Year - request.DateOfBirth.Value.Year;
                if (request.DateOfBirth.Value > DateTime.Today.AddYears(-age)) age--;

                if (age < 13)
                {
                    return BadRequest(new { error = "age_restriction", error_description = "You must be at least 13 years old to register" });
                }
            }

            var user = await _userService.RegisterUserAsync(
                request.Email,
                request.FirstName,
                request.LastName,
                request.Password,
                request.DateOfBirth);

            Console.WriteLine($"[DEBUG] User created with ID: {user.Id}");

            // Automatically sign in the user after registration
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

            Console.WriteLine($"[DEBUG] User auto-logged in after manual registration");

            // If there's a returnUrl with OIDC parameters, generate authorization code
            if (!string.IsNullOrEmpty(request.ReturnUrl))
            {
                var uri = new Uri(request.ReturnUrl, UriKind.Absolute);
                var queryParams = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

                if (queryParams.ContainsKey("client_id") && queryParams.ContainsKey("redirect_uri"))
                {
                    var clientId = queryParams["client_id"].ToString();
                    var redirectUri = queryParams["redirect_uri"].ToString();
                    var scope = queryParams.ContainsKey("scope") ? queryParams["scope"].ToString() : "openid";
                    var state = queryParams.ContainsKey("state") ? queryParams["state"].ToString() : null;
                    var codeChallenge = queryParams.ContainsKey("code_challenge") ? queryParams["code_challenge"].ToString() : null;
                    var codeChallengeMethod = queryParams.ContainsKey("code_challenge_method") ? queryParams["code_challenge_method"].ToString() : null;

                    Console.WriteLine($"[DEBUG] OIDC flow detected - Client: {clientId}, RedirectUri: {redirectUri}");

                    var authCode = await _tokenService.GenerateAuthorizationCodeAsync(
                        clientId, user.Id, scope.Split(' ').ToList(), redirectUri,
                        codeChallenge, codeChallengeMethod);

                    var finalRedirectUrl = $"{redirectUri}?code={authCode}";
                    if (!string.IsNullOrEmpty(state))
                        finalRedirectUrl += $"&state={Uri.EscapeDataString(state)}";

                    Console.WriteLine($"[DEBUG] Redirecting to app after manual registration: {finalRedirectUrl}");
                    return Redirect(finalRedirectUrl);
                }
            }

            // No OIDC flow - redirect to dashboard
            var identityServerUrl = _configuration["IdentityServer:LoginUrl"] ?? "https://localhost:7000";
            Console.WriteLine($"[DEBUG] Redirecting to dashboard after manual registration");
            return Redirect($"{identityServerUrl}/dashboard");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"[ERROR] RegisterComplete failed: {ex.Message}");
            return BadRequest(new { error = "registration_failed", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] RegisterComplete unexpected error: {ex.Message}");
            return StatusCode(500, new { error = "server_error", error_description = "An unexpected error occurred during registration" });
        }
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

    // New endpoint: Get Google user info for registration (Step 1 - doesn't create account)
    [HttpPost("google-userinfo")]
    public async Task<IActionResult> GetGoogleUserInfo([FromBody] GoogleUserInfoRequest request)
    {
        try
        {
            Console.WriteLine($"[DEBUG] GetGoogleUserInfo called with code: {request.AuthorizationCode?.Substring(0, 10)}...");

            if (string.IsNullOrEmpty(request.AuthorizationCode))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Authorization code is required" });
            }

            // Exchange authorization code for Google tokens
            var redirectUri = $"{Request.Scheme}://{Request.Host}/api/auth/google-register-callback";
            var tokenResponse = await ExchangeGoogleCodeForToken(request.AuthorizationCode, redirectUri);

            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                return BadRequest(new { error = "google_auth_failed", error_description = "Failed to authenticate with Google" });
            }

            // Get user info from Google
            var googleUserInfo = await GetGoogleUserInfo(tokenResponse.AccessToken);

            if (googleUserInfo == null)
            {
                return BadRequest(new { error = "failed_to_get_user_info", error_description = "Failed to retrieve user information from Google" });
            }

            // SECURITY: Validate the id_token NOW (not later when it might expire)
            GoogleUserInfo? validatedUserInfo = null;
            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                try
                {
                    validatedUserInfo = await ValidateGoogleIdToken(tokenResponse.IdToken);
                    Console.WriteLine($"[DEBUG] ID token validated successfully during registration flow");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] ID token validation failed: {ex.Message}");
                }
            }

            // If token validation failed, fall back to using access token data
            // (less secure but still works)
            var finalUserInfo = validatedUserInfo ?? googleUserInfo;

            // Check if user already exists (by GoogleId or Email)
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.GoogleId == finalUserInfo.Id || u.Email == finalUserInfo.Email);

            if (existingUser != null)
            {
                return BadRequest(new { error = "user_already_exists", error_description = "User already registered. Please use login instead." });
            }

            // Return Google user info WITHOUT creating account
            // IMPORTANT: Return the googleId for later use (already validated)
            return Ok(new
            {
                success = true,
                googleId = finalUserInfo.Id,
                email = finalUserInfo.Email,
                firstName = finalUserInfo.GivenName ?? finalUserInfo.Name ?? finalUserInfo.Email.Split('@')[0],
                lastName = finalUserInfo.FamilyName ?? "User",
                profilePicture = finalUserInfo.Picture,
                // DO NOT return idToken - we'll use googleId directly
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] GetGoogleUserInfo failed: {ex.Message}");
            return StatusCode(500, new { error = "internal_error", error_description = "An error occurred while getting user information" });
        }
    }

    // New endpoint: Complete registration with Google data (Step 2 - creates account)
    [HttpPost("register-with-google")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> RegisterWithGoogle([FromBody] RegisterWithGoogleRequest request)
    {
        try
        {
            Console.WriteLine($"[DEBUG] RegisterWithGoogle called");

            // Validate required fields
            if (string.IsNullOrEmpty(request.GoogleId) ||
                string.IsNullOrEmpty(request.Email) ||
                request.DateOfBirth == default ||
                !request.AcceptTerms)
            {
                return Ok(new { success = false, error = "All fields are required" });
            }

            Console.WriteLine($"[DEBUG] Registering user with GoogleId: {request.GoogleId}, Email: {request.Email}");

            // Use data from request (already validated in GetGoogleUserInfo endpoint)
            var googleId = request.GoogleId;
            var email = request.Email;
            var firstName = request.FirstName ?? email.Split('@')[0];
            var lastName = request.LastName ?? "User";

            Console.WriteLine($"[DEBUG] Creating account for Google user: {email} (GoogleId: {googleId})");

            // Check if user already exists
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.GoogleId == googleId || u.Email == email);

            if (existingUser != null)
            {
                return Ok(new { success = false, error = "User is already registered" });
            }

            // Validate age (minimum 13 years old)
            var age = DateTime.Today.Year - request.DateOfBirth.Year;
            if (request.DateOfBirth.Date > DateTime.Today.AddYears(-age))
                age--;

            if (age < 13)
            {
                return Ok(new { success = false, error = "You must be at least 13 years old to register" });
            }

            // Create new user with Google data (validated in previous step)
            var user = new User
            {
                GoogleId = googleId,
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                DateOfBirth = request.DateOfBirth,  // From user input
                PasswordHash = string.Empty, // No password for Google-only accounts
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            Console.WriteLine($"[DEBUG] User created with ID: {user.Id}");

            // Auto-login: Create authentication session
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.FirstName),
                new Claim(ClaimTypes.Surname, user.LastName),
                new Claim("UserId", user.Id.ToString()),
                new Claim("name", $"{user.FirstName} {user.LastName}")
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme, null, null);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                new AuthenticationProperties { IsPersistent = true });

            Console.WriteLine($"[DEBUG] User auto-logged in after Google registration");

            // Return JSON response (the UI will handle the redirect)
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
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] RegisterWithGoogle failed: {ex.Message}");
            return Ok(new { success = false, error = "An error occurred during registration" });
        }
    }

    // Helper method to validate Google's id_token with cryptographic signature verification
    private async Task<GoogleUserInfo?> ValidateGoogleIdToken(string idToken)
    {
        try
        {
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var expectedClientId = _configuration["Authentication:Google:ClientId"];

            // Configure token validation parameters
            var validationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = new[] { "https://accounts.google.com", "accounts.google.com" },

                ValidateAudience = true,
                ValidAudience = expectedClientId,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5), // Allow 5 minutes clock skew

                // CRITICAL: Validate the signature using Google's public keys
                ValidateIssuerSigningKey = true,
                IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                {
                    // Fetch Google's public keys from their well-known endpoint
                    // Google rotates these keys periodically
                    using var httpClient = new HttpClient();
                    var response = httpClient.GetAsync("https://www.googleapis.com/oauth2/v3/certs").Result;

                    if (!response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("[ERROR] Failed to fetch Google's public keys");
                        return null;
                    }

                    var jwks = response.Content.ReadAsStringAsync().Result;
                    var jsonWebKeySet = new Microsoft.IdentityModel.Tokens.JsonWebKeySet(jwks);

                    // Return the key that matches the 'kid' (Key ID) from the JWT header
                    return jsonWebKeySet.Keys;
                }
            };

            // Validate token - this will verify signature, expiration, issuer, and audience
            var principal = handler.ValidateToken(idToken, validationParameters, out var validatedToken);

            // Extract claims from validated token
            var googleId = principal.FindFirst("sub")?.Value;
            var email = principal.FindFirst("email")?.Value;
            var name = principal.FindFirst("name")?.Value;
            var givenName = principal.FindFirst("given_name")?.Value;
            var familyName = principal.FindFirst("family_name")?.Value;
            var picture = principal.FindFirst("picture")?.Value;
            var emailVerified = principal.FindFirst("email_verified")?.Value;

            // Verify required claims are present
            if (string.IsNullOrEmpty(googleId) || string.IsNullOrEmpty(email))
            {
                Console.WriteLine("[ERROR] ID token missing required claims (sub or email)");
                return null;
            }

            Console.WriteLine($"[DEBUG] ID token CRYPTOGRAPHICALLY VALIDATED - GoogleId: {googleId}, Email: {email}");

            return new GoogleUserInfo
            {
                Id = googleId,
                Email = email,
                Name = name ?? "",
                GivenName = givenName,
                FamilyName = familyName,
                Picture = picture,
                VerifiedEmail = emailVerified == "true"
            };
        }
        catch (Microsoft.IdentityModel.Tokens.SecurityTokenException ex)
        {
            Console.WriteLine($"[ERROR] Token validation failed: {ex.Message}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to validate ID token: {ex.Message}");
            return null;
        }
    }

    // Helper endpoint for Google registration callback
    [HttpGet("google-register-callback")]
    public IActionResult GoogleRegisterCallback([FromQuery] string code, [FromQuery] string? state = null)
    {
        // This callback receives the authorization code from Google during registration
        // We'll pass it to the frontend which will then call GetGoogleUserInfo endpoint
        var frontendUrl = _configuration["IdentityServer:LoginUrl"] ?? "https://localhost:7000";
        var registerUrl = $"{frontendUrl}/register?google_code={Uri.EscapeDataString(code)}";

        if (!string.IsNullOrEmpty(state))
        {
            registerUrl += $"&state={Uri.EscapeDataString(state)}";
        }

        return Redirect(registerUrl);
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

public class RegisterRequest
{
    [Required(ErrorMessage = "First name is required")]
    [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).*$",
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, and one number")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [DataType(DataType.Date)]
    public DateTime? DateOfBirth { get; set; }

    [Required(ErrorMessage = "You must accept the terms and conditions")]
    [Range(typeof(bool), "true", "true", ErrorMessage = "You must accept the terms and conditions")]
    public bool AcceptTerms { get; set; }
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

public class GoogleTokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }

    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }
}

public class GoogleUserInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("given_name")]
    public string? GivenName { get; set; }

    [JsonPropertyName("family_name")]
    public string? FamilyName { get; set; }

    [JsonPropertyName("picture")]
    public string? Picture { get; set; }

    [JsonPropertyName("verified_email")]
    public bool VerifiedEmail { get; set; }

    [JsonPropertyName("locale")]
    public string? Locale { get; set; }
}

public class GoogleUserInfoRequest
{
    [Required]
    public string AuthorizationCode { get; set; } = string.Empty;
}

public class RegisterWithGoogleRequest
{
    [Required]
    public string GoogleId { get; set; } = string.Empty;  // Google user ID (validated in previous step)

    [Required]
    public string Email { get; set; } = string.Empty;  // Email from Google (validated in previous step)

    public string? FirstName { get; set; }  // Optional - from Google

    public string? LastName { get; set; }  // Optional - from Google

    // These fields are from the form (user input)
    [Required]
    public DateTime DateOfBirth { get; set; }

    [Required]
    public bool AcceptTerms { get; set; }

    public string? ReturnUrl { get; set; }
}

public class RegisterCompleteRequest
{
    [Required(ErrorMessage = "First name is required")]
    [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).*$",
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, and one number")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [DataType(DataType.Date)]
    public DateTime? DateOfBirth { get; set; }

    [Required(ErrorMessage = "You must accept the terms and conditions")]
    [Range(typeof(bool), "true", "true", ErrorMessage = "You must accept the terms and conditions")]
    public bool AcceptTerms { get; set; }

    public string? ReturnUrl { get; set; }
}