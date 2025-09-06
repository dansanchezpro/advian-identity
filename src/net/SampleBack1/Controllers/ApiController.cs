using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SampleBack1.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ApiController : ControllerBase
{
    private readonly ILogger<ApiController> _logger;

    public ApiController(ILogger<ApiController> logger)
    {
        _logger = logger;
    }

    [HttpGet("public")]
    public IActionResult GetPublicData()
    {
        _logger.LogInformation("[SAMPLEBACK1] Public endpoint accessed");
        
        return Ok(new
        {
            message = "This is public data - no authentication required",
            timestamp = DateTime.UtcNow,
            server = "SampleBack1 API"
        });
    }

    [HttpGet("protected")]
    [Authorize]
    public IActionResult GetProtectedData()
    {
        var userId = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst("email")?.Value ?? User.FindFirst(ClaimTypes.Email)?.Value;
        var name = User.FindFirst("name")?.Value ?? User.FindFirst(ClaimTypes.Name)?.Value;

        _logger.LogInformation("[SAMPLEBACK1] Protected endpoint accessed by user: {Email} (ID: {UserId})", email, userId);

        return Ok(new
        {
            message = "This is protected data - authentication required!",
            timestamp = DateTime.UtcNow,
            server = "SampleBack1 API",
            user = new
            {
                id = userId,
                email = email,
                name = name
            },
            scopes = User.FindAll("scope").Select(c => c.Value).ToList(),
            allClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
        });
    }

    [HttpGet("weather")]
    [Authorize]
    public IActionResult GetWeatherData()
    {
        var userId = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst("email")?.Value ?? User.FindFirst(ClaimTypes.Email)?.Value;

        _logger.LogInformation("[SAMPLEBACK1] Weather endpoint accessed by user: {Email}", email);

        var summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        var forecast = Enumerable.Range(1, 5).Select(index =>
            new WeatherForecast
            (
                DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                Random.Shared.Next(-20, 55),
                summaries[Random.Shared.Next(summaries.Length)]
            ))
            .ToArray();

        return Ok(new
        {
            message = $"Weather data for user: {email}",
            timestamp = DateTime.UtcNow,
            userId = userId,
            forecast = forecast
        });
    }

    [HttpGet("user-info")]
    [Authorize]
    public IActionResult GetUserInfo()
    {
        var userId = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst("email")?.Value ?? User.FindFirst(ClaimTypes.Email)?.Value;
        var givenName = User.FindFirst("given_name")?.Value ?? User.FindFirst(ClaimTypes.GivenName)?.Value;
        var familyName = User.FindFirst("family_name")?.Value ?? User.FindFirst(ClaimTypes.Surname)?.Value;
        var name = User.FindFirst("name")?.Value ?? User.FindFirst(ClaimTypes.Name)?.Value;

        _logger.LogInformation("[SAMPLEBACK1] User info endpoint accessed by: {Email}", email);

        return Ok(new
        {
            message = "User information from JWT token",
            timestamp = DateTime.UtcNow,
            server = "SampleBack1 API",
            user = new
            {
                id = userId,
                email = email,
                givenName = givenName,
                familyName = familyName,
                name = name,
                scopes = User.FindAll("scope").Select(c => c.Value).ToList()
            },
            token_info = new
            {
                issuer = User.FindFirst("iss")?.Value,
                audience = User.FindAll("aud").Select(c => c.Value).ToList(),
                expiry = User.FindFirst("exp")?.Value,
                issuedAt = User.FindFirst("iat")?.Value,
                jwtId = User.FindFirst("jti")?.Value
            }
        });
    }

    [HttpPost("test-refresh")]
    [Authorize]
    public IActionResult TestTokenRefresh([FromBody] TestRefreshRequest request)
    {
        var userId = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst("email")?.Value ?? User.FindFirst(ClaimTypes.Email)?.Value;

        _logger.LogInformation("[SAMPLEBACK1] Token refresh test endpoint accessed by: {Email}", email);

        return Ok(new
        {
            message = "Token is valid and request processed successfully!",
            timestamp = DateTime.UtcNow,
            server = "SampleBack1 API",
            request_data = request,
            user = new
            {
                id = userId,
                email = email
            },
            token_expiry = User.FindFirst("exp")?.Value,
            note = "If you see this, your access token is valid. If it was refreshed automatically, the OIDC client handled it transparently."
        });
    }

    [HttpGet("token-info")]
    [Authorize]
    public IActionResult GetTokenInfo()
    {
        var userId = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst("email")?.Value ?? User.FindFirst(ClaimTypes.Email)?.Value;
        var expClaim = User.FindFirst("exp")?.Value;
        var iatClaim = User.FindFirst("iat")?.Value;

        _logger.LogInformation("[SAMPLEBACK1] Token info endpoint accessed by: {Email}", email);

        DateTime? expiryTime = null;
        DateTime? issuedTime = null;
        TimeSpan? timeRemaining = null;

        if (long.TryParse(expClaim, out var expUnix))
        {
            expiryTime = DateTimeOffset.FromUnixTimeSeconds(expUnix).DateTime;
            timeRemaining = expiryTime - DateTime.UtcNow;
        }

        if (long.TryParse(iatClaim, out var iatUnix))
        {
            issuedTime = DateTimeOffset.FromUnixTimeSeconds(iatUnix).DateTime;
        }

        return Ok(new
        {
            message = "Token information",
            timestamp = DateTime.UtcNow,
            server = "SampleBack1 API",
            user = new
            {
                id = userId,
                email = email
            },
            token = new
            {
                issued_at = issuedTime?.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                expires_at = expiryTime?.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                time_remaining = timeRemaining?.TotalSeconds > 0 ? 
                    $"{Math.Floor(timeRemaining.Value.TotalMinutes)}m {timeRemaining.Value.Seconds}s" : 
                    "EXPIRED",
                seconds_remaining = Math.Max(0, (int)(timeRemaining?.TotalSeconds ?? 0)),
                is_expired = timeRemaining?.TotalSeconds <= 0
            },
            raw_claims = new
            {
                exp = expClaim,
                iat = iatClaim
            }
        });
    }
}

public record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public record TestRefreshRequest(string? TestData, DateTime RequestTime);