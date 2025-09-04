using IdentityServer.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Api.Controllers;

[ApiController]
public class DiscoveryController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public DiscoveryController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    [HttpGet(".well-known/openid_configuration")]
    public IActionResult GetDiscoveryDocument()
    {
        Console.WriteLine($"[DEBUG] Discovery endpoint called from: {Request.Headers["Origin"].FirstOrDefault() ?? "no-origin"}, User-Agent: {Request.Headers["User-Agent"].FirstOrDefault() ?? "no-user-agent"}");

        var baseUrl = $"{Request.Scheme}://{Request.Host}";

        var discoveryDocument = new
        {
            issuer = baseUrl,
            authorization_endpoint = $"{baseUrl}/api/auth/oidc-login",
            token_endpoint = $"{baseUrl}/connect/token",
            userinfo_endpoint = $"{baseUrl}/connect/userinfo",
            end_session_endpoint = $"{baseUrl}/api/auth/logout",
            jwks_uri = $"{baseUrl}/.well-known/jwks",
            scopes_supported = new[]
            {
                "openid",
                "profile",
                "email",
                "api1",
                "api2",
                "api3",
                "identity-api"
            },
            response_types_supported = new[] { "code" },
            response_modes_supported = new[] { "query" },
            grant_types_supported = new[] { "authorization_code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "none" },
            claims_supported = new[]
            {
                "sub",
                "email",
                "given_name",
                "family_name",
                "name"
            },
            code_challenge_methods_supported = new[] { "plain", "S256" }
        };

        return Ok(discoveryDocument);
    }

    [HttpGet(".well-known/jwks")]
    public IActionResult GetJwks([FromServices] IRsaKeyService rsaKeyService)
    {
        var jwk = rsaKeyService.GetJsonWebKey();

        var jwks = new
        {
            keys = new[] { jwk }
        };

        return Ok(jwks);
    }
}