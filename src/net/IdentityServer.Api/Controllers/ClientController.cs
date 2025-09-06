using Microsoft.AspNetCore.Mvc;
using IdentityServer.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Api.Controllers;

[ApiController]
[Route("api/clients")]
public class ClientController : ControllerBase
{
    private readonly IdentityDbContext _context;

    public ClientController(IdentityDbContext context)
    {
        _context = context;
    }

    [HttpGet("{clientId}")]
    public async Task<IActionResult> GetClient(string clientId)
    {
        var client = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == clientId);

        if (client == null)
        {
            return NotFound();
        }

        return Ok(new
        {
            ClientId = client.ClientId,
            ClientName = client.ClientName,
            RedirectUris = client.RedirectUris,
            PostLogoutRedirectUris = client.PostLogoutRedirectUris,
            AllowedScopes = client.AllowedScopes,
            AllowedGrantTypes = client.AllowedGrantTypes,
            RequirePkce = client.RequirePkce
        });
    }

    [HttpGet]
    public async Task<IActionResult> GetClients()
    {
        var clients = await _context.Clients
            .Select(c => new
            {
                ClientId = c.ClientId,
                ClientName = c.ClientName,
                RedirectUris = c.RedirectUris,
                PostLogoutRedirectUris = c.PostLogoutRedirectUris,
                AllowedScopes = c.AllowedScopes,
                AllowedGrantTypes = c.AllowedGrantTypes,
                RequirePkce = c.RequirePkce
            })
            .ToListAsync();

        return Ok(clients);
    }
}