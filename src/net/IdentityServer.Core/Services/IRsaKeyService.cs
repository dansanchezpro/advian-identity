using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Core.Services;

public interface IRsaKeyService
{
    RsaSecurityKey GetRsaSecurityKey();
    SigningCredentials GetSigningCredentials();
    JsonWebKey GetJsonWebKey();
}
