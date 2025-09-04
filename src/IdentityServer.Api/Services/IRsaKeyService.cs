using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace IdentityServer.Api.Services;

public interface IRsaKeyService
{
    RsaSecurityKey GetRsaSecurityKey();
    SigningCredentials GetSigningCredentials();
    JsonWebKey GetJsonWebKey();
}

public class RsaKeyService : IRsaKeyService, IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _rsaSecurityKey;
    
    public RsaKeyService()
    {
        _rsa = RSA.Create(2048);
        _rsaSecurityKey = new RsaSecurityKey(_rsa) { KeyId = "default-rsa-key" };
    }
    
    public RsaSecurityKey GetRsaSecurityKey() => _rsaSecurityKey;
    
    public SigningCredentials GetSigningCredentials() => 
        new SigningCredentials(_rsaSecurityKey, SecurityAlgorithms.RsaSha256);
    
    public JsonWebKey GetJsonWebKey()
    {
        var parameters = _rsa.ExportParameters(false);
        
        return new JsonWebKey
        {
            Kty = "RSA",
            Use = "sig",
            Alg = "RS256",
            Kid = "default-rsa-key",
            N = Base64UrlEncode(parameters.Modulus!),
            E = Base64UrlEncode(parameters.Exponent!)
        };
    }
    
    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }
    
    public void Dispose()
    {
        _rsa?.Dispose();
    }
}