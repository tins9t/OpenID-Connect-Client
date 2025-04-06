using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

public class JwtTokenHandler
{
    private readonly IConfiguration _configuration;

    public JwtTokenHandler(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public async Task<bool> ValidateIdToken(string idToken)
    {
        try
        {
            var keycloakConfig = _configuration.GetSection("Keycloak");
            var jwksUri = keycloakConfig["JwksUri"];
            var clientId = keycloakConfig["ClientId"];
            
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(idToken);
            
            var response = await new HttpClient().GetAsync(jwksUri);
            var keys = await response.Content.ReadAsStringAsync();
            var jwks = new JsonWebKeySet(keys);
            jwks.SkipUnresolvedJsonWebKeys = false;
            
            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = jwtToken.Issuer,
                ValidAudience = clientId,
                IssuerSigningKeys = jwks.Keys,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true
            };

            handler.ValidateToken(idToken, validationParameters, out _);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string base64 = input.Replace('-', '+').Replace('_', '/');
        while (base64.Length % 4 != 0)
        {
            base64 += "=";
        }
        return Convert.FromBase64String(base64);
    }
}