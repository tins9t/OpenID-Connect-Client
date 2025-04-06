using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OpenID_Connect_Client.Models;

namespace OpenID_Connect_Client.Controllers;

[Route("[controller]")]
public class AuthController : Controller
{
    private readonly IConfiguration _configuration;
    private readonly JwtTokenHandler _jwtTokenHandler;

    public AuthController(IConfiguration configuration, JwtTokenHandler jwtTokenHandler)
    {
        _configuration = configuration;
        _jwtTokenHandler = jwtTokenHandler;
    }
    
    [Route("login")]
    public IActionResult Login()
    {
        var keycloakConfig = _configuration.GetSection("Keycloak");
        var clientId = keycloakConfig["ClientId"];
        var callback = keycloakConfig["CallBackUri"];
        var authorizationEndpoint = keycloakConfig["AuthorizationEndpoint"];

        var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)); 
        var codeVerifier = Convert.ToHexString(RandomNumberGenerator.GetBytes(48)); 
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        
        HttpContext.Session.SetString(state, codeVerifier);

        var parameters = new Dictionary<string, string?>
        {
            { "client_id", clientId },
            { "scope", "openid email phone address profile" },
            { "response_type", "code" },
            { "redirect_uri", callback },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "S256" },
            { "code_challenge", codeChallenge }
        };

        var authorizationUri = QueryHelpers.AddQueryString(authorizationEndpoint, parameters);

        return Redirect(authorizationUri); 
    }
    
    public record AuthorizationResponse(string state, string code);
    
    [Route("callback")]
    public async Task<IActionResult> Callback(AuthorizationResponse query)
    {
        var (state, code) = query;

        var codeVerifier = HttpContext.Session.GetString(state);
        if (string.IsNullOrEmpty(codeVerifier)) return BadRequest("Invalid state or missing code verifier");

        var keycloakConfig = _configuration.GetSection("Keycloak");
        var clientId = keycloakConfig["ClientId"];
        var clientSecret = keycloakConfig["ClientSecret"];
        var redirectUri = keycloakConfig["CallBackUri"];
        var tokenEndpoint = keycloakConfig["TokenEndpoint"];
        var userInfoEndpoint = keycloakConfig["UserInfoEndpoint"];


        var parameters = new Dictionary<string, string?>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", redirectUri },
            { "client_id", clientId },
            { "client_secret", clientSecret },
            { "code_verifier", codeVerifier }
        };

       var tokenResponse = await new HttpClient().PostAsync(tokenEndpoint, new FormUrlEncodedContent(parameters));
       var payload = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();

       if (payload is null)
       {
           return BadRequest("Invalid response");
       }

       var isValid = await _jwtTokenHandler.ValidateIdToken(payload.id_token);
       if (!isValid)
       {
           return BadRequest("ID token validation failed");
       }
       
       var http = new HttpClient
       {
           DefaultRequestHeaders =
           {
               { "Authorization", "Bearer " + payload.access_token }
           }
       };
       var response = await http.GetAsync(userInfoEndpoint);
       
       if (!response.IsSuccessStatusCode)
       {
           var errorContent = await response.Content.ReadAsStringAsync();
           return BadRequest($"Error fetching user info: {errorContent}");
       }
       
       var content = await response.Content.ReadFromJsonAsync<object?>();
        
       HttpContext.Session.SetString("UserInfo", JsonSerializer.Serialize(content));
       HttpContext.Session.SetString("AccessToken", payload.access_token);

       if (!response.IsSuccessStatusCode)
       {
           return BadRequest();
       }
       
       return Redirect("/index.html");
    }
    
    [Route("whoami")]
    public IActionResult WhoAmI()
    {
        var accessToken = HttpContext.Session.GetString("AccessToken");

        if (string.IsNullOrEmpty(accessToken))
        {
            return Unauthorized("User not authenticated.");
        }

        return Ok(accessToken);
    }

    public string GenerateCodeChallenge(string codeVerifier)
    {
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncode(hash);
        }
    }

    public string Base64UrlEncode(byte[] input)
    {
        var base64 = Convert.ToBase64String(input);
        base64 = base64.Split('=')[0]; 
        base64 = base64.Replace('+', '-'); 
        base64 = base64.Replace('/', '_'); 
        return base64;
    }
}