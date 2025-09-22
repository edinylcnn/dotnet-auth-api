using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace DotnetAuth.Api.Services;

public class UpaTokenValidator
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly IConfiguration _cfg;
    private readonly IMemoryCache _cache;

    public UpaTokenValidator(IHttpClientFactory httpFactory, IConfiguration cfg, IMemoryCache cache)
    {
        _httpFactory = httpFactory;
        _cfg = cfg;
        _cache = cache;
    }

    public async Task<ClaimsPrincipal?> ValidateAsync(string token)
    {
        var jwksUrl = _cfg["Upa:JwksUrl"]!;
        var issuer = _cfg["Upa:Issuer"]!;
        var validateAudience = bool.TryParse(_cfg["Upa:ValidateAudience"], out var va) && va;

        var keys = await GetSigningKeysAsync(jwksUrl);
        var handler = new JwtSecurityTokenHandler();

        var parms = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = validateAudience,
            // UPA tokenda audience projenin ayrıntılarına bağlı olabilir; başlangıçta kapatıyoruz.
            ValidateLifetime = true,
            RequireSignedTokens = true,
            IssuerSigningKeys = keys
        };

        try
        {
            var principal = handler.ValidateToken(token, parms, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }

    private async Task<IEnumerable<SecurityKey>> GetSigningKeysAsync(string url)
    {
        if (_cache.TryGetValue(url, out IEnumerable<SecurityKey> cached))
            return cached;

        var http = _httpFactory.CreateClient();
        var json = await http.GetStringAsync(url);
        var jwks = new JsonWebKeySet(json);
        var keys = jwks.GetSigningKeys();

        _cache.Set(url, keys, TimeSpan.FromHours(12)); // Key rotation’a karşı makul cache
        return keys;
    }
}
