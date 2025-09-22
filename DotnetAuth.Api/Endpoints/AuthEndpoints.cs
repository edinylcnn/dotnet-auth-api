using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotnetAuth.Api.Contracts;
using DotnetAuth.Api.Data;
using DotnetAuth.Api.Models;
using DotnetAuth.Api.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace DotnetAuth.Api.Endpoints
{
    public static class AuthEndpoints
    {
        public static RouteGroupBuilder MapAuthEndpoints(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("/auth")
                              .WithTags("Auth");

            // GET /auth/check-username
            group.MapGet("/check-username", async (string username, AppDbContext db) =>
            {
                var exists = await db.Users.AnyAsync(u => u.Username == username);
                var message = exists ? "This username already exists." : "This username is available.";
                return Results.Ok(new ExistsResponse(exists, message));
            })
            .WithName("CheckUsername")
            .WithSummary("Check if username already exists")
            .Produces<ExistsResponse>(StatusCodes.Status200OK);

            // GET /auth/check-email
            group.MapGet("/check-email", async (string email, AppDbContext db) =>
            {
                var exists = await db.Users.AnyAsync(u => u.Email == email);
                var message = exists ? "There is already an account with this email address." : "Email is available.";
                return Results.Ok(new ExistsResponse(exists, message));
            })
            .WithName("CheckEmail")
            .WithSummary("Check if email already exists")
            .Produces<ExistsResponse>(StatusCodes.Status200OK);

            // POST /auth/signup
            group.MapPost("/signup", async (SignUpRequest req, AppDbContext db) =>
            {
                if (await db.Users.AnyAsync(u => u.Username == req.Username))
                    return Results.Conflict(new { message = "This username already exists." });

                if (await db.Users.AnyAsync(u => u.Email == req.Email))
                    return Results.Conflict(new { message = "There is already an account with this email address." });

                var hash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: 11);
                var user = new User { Username = req.Username, Email = req.Email, PasswordHash = hash };
                db.Users.Add(user);
                await db.SaveChangesAsync();

                return Results.Created($"/users/{user.Id}", new { message = "Registration successful." });
            })
            .WithName("SignUp")
            .WithSummary("Create a new user")
            .Produces(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status409Conflict);

            // POST /auth/login
            group.MapPost("/login", async (LoginRequest req, AppDbContext db, IConfiguration cfg) =>
            {
                var user = await db.Users.FirstOrDefaultAsync(u =>
                    u.Username == req.UsernameOrEmail || u.Email == req.UsernameOrEmail);

                if (user is null) return Results.Unauthorized();

                if (!BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
                    return Results.Unauthorized();

                var token = CreateJwt(user, cfg);
                return Results.Ok(new AuthResponse(token, user.Username, user.Email));
            })
            .WithName("Login")
            .WithSummary("Authenticate and issue a JWT")
            .Produces<AuthResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized);

            // POST /auth/upa
            group.MapPost("/upa", async (UnityLoginRequest req, AppDbContext db, IConfiguration cfg, UpaTokenValidator upa) =>
            {
                if (string.IsNullOrWhiteSpace(req.IdToken))
                    return Results.BadRequest(new { message = "idToken zorunlu." });

                var principal = await upa.ValidateAsync(req.IdToken);
                if (principal is null) return Results.Unauthorized();

                var sub = principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
                          ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(sub)) return Results.Unauthorized();

                var email = principal.FindFirstValue(JwtRegisteredClaimNames.Email)
                            ?? principal.FindFirstValue(ClaimTypes.Email);

                const string provider = nameof(ExternalProviders.Unity);
                var ext = await db.ExternalLogins
                    .Include(x => x.User)
                    .FirstOrDefaultAsync(x => x.Provider == provider && x.ProviderUserId == sub);

                User user;
                if (ext is null)
                {
                    // If there is a user with the same email address, you can ask for a merge here (optional).
                    
                    var usernameBase = !string.IsNullOrEmpty(email) ? email.Split('@')[0] : $"up_{Guid.NewGuid().ToString()[..8]}";
                    var username = await NextAvailableUsername(db, usernameBase);

                    user = new User
                    {
                        Username = username,
                        Email = string.IsNullOrEmpty(email) ? $"{username}@no-email.local" : email,
                        PasswordHash = "EXTERNAL_LOGIN" // no pass
                    };
                    db.Users.Add(user);
                    await db.SaveChangesAsync();

                    ext = new ExternalLogin
                    {
                        Provider = provider,
                        ProviderUserId = sub,
                        Email = email,
                        UserId = user.Id,
                        CreatedAt = DateTime.UtcNow,
                        LastUsedAt = DateTime.UtcNow
                    };
                    db.ExternalLogins.Add(ext);
                    await db.SaveChangesAsync();
                }
                else
                {
                    user = ext.User;
                    ext.LastUsedAt = DateTime.UtcNow;
                    if (!string.IsNullOrEmpty(email) && ext.Email != email)
                        ext.Email = email;
                    await db.SaveChangesAsync();
                }

                var token = CreateJwt(user, cfg);

                return Results.Ok(new AuthResponse(token, user.Username, user.Email));

            })
            .WithName("UnityPlayerAccountsLogin")
            .WithSummary("UPA/UGS token ile giriş -> ExternalLogin + app JWT")
            .Produces<AuthResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status400BadRequest);

            return group;
        }
        static async Task<string> NextAvailableUsername(AppDbContext db, string baseName)
        {
            var name = baseName;
            var i = 1;
            while (await db.Users.AnyAsync(u => u.Username == name))
            {
                name = $"{baseName}{i}";
                i++;
            }
            return name;
        }
        private static string CreateJwt(User user, IConfiguration cfg)
        {
            var issuer = cfg["Jwt:Issuer"];
            var audience = cfg["Jwt:Audience"];
            var key = cfg["Jwt:Key"]!;
            var expires = DateTime.UtcNow.AddMinutes(int.Parse(cfg["Jwt:ExpiresMinutes"] ?? "60"));

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Name, user.Username), // user.Identity.Name dolsun
            new Claim(JwtRegisteredClaimNames.Email, user.Email)
        };

            var creds = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}