using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotnetAuth.Api.Contracts;
using DotnetAuth.Api.Data;
using DotnetAuth.Api.Models;
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

            return group;
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