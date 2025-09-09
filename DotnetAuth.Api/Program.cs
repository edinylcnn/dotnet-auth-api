using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using DotnetAuth.Api.Contracts;
using DotnetAuth.Api.Data;
using DotnetAuth.Api.Models;

var builder = WebApplication.CreateBuilder(args);

// EF Core + MySQL
builder.Services.AddDbContext<AppDbContext>(opt =>
{
    var cs = builder.Configuration.GetConnectionString("Default")!;
    opt.UseMySql(cs, ServerVersion.AutoDetect(cs));
});

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// CORS
builder.Services.AddCors(opt =>
{
    opt.AddDefaultPolicy(p => p.AllowAnyOrigin()
                               .AllowAnyHeader()
                               .AllowAnyMethod());
});

// JWT
var jwtKey = builder.Configuration["Jwt:Key"]!;
var keyBytes = Encoding.UTF8.GetBytes(jwtKey);

builder.Services.AddAuthentication()
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateLifetime = true
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

// open later
// app.UseHttpsRedirection();

app.UseCors();

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "API up");

app.MapGet("/datetime", () =>
{
    return DateTime.UtcNow;
});

// username control
app.MapGet("/auth/check-username", async (string username, AppDbContext db) =>
{
    var exists = await db.Users.AnyAsync(u => u.Username == username);
    return Results.Ok(new ExistsResponse(exists));
});

// email control
app.MapGet("/auth/check-email", async (string email, AppDbContext db) =>
{
    var exists = await db.Users.AnyAsync(u => u.Email == email);
    return Results.Ok(new ExistsResponse(exists));
});

// signup
app.MapPost("/auth/signup", async (SignUpRequest req, AppDbContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Username == req.Username))
        return Results.Conflict(new { message = "Bu kullanıcı adı zaten mevcut." });

    if (await db.Users.AnyAsync(u => u.Email == req.Email))
        return Results.Conflict(new { message = "Bu e-posta adresiyle zaten bir hesap var." });

    var hash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: 11);
    var user = new User { Username = req.Username, Email = req.Email, PasswordHash = hash };
    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Created($"/users/{user.Id}", new { message = "Kayıt başarılı." });
});

// login
app.MapPost("/auth/login", async (LoginRequest req, AppDbContext db, IConfiguration cfg) =>
{
    var user = await db.Users
        .FirstOrDefaultAsync(u => u.Username == req.UsernameOrEmail || u.Email == req.UsernameOrEmail);

    if (user is null) return Results.Unauthorized();

    if (!BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
        return Results.Unauthorized();

    var token = CreateJwt(user, cfg);
    return Results.Ok(new AuthResponse(token, user.Username, user.Email));
});

//token login
app.MapGet("/users/me", (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name;
    var email = user.FindFirst(ClaimTypes.Email)?.Value;
    return Results.Ok(new { username, email });
})
.RequireAuthorization();

app.Run();

static string CreateJwt(User user, IConfiguration cfg)
{
    var issuer = cfg["Jwt:Issuer"];
    var audience = cfg["Jwt:Audience"];
    var key = cfg["Jwt:Key"]!;
    var expires = DateTime.UtcNow.AddMinutes(int.Parse(cfg["Jwt:ExpiresMinutes"] ?? "60"));

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
        new Claim(ClaimTypes.Name, user.Username),
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
