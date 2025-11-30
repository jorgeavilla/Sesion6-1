using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Prometheus;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// --- Swagger ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Practica 6 - JWT + Roles",
        Version = "v1"
    });

    // Config para que Swagger permita enviar el JWT
    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "Escribe: Bearer {tu token JWT}",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    };

    options.AddSecurityDefinition("Bearer", securityScheme);

    var securityRequirement = new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    };

    options.AddSecurityRequirement(securityRequirement);
});

// --- HealthChecks básicos ---
builder.Services.AddHealthChecks();

// 1) Auth JWT
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!);

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["Jwt:Issuer"],
            ValidAudience = configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ClockSkew = TimeSpan.Zero
        };
    });

// 2) Roles / Policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
    {
        policy.RequireRole("Admin");
    });
});

// 3) Dependencias para usuarios en memoria
builder.Services.AddSingleton<PasswordHasher<User>>();
builder.Services.AddSingleton<UserStore>();

var app = builder.Build();

// --- Swagger UI ---
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// --- Prometheus metrics ---
app.UseHttpMetrics();   // mide las requests HTTP

app.UseAuthentication();
app.UseAuthorization();

// 4) Endpoint de login: POST /auth/login
app.MapPost("/auth/login",
    (LoginRequest request,
     UserStore userStore,
     PasswordHasher<User> passwordHasher,
     IConfiguration config) =>
    {
        var user = userStore.FindByUsername(request.Username);

        if (user is null)
            return Results.Unauthorized();

        var result = passwordHasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.Password
        );

        if (result == PasswordVerificationResult.Failed)
            return Results.Unauthorized();

        var token = JwtTokenService.GenerateJwtToken(user, config);

        return Results.Ok(new LoginResponse(token));
    })
    .WithTags("Auth");

// 5) Endpoint público
app.MapGet("/public/ping", () => Results.Ok("pong"))
    .AllowAnonymous()
    .WithTags("Public");

// 6) Endpoint protegido (cualquier usuario autenticado)
app.MapGet("/api/me", (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name;
    var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value);

    return Results.Ok(new
    {
        username,
        roles
    });
})
    .RequireAuthorization()
    .WithTags("User");

// 7) Endpoint protegido por rol Admin
app.MapGet("/admin/secret", () =>
{
    return Results.Ok("Sólo admins pueden ver esto.");
})
    .RequireAuthorization("AdminOnly")
    .WithTags("Admin");

// 8) Endpoint para ver entorno
app.MapGet("/environment", (IHostEnvironment env, IConfiguration cfg) =>
{
    return Results.Ok(new
    {
        Environment = env.EnvironmentName,
        ApplicationName = env.ApplicationName,
        MachineName = Environment.MachineName
    });
})
    .AllowAnonymous()
    .WithTags("Info");

// 9) HealthChecks
app.MapHealthChecks("/health")
   .WithTags("Health");

// 10) Endpoint de métricas de Prometheus
app.MapMetrics("/metrics")
   .WithTags("Metrics");

app.Run();


// ======= TIPOS Y SERVICIOS (DESPUÉS de app.Run) =======

record LoginRequest(string Username, string Password);
record LoginResponse(string AccessToken);

public record User(Guid Id, string Username, string PasswordHash, string[] Roles);

public class UserStore
{
    private readonly List<User> _users = new();
    private readonly PasswordHasher<User> _passwordHasher;

    public UserStore(PasswordHasher<User> passwordHasher)
    {
        _passwordHasher = passwordHasher;
        Seed();
    }

    private void Seed()
    {
        // usuario admin
        AddUser("admin", "Admin123!", new[] { "Admin", "User" });

        // usuario normal
        AddUser("juan", "User123!", new[] { "User" });
    }

    private void AddUser(string username, string plainPassword, string[] roles)
    {
        var user = new User(Guid.NewGuid(), username, "", roles);
        var hash = _passwordHasher.HashPassword(user, plainPassword);

        _users.Add(user with { PasswordHash = hash });
    }

    public User? FindByUsername(string username) =>
        _users.SingleOrDefault(u =>
            string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
}

public static class JwtTokenService
{
    public static string GenerateJwtToken(User user, IConfiguration configuration)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!)
        );

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username)
        };

        foreach (var role in user.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var token = new JwtSecurityToken(
            issuer: configuration["Jwt:Issuer"],
            audience: configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
