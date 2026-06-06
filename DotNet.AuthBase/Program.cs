using System.Text;
using DotNet.AuthBase.Api.Auth.Contracts;
using DotNet.AuthBase.Api.Auth.Services;
using DotNet.AuthBase.Api.Auth.Validators;
using DotNet.AuthBase.Api.Common.Middleware;
using DotNet.AuthBase.Api.Configurations;
using DotNet.AuthBase.Api.Data;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ES: Agrega soporte para Controllers.
// EN: Adds support for Controllers.
builder.Services.AddControllers();

// ES: Registrar Interfaz con su implementación 
// EN: Register Interface and Implementation class
builder.Services.AddScoped<IAuthService, AuthService>();

// ES: Validación de reglas 
// EN: Rules validation
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();

// ES: Agrega OpenAPI para documentación de endpoints.
// EN: Adds OpenAPI support for endpoint documentation.
//builder.Services.AddOpenApi();

// ES: Registra el DbContext usando SQL Server.
// EN: Registers the DbContext using SQL Server.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

// ES: Lee la configuración JWT desde appsettings.json.
// EN: Reads JWT configuration from appsettings.json.
builder.Services.Configure<JwtOptions>(
    builder.Configuration.GetSection(JwtOptions.SectionName));

// ES: Registra servicios propios de autenticación.
// EN: Registers custom authentication services.
builder.Services.AddScoped<PasswordService>();
builder.Services.AddScoped<JwtService>();

var jwtOptions = builder.Configuration
    .GetSection(JwtOptions.SectionName)
    .Get<JwtOptions>()!;

// ES: Configura la autenticación usando JWT Bearer.
// EN: Configures authentication using JWT Bearer.
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        // ES: Define cómo se validará el token JWT recibido.
        // EN: Defines how the received JWT token will be validated.
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // ES: Valida que el emisor del token sea correcto.
            // EN: Validates that the token issuer is correct.
            ValidateIssuer = true,

            // ES: Valida que la audiencia del token sea correcta.
            // EN: Validates that the token audience is correct.
            ValidateAudience = true,

            // ES: Valida que el token no esté expirado.
            // EN: Validates that the token has not expired.
            ValidateLifetime = true,

            // ES: Valida que la firma del token sea correcta.
            // EN: Validates that the token signature is correct.
            ValidateIssuerSigningKey = true,

            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,

            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtOptions.SecretKey))
        };
    });

// ES: Agrega soporte para autorización con [Authorize].
// EN: Adds support for authorization using [Authorize].
builder.Services.AddAuthorization();

// ES: Agrega Swagger
// EN: Add Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Ingresa tu JWT. Ejemplo: Bearer eyJhbGciOi..."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
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
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // ES: Expone el documento OpenAPI en ambiente de desarrollo.
    // EN: Exposes the OpenAPI document in development environment.
    //app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ES: Redirige HTTP a HTTPS.
// EN: Redirects HTTP to HTTPS.
//app.UseHttpsRedirection();

// ES: Catch de errores de servidor
// EN: Try Catch Server error
app.UseMiddleware<ExceptionMiddleware>();

// ES: Primero valida quién es el usuario.
// EN: First validates who the user is.
app.UseAuthentication();

// ES: Luego valida si tiene permiso para acceder.
// EN: Then validates whether the user has permission to access.
app.UseAuthorization();

// ES: Mapea los controllers como /api/auth/login.
// EN: Maps controllers like /api/auth/login.
app.MapControllers();

app.Run();