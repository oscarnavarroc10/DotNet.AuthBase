using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DotNet.AuthBase.Api.Auth.Constants;
using DotNet.AuthBase.Api.Auth.Entities;
using DotNet.AuthBase.Api.Configurations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace DotNet.AuthBase.Api.Auth.Services;

/// <summary>
/// ES: Servicio responsable de generar y validar tokens JWT y refresh tokens.
/// EN: Service responsible for generating and validating JWT tokens and refresh tokens.
/// </summary>
public class JwtService
{
    private readonly JwtOptions _jwtOptions;
    private readonly ILogger<JwtService> _logger;

    /// <summary>
    /// ES: Constructor que recibe las opciones JWT y un logger.
    /// EN: Constructor that receives JWT options and a logger.
    /// </summary>
    public JwtService(IOptions<JwtOptions> jwtOptions, ILogger<JwtService> logger)
    {
        _jwtOptions = jwtOptions.Value ?? throw new ArgumentNullException(nameof(jwtOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// ES: Genera un token JWT para el usuario especificado.
    /// EN: Generates a JWT token for the specified user.
    /// </summary>
    /// <param name="user">ES: Usuario para el cual generar el token. EN: User to generate token for.</param>
    /// <returns>ES: Token JWT codificado. EN: Encoded JWT token.</returns>
    /// <exception cref="ArgumentNullException">ES: Se lanza cuando el usuario es nulo. EN: Thrown when user is null.</exception>
    public string GenerateToken(User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        try
        {
            var claims = BuildUserClaims(user);
            var signingCredentials = GetSigningCredentials();
            var token = CreateSecurityToken(claims, signingCredentials);
            var tokenHandler = new JwtSecurityTokenHandler();
            var encodedToken = tokenHandler.WriteToken(token);

            _logger.LogInformation("JWT token generated successfully for user {UserId}", user.Id);

            return encodedToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating JWT token for user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// ES: Genera un token de actualización seguro aleatorio.
    /// EN: Generates a secure random refresh token.
    /// </summary>
    /// <returns>ES: Refresh token codificado en Base64. EN: Refresh token encoded in Base64.</returns>
    public string GenerateRefreshToken()
    {
        try
        {
            var randomBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(randomBytes);

            _logger.LogDebug("Refresh token generated successfully");

            return refreshToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating refresh token");
            throw;
        }
    }

    /// <summary>
    /// ES: Construye la lista de claims para el usuario incluyendo rol.
    /// EN: Builds the list of claims for the user including role.
    /// </summary>
    private List<Claim> BuildUserClaims(User user)
    {
        var claims = new List<Claim>
        {
            // ES: Identificadores únicos del usuario
            // EN: User unique identifiers
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            
            // ES: Información adicional del usuario
            // EN: Additional user information
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // ES: Agregar roles como claims
        // EN: Add roles as claims
        if (user.UserRoles != null && user.UserRoles.Any())
        {
            foreach (var userRole in user.UserRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole.Role?.Name ?? RoleNames.User));
            }
        }

        return claims;
    }

    /// <summary>
    /// ES: Obtiene las credenciales de firma para firmar el token.
    /// EN: Gets the signing credentials to sign the token.
    /// </summary>
    private SigningCredentials GetSigningCredentials()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SecretKey));
        return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    /// <summary>
    /// ES: Crea el token de seguridad JWT con los parámetros especificados.
    /// EN: Creates the JWT security token with the specified parameters.
    /// </summary>
    private JwtSecurityToken CreateSecurityToken(
        List<Claim> claims,
        SigningCredentials signingCredentials)
    {
        var token = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtOptions.ExpirationMinutes),
            signingCredentials: signingCredentials);

        return token;
    }
}
