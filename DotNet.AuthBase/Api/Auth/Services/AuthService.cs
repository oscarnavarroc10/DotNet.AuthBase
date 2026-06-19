using DotNet.AuthBase.Api.Auth.Constants;
using DotNet.AuthBase.Api.Auth.Contracts;
using DotNet.AuthBase.Api.Auth.DTOs;
using DotNet.AuthBase.Api.Auth.Entities;
using DotNet.AuthBase.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DotNet.AuthBase.Api.Auth.Services;

/// <summary>
/// ES: Servicio principal para gestionar operaciones de autenticación y autorización.
/// EN: Main service for managing authentication and authorization operations.
/// </summary>
public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly PasswordService _passwordService;
    private readonly JwtService _jwtService;
    private readonly ILogger<AuthService> _logger;

    /// <summary>
    /// ES: Constructor que recibe las dependencias necesarias para autenticación.
    /// EN: Constructor that receives the necessary dependencies for authentication.
    /// </summary>
    public AuthService(
        ApplicationDbContext dbContext,
        PasswordService passwordService,
        JwtService jwtService,
        ILogger<AuthService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _passwordService = passwordService ?? throw new ArgumentNullException(nameof(passwordService));
        _jwtService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// ES: Autentica un usuario con email y contraseña, retornando tokens.
    /// EN: Authenticates a user with email and password, returning tokens.
    /// </summary>
    /// <param name="request">ES: Credenciales de login. EN: Login credentials.</param>
    /// <returns>ES: Respuesta con tokens si es válido, null si falla. EN: Response with tokens if valid, null if fails.</returns>
    public async Task<AuthResponse?> LoginAsync(LoginRequest request)
    {
        if (request == null)
        {
            _logger.LogWarning("Login attempt with null request");
            return null;
        }

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            _logger.LogWarning("Login attempt with empty email");
            return null;
        }

        try
        {
            var user = await GetUserWithRolesAsync(request.Email);

            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found - {Email}", request.Email);
                return null;
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login failed: User account inactive - {UserId}", user.Id);
                return null;
            }

            if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash))
            {
                _logger.LogWarning("Login failed: Invalid password for user - {Email}", request.Email);
                return null;
            }

            var authResponse = GenerateAuthResponse(user);

            _logger.LogInformation("User logged in successfully - {Email}", request.Email);

            return authResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for email {Email}", request.Email);
            throw;
        }
    }

    /// <summary>
    /// ES: Registra un nuevo usuario en el sistema.
    /// EN: Registers a new user in the system.
    /// </summary>
    /// <param name="request">ES: Datos de registro del nuevo usuario. EN: New user registration data.</param>
    /// <returns>ES: True si el registro fue exitoso, false si el email ya existe. EN: True if registration succeeds, false if email exists.</returns>
    public async Task<bool> RegisterAsync(RegisterRequest request)
    {
        if (request == null)
        {
            _logger.LogWarning("Register attempt with null request");
            return false;
        }

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            _logger.LogWarning("Register attempt with empty email");
            return false;
        }

        try
        {
            var userExists = await _dbContext.Users
                .AnyAsync(x => x.Email == request.Email);

            if (userExists)
            {
                _logger.LogWarning("Registration failed: Email already exists - {Email}", request.Email);
                return false;
            }

            var user = CreateNewUser(request);
            var userRole = await GetUserRoleAsync();

            if (userRole == null)
            {
                _logger.LogError("Cannot find User role in database");
                return false;
            }

            _dbContext.Users.Add(user);
            _dbContext.UserRoles.Add(new UserRole
            {
                UserId = user.Id,
                RoleId = userRole.Id
            });

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("User registered successfully - {Email}", request.Email);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration for email {Email}", request.Email);
            throw;
        }
    }

    /// <summary>
    /// ES: Refresca el token de acceso usando un refresh token válido.
    /// EN: Refreshes the access token using a valid refresh token.
    /// </summary>
    /// <param name="request">ES: Contiene el refresh token. EN: Contains the refresh token.</param>
    /// <returns>ES: Nuevos tokens si son válidos, null si falla. EN: New tokens if valid, null if fails.</returns>
    public async Task<AuthResponse?> RefreshTokenAsync(RefreshTokenRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            _logger.LogWarning("Refresh token attempt with invalid request");
            return null;
        }

        try
        {
            var storedRefreshToken = await GetValidRefreshTokenAsync(request.RefreshToken);

            if (storedRefreshToken == null)
            {
                _logger.LogWarning("Refresh token attempt: Invalid or expired token");
                return null;
            }

            var user = storedRefreshToken.User;

            if (user == null || !user.IsActive)
            {
                _logger.LogWarning("Refresh token attempt: User not found or inactive");
                return null;
            }

            // ES: Revocar el refresh token anterior
            // EN: Revoke the old refresh token
            storedRefreshToken.IsRevoked = true;

            var newRefreshToken = CreateNewRefreshToken(user.Id);
            _dbContext.RefreshTokens.Add(newRefreshToken);

            await _dbContext.SaveChangesAsync();

            var authResponse = GenerateAuthResponse(user, newRefreshToken.Token);

            _logger.LogInformation("Token refreshed successfully for user - {UserId}", user.Id);

            return authResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            throw;
        }
    }

    /// <summary>
    /// ES: Cierra la sesión del usuario revocando su refresh token.
    /// EN: Logs out the user by revoking their refresh token.
    /// </summary>
    /// <param name="request">ES: Contiene el refresh token a revocar. EN: Contains the refresh token to revoke.</param>
    /// <returns>ES: Task completado. EN: Completed task.</returns>
    public async Task LogoutAsync(LogoutRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            _logger.LogWarning("Logout attempt with invalid request");
            return;
        }

        try
        {
            var storedRefreshToken = await _dbContext.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

            if (storedRefreshToken == null)
            {
                _logger.LogWarning("Logout attempt: Refresh token not found");
                return;
            }

            storedRefreshToken.IsRevoked = true;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("User logged out successfully - {UserId}", storedRefreshToken.UserId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            throw;
        }
    }

    /// <summary>
    /// ES: Obtiene la información del usuario actual autenticado.
    /// EN: Gets the current authenticated user's information.
    /// </summary>
    /// <param name="userId">ES: ID del usuario. EN: User ID.</param>
    /// <returns>ES: Información del usuario si existe, null si no. EN: User information if exists, null otherwise.</returns>
    public async Task<CurrentUserResponse?> GetCurrentUserAsync(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            _logger.LogWarning("GetCurrentUser attempt with empty user ID");
            return null;
        }

        try
        {
            var user = await GetUserWithRolesAsync(userId);

            if (user == null)
            {
                _logger.LogWarning("User not found - {UserId}", userId);
                return null;
            }

            var response = MapToCurrentUserResponse(user);

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user {UserId}", userId);
            throw;
        }
    }

    // ============= MÉTODOS PRIVADOS =============

    /// <summary>
    /// ES: Obtiene un usuario con sus roles cargados desde la base de datos.
    /// EN: Gets a user with their roles loaded from the database.
    /// </summary>
    private async Task<User?> GetUserWithRolesAsync(string email)
    {
        return await _dbContext.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Email == email);
    }

    /// <summary>
    /// ES: Obtiene un usuario con sus roles cargados por ID.
    /// EN: Gets a user with their roles loaded by ID.
    /// </summary>
    private async Task<User?> GetUserWithRolesAsync(Guid userId)
    {
        return await _dbContext.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Id == userId);
    }

    /// <summary>
    /// ES: Obtiene el refresh token válido de la base de datos.
    /// EN: Gets the valid refresh token from the database.
    /// </summary>
    private async Task<RefreshToken?> GetValidRefreshTokenAsync(string token)
    {
        var storedRefreshToken = await _dbContext.RefreshTokens
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.Token == token);

        if (storedRefreshToken == null)
            return null;

        // ES: Validar que no esté revocado
        // EN: Validate it's not revoked
        if (storedRefreshToken.IsRevoked)
            return null;

        // ES: Validar que no esté expirado
        // EN: Validate it's not expired
        if (storedRefreshToken.ExpiresAt <= DateTime.UtcNow)
            return null;

        return storedRefreshToken;
    }

    /// <summary>
    /// ES: Obtiene el rol de usuario por defecto del sistema.
    /// EN: Gets the default user role from the system.
    /// </summary>
    private async Task<Role?> GetUserRoleAsync()
    {
        return await _dbContext.Roles
            .FirstAsync(x => x.Name == RoleNames.User);
    }

    /// <summary>
    /// ES: Crea un nuevo usuario a partir de la solicitud de registro.
    /// EN: Creates a new user from the registration request.
    /// </summary>
    private User CreateNewUser(RegisterRequest request)
    {
        return new User
        {
            Id = Guid.NewGuid(),
            FirstName = request.FirstName.Trim(),
            LastName = request.LastName.Trim(),
            Email = request.Email.ToLowerInvariant().Trim(),
            PasswordHash = _passwordService.HashPassword(request.Password),
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// ES: Crea un nuevo refresh token para el usuario.
    /// EN: Creates a new refresh token for the user.
    /// </summary>
    private RefreshToken CreateNewRefreshToken(Guid userId)
    {
        return new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = _jwtService.GenerateRefreshToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            IsRevoked = false,
            UserId = userId
        };
    }

    /// <summary>
    /// ES: Genera la respuesta de autenticación con tokens.
    /// EN: Generates the authentication response with tokens.
    /// </summary>
    private AuthResponse GenerateAuthResponse(User user, string? customRefreshToken = null)
    {
        var accessToken = _jwtService.GenerateToken(user);
        var refreshToken = customRefreshToken ?? _jwtService.GenerateRefreshToken();

        // ES: Si no se proporcionó un refresh token personalizado, guardarlo en BD
        // EN: If no custom refresh token was provided, save it to DB
        if (customRefreshToken == null)
        {
            var refreshTokenEntity = CreateNewRefreshToken(user.Id);
            _dbContext.RefreshTokens.Add(refreshTokenEntity);
            _ = _dbContext.SaveChangesAsync();
        }

        return new AuthResponse
        {
            UserId = user.Id,
            Email = user.Email,
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    /// <summary>
    /// ES: Mapea un usuario a la respuesta de usuario actual.
    /// EN: Maps a user to the current user response.
    /// </summary>
    private CurrentUserResponse MapToCurrentUserResponse(User user)
    {
        return new CurrentUserResponse
        {
            UserId = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt,
            Roles = user.UserRoles?
                .Select(x => x.Role?.Name ?? RoleNames.User)
                .ToList() ?? new List<string>()
        };
    }
}
