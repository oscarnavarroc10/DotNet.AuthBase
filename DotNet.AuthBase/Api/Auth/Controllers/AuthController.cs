using System.Security.Claims;
using DotNet.AuthBase.Api.Auth.Constants;
using DotNet.AuthBase.Api.Auth.DTOs;
using DotNet.AuthBase.Api.Auth.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;

namespace DotNet.AuthBase.Api.Auth.Controllers;

/// <summary>
/// ES: Controlador para gestionar operaciones de autenticación (login, registro, logout, etc).
/// EN: Controller for managing authentication operations (login, registration, logout, etc).
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    /// <summary>
    /// ES: Constructor que recibe las inyecciones de dependencia.
    /// EN: Constructor that receives dependency injections.
    /// </summary>
    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// ES: Endpoint de test que valida acceso solo para administradores.
    /// EN: Test endpoint that validates access only for administrators.
    /// </summary>
    /// <remarks>
    /// ES: Requiere estar autenticado con rol de administrador.
    /// EN: Requires to be authenticated with administrator role.
    /// </remarks>
    [HttpGet("admin-only")]
    [Authorize(Roles = RoleNames.Admin)]
    [ProduceResponseType(StatusCodes.Status200OK)]
    [ProduceResponseType(StatusCodes.Status403Forbidden)]
    [ProduceResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult AdminOnly()
    {
        try
        {
            _logger.LogInformation("Admin-only endpoint accessed successfully");

            return Ok(new { message = "You are an Admin." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in admin-only endpoint");
            return StatusCode(StatusCodes.Status500InternalServerError, 
                new { message = "An error occurred" });
        }
    }

    /// <summary>
    /// ES: Registra un nuevo usuario en el sistema.
    /// EN: Registers a new user in the system.
    /// </summary>
    /// <remarks>
    /// ES: Endpoint público que permite registrar un nuevo usuario con email y contraseña.
    /// Validación automática de FluentValidation.
    /// EN: Public endpoint that allows registering a new user with email and password.
    /// Automatic validation with FluentValidation.
    /// </remarks>
    /// <param name="request">ES: Datos de registro del usuario. EN: User registration data.</param>
    [HttpPost("register")]
    [AllowAnonymous]
    [ProduceResponseType(StatusCodes.Status200OK)]
    [ProduceResponseType(StatusCodes.Status400BadRequest)]
    [ProduceResponseType(StatusCodes.Status409Conflict)]
    [ProduceResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Register attempt with invalid model state");
            return BadRequest(ModelState);
        }

        try
        {
            var registered = await _authService.RegisterAsync(request);

            if (!registered)
            {
                _logger.LogWarning("Registration failed: Email already exists - {Email}", request.Email);
                return Conflict(new { message = "Email already exists." });
            }

            _logger.LogInformation("User registered successfully - {Email}", request.Email);

            return Ok(new { message = "User registered successfully." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { message = "An error occurred during registration." });
        }
    }

    /// <summary>
    /// ES: Autentica un usuario y retorna tokens de acceso y actualización.
    /// EN: Authenticates a user and returns access and refresh tokens.
    /// </summary>
    /// <remarks>
    /// ES: Endpoint público que valida credenciales y retorna un token JWT y refresh token.
    /// Ambos tokens se pueden usar posteriormente para acceder a recursos protegidos.
    /// EN: Public endpoint that validates credentials and returns a JWT token and refresh token.
    /// Both tokens can be used later to access protected resources.
    /// </remarks>
    /// <param name="request">ES: Credenciales de login. EN: Login credentials.</param>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProduceResponseType(StatusCodes.Status200OK, Type = typeof(AuthResponse))]
    [ProduceResponseType(StatusCodes.Status401Unauthorized)]
    [ProduceResponseType(StatusCodes.Status400BadRequest)]
    [ProduceResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Login attempt with invalid model state");
            return BadRequest(ModelState);
        }

        try
        {
            var response = await _authService.LoginAsync(request);

            if (response is null)
            {
                _logger.LogWarning("Login failed for email: {Email}", request.Email);
                return Unauthorized(new { message = "Invalid email or password." });
            }

            _logger.LogInformation("User logged in successfully - {Email}", request.Email);

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { message = "An error occurred during login." });
        }
    }

    /// <summary>
    /// ES: Obtiene la información del usuario actualmente autenticado.
    /// EN: Gets the current authenticated user's information.
    /// </summary>
    /// <remarks>
    /// ES: Endpoint protegido que retorna los datos del usuario autenticado incluyendo sus roles.
    /// EN: Protected endpoint that returns the authenticated user's data including their roles.
    /// </remarks>
    [HttpGet("current-user")]
    [Authorize]
    [ProduceResponseType(StatusCodes.Status200OK, Type = typeof(CurrentUserResponse))]
    [ProduceResponseType(StatusCodes.Status401Unauthorized)]
    [ProduceResponseType(StatusCodes.Status404NotFound)]
    [ProduceResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<CurrentUserResponse>> GetCurrentUser()
    {
        try
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim is null || !Guid.TryParse(userIdClaim.Value, out var userId))
            {
                _logger.LogWarning("Current user endpoint: Invalid user ID claim");
                return Unauthorized(new { message = "Invalid user identification." });
            }

            var response = await _authService.GetCurrentUserAsync(userId);

            if (response is null)
            {
                _logger.LogWarning("Current user endpoint: User not found - {UserId}", userId);
                return NotFound(new { message = "User not found." });
            }

            _logger.LogInformation("Current user information retrieved - {UserId}", userId);

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving current user");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { message = "An error occurred while retrieving user information." });
        }
    }

    /// <summary>
    /// ES: Refresca el token de acceso usando un refresh token válido.
    /// EN: Refreshes the access token using a valid refresh token.
    /// </summary>
    /// <remarks>
    /// ES: Endpoint protegido que genera un nuevo access token a partir del refresh token.
    /// El refresh token anterior se revoca automáticamente.
    /// EN: Protected endpoint that generates a new access token from the refresh token.
    /// The previous refresh token is automatically revoked.
    /// </remarks>
    /// <param name="request">ES: Contiene el refresh token válido. EN: Contains the valid refresh token.</param>
    [HttpPost("refresh-token")]
    [Authorize]
    [ProduceResponseType(StatusCodes.Status200OK, Type = typeof(AuthResponse))]
    [ProduceResponseType(StatusCodes.Status401Unauthorized)]
    [ProduceResponseType(StatusCodes.Status400BadRequest)]
    [ProduceResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Refresh token attempt with invalid model state");
            return BadRequest(ModelState);
        }

        try
        {
            var response = await _authService.RefreshTokenAsync(request);

            if (response is null)
            {
                _logger.LogWarning("Refresh token failed: Invalid or expired token");
                return Unauthorized(new { message = "Invalid refresh token." });
            }

            _logger.LogInformation("Token refreshed successfully for user - {UserId}", response.UserId);

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { message = "An error occurred while refreshing the token." });
        }
    }

    /// <summary>
    /// ES: Cierra la sesión del usuario revocando su refresh token.
    /// EN: Logs out the user by revoking their refresh token.
    /// </summary>
    /// <remarks>
    /// ES: Endpoint protegido que invalida el refresh token del usuario,
    /// impidiendo que se generen nuevos access tokens.
    /// EN: Protected endpoint that invalidates the user's refresh token,
    /// preventing new access tokens from being generated.
    /// </remarks>
    /// <param name="request">ES: Contiene el refresh token a revocar. EN: Contains the refresh token to revoke.</param>
    [HttpPost("logout")]
    [Authorize]
    [ProduceResponseType(StatusCodes.Status200OK)]
    [ProduceResponseType(StatusCodes.Status401Unauthorized)]
    [ProduceResponseType(StatusCodes.Status400BadRequest)]
    [ProduceResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Logout attempt with invalid model state");
            return BadRequest(ModelState);
        }

        try
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim is null || !Guid.TryParse(userIdClaim.Value, out var userId))
            {
                _logger.LogWarning("Logout endpoint: Invalid user ID claim");
                return Unauthorized(new { message = "Invalid user identification." });
            }

            await _authService.LogoutAsync(request);

            _logger.LogInformation("User logged out successfully - {UserId}", userId);

            return Ok(new { message = "Logged out successfully." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { message = "An error occurred during logout." });
        }
    }
}
