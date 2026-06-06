using System.Security.Claims;
using DotNet.AuthBase.Api.Auth.Constants;
using DotNet.AuthBase.Api.Auth.DTOs;
using DotNet.AuthBase.Api.Auth.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotNet.AuthBase.Api.Auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }
    
    /// <summary>
    /// Test API
    /// </summary>
    /// <returns></returns>
    [Authorize(Roles = RoleNames.Admin)]
    [HttpGet("admin-only")]
    public IActionResult AdminOnly()
    {
        return Ok(new
        {
            Message = "You are an Admin."
        });
    }

    //[Authorize(Roles = RoleNames.Admin)]
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var registered = await _authService.RegisterAsync(request);

        if (!registered)
        {
            return BadRequest("Email already exists.");
        }

        return Ok(new
        {
            Message = "User registered successfully."
        });
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login(LoginRequest request)
    {
        var response = await _authService.LoginAsync(request);

        if (response is null)
        {
            return Unauthorized("Invalid email or password.");
        }

        return Ok(response);
    }
    
    [Authorize]
    [HttpGet("current-user")]
    public async Task<ActionResult<CurrentUserResponse>> CurrentUser()
    {
        var userIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Unauthorized();
        }

        var response = await _authService.GetCurrentUserAsync(userId);

        if (response is null)
        {
            return NotFound("User not found.");
        }

        return Ok(response);
    }
    
    [HttpPost("refresh-token")]
    public async Task<ActionResult<AuthResponse>> RefreshToken(RefreshTokenRequest request)
    {
        var response = await _authService.RefreshTokenAsync(request);

        if (response is null)
        {
            return Unauthorized(new
            {
                Message = "Invalid refresh token."
            });
        }

        return Ok(response);
    }
    
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(LogoutRequest request)
    {
        await _authService.LogoutAsync(request);

        return Ok(new
        {
            Message = "Logged out successfully."
        });
    }
}