using DotNet.AuthBase.Api.Auth.Constants;
using DotNet.AuthBase.Api.Auth.Contracts;
using DotNet.AuthBase.Api.Auth.DTOs;
using DotNet.AuthBase.Api.Auth.Entities;
using DotNet.AuthBase.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace DotNet.AuthBase.Api.Auth.Services;

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly PasswordService _passwordService;
    private readonly JwtService _jwtService;

    public AuthService(
        ApplicationDbContext dbContext,
        PasswordService passwordService,
        JwtService jwtService)
    {
        _dbContext = dbContext;
        _passwordService = passwordService;
        _jwtService = jwtService;
    }

    public async Task<AuthResponse?> LoginAsync(LoginRequest request)
    {
        var user = await _dbContext.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Email == request.Email);

        if (user is null)
        {
            return null;
        }

        var isValidPassword = _passwordService.VerifyPassword(
            request.Password,
            user.PasswordHash);

        if (!isValidPassword)
        {
            return null;
        }

        var accessToken = _jwtService.GenerateToken(user);

        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = _jwtService.GenerateRefreshToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            IsRevoked = false,
            UserId = user.Id
        };

        _dbContext.RefreshTokens.Add(refreshToken);

        await _dbContext.SaveChangesAsync();

        return new AuthResponse
        {
            UserId = user.Id,
            Email = user.Email,
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token
        };
    }
    
    public async Task<bool> RegisterAsync(RegisterRequest request)
    {
        var userExists = await _dbContext.Users
            .AnyAsync(x => x.Email == request.Email);

        if (userExists)
        {
            return false;
        }

        var user = new User
        {
            Id = Guid.NewGuid(),
            FirstName = request.FirstName,
            LastName = request.LastName,
            Email = request.Email,
            PasswordHash = _passwordService.HashPassword(request.Password)
        };

        var userRole = await _dbContext.Roles
            .FirstAsync(x => x.Name == RoleNames.User);

        _dbContext.Users.Add(user);

        _dbContext.UserRoles.Add(new UserRole
        {
            UserId = user.Id,
            RoleId = userRole.Id
        });

        await _dbContext.SaveChangesAsync();

        return true;
    }
    
    public async Task<AuthResponse?> RefreshTokenAsync(RefreshTokenRequest request)
    {
        var storedRefreshToken = await _dbContext.RefreshTokens
            .Include(x => x.User)
            .ThenInclude(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

        if (storedRefreshToken is null)
        {
            return null;
        }

        if (storedRefreshToken.IsRevoked)
        {
            return null;
        }

        if (storedRefreshToken.ExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        var user = storedRefreshToken.User;

        storedRefreshToken.IsRevoked = true;

        var newRefreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = _jwtService.GenerateRefreshToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            IsRevoked = false,
            UserId = user.Id
        };

        _dbContext.RefreshTokens.Add(newRefreshToken);

        await _dbContext.SaveChangesAsync();

        var newAccessToken = _jwtService.GenerateToken(user);

        return new AuthResponse
        {
            UserId = user.Id,
            Email = user.Email,
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken.Token
        };
    }
    
    public async Task LogoutAsync(LogoutRequest request)
    {
        var storedRefreshToken = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

        if (storedRefreshToken is null)
        {
            return;
        }

        storedRefreshToken.IsRevoked = true;

        await _dbContext.SaveChangesAsync();
    }
    
    public async Task<CurrentUserResponse?> GetCurrentUserAsync(Guid userId)
    {
        var user = await _dbContext.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Id == userId);

        if (user is null)
        {
            return null;
        }

        return new CurrentUserResponse
        {
            UserId = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt,
            Roles = user.UserRoles
                .Select(x => x.Role.Name)
                .ToList()
        };
    }
}