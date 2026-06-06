using DotNet.AuthBase.Api.Auth.DTOs;

namespace DotNet.AuthBase.Api.Auth.Contracts;

public interface IAuthService
{
    Task<AuthResponse?> LoginAsync(LoginRequest request);
    Task<bool> RegisterAsync(RegisterRequest request);
    Task<AuthResponse?> RefreshTokenAsync(RefreshTokenRequest request);
    Task LogoutAsync(LogoutRequest request);
    Task<CurrentUserResponse?> GetCurrentUserAsync(Guid userId);
}