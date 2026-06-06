namespace DotNet.AuthBase.Api.Auth.DTOs;

public class LogoutRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}