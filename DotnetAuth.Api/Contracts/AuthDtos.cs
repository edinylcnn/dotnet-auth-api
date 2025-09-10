namespace DotnetAuth.Api.Contracts
{

    public record SignUpRequest(string Username, string Email, string Password);
    public record LoginRequest(string UsernameOrEmail, string Password);
    public record AuthResponse(string Token, string Username, string Email);
    public record ExistsResponse(bool Exists, string Message);
}