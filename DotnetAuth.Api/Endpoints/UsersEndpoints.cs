using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace DotnetAuth.Api.Endpoints
{
    public static class UsersEndpoints
    {
        public static RouteGroupBuilder MapUserEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/users")
                          .WithTags("Users");

        // GET /users/me
        group.MapGet("/me", (ClaimsPrincipal user) =>
        {
            var username = user.Identity?.Name;
            var email = user.FindFirst(ClaimTypes.Email)?.Value;
            return Results.Ok(new { username, email });
        })
        .RequireAuthorization()
        .WithName("Me")
        .WithSummary("Get the current authenticated user")
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized);

        return group;
    }
    }
}