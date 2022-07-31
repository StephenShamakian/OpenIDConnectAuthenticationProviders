using System;
using System.Linq;
using System.Security.Claims;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public class PrincipalToUserResourceMapper : IPrincipalToUserResourceMapper
    {
        public UserResource MapToUserResource(ClaimsPrincipal principal)
        {
            var userResource = new UserResource
            {
                ExternalId = GetExternalId(principal),
                Username = GetUsername(principal),
                EmailAddress = GetEmailAddress(principal),
                DisplayName = GetDisplayName(principal)
            };

            // Assert we have the bare essentials
            if (string.IsNullOrWhiteSpace(userResource.ExternalId))
                throw new Exception($"The ExternalId resolved by {GetType().Name} was empty but is required. Username: '{userResource.Username}' Email: '{userResource.EmailAddress}' Display Name: '{userResource.DisplayName}'");
            if (string.IsNullOrWhiteSpace(userResource.Username))
                throw new Exception($"The Username resolved by {GetType().Name} was empty but is required. ExternalId: '{userResource.ExternalId}' Email: '{userResource.EmailAddress}' Display Name: '{userResource.DisplayName}'");

            return userResource;
        }

        protected virtual string? GetExternalId(ClaimsPrincipal principal)
        {
            return GetClaimValue(principal, ClaimTypes.NameIdentifier);
        }

        protected virtual string? GetUsername(ClaimsPrincipal principal)
        {
            return GetClaimValue(principal, ClaimTypes.Email) ?? GetClaimValue(principal, ClaimTypes.NameIdentifier);
        }

        protected virtual string? GetEmailAddress(ClaimsPrincipal principal)
        {
            return GetClaimValue(principal, ClaimTypes.Email);
        }

        protected virtual string? GetDisplayName(ClaimsPrincipal principal)
        {
            return principal.Identity?.Name;
        }

        protected string? GetClaimValue(ClaimsPrincipal principal, string type)
        {
            // NOTE: The System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler maps OIDC claims from short to long names.
            // See System.IdentityModel.Tokens.Jwt.ClaimTypeMapping for more details.
            return principal.Claims.FirstOrDefault(c => string.Equals(c.Type, type, StringComparison.OrdinalIgnoreCase))?.Value;
        }
    }
}