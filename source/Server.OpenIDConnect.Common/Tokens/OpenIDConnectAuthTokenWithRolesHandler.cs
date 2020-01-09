using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens
{
    public abstract class OpenIDConnectAuthTokenWithRolesHandler<TStore, TRetriever, TDiscoverer> : OpenIDConnectAuthTokenHandler<TStore, TRetriever, TDiscoverer>
        where TStore : IOpenIDConnectConfigurationWithRoleStore
        where TRetriever : IKeyRetriever
        where TDiscoverer : IIdentityProviderConfigDiscoverer
    {
        protected OpenIDConnectAuthTokenWithRolesHandler(ISystemLog log, TStore configurationStore, TDiscoverer identityProviderConfigDiscoverer, TRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }

        protected override void SetIssuerSpecificTokenValidationParameters(TokenValidationParameters validationParameters)
        {
            if (!string.IsNullOrWhiteSpace(ConfigurationStore.GetRoleClaimType()))
                validationParameters.RoleClaimType = ConfigurationStore.GetRoleClaimType();
        }

        protected override string[] GetProviderGroupIds(ClaimsPrincipal principal)
        {
            var roleClaimType = ConfigurationStore.GetRoleClaimType();

            if (string.IsNullOrWhiteSpace(roleClaimType))
                return new string[0];

            // the groups Ids consist of external Role and Group identifiers. We always load ClaimTypes.Role claims
            // as external identifiers, and then also based on a custom claim specified by the provider.
            var groups = principal.FindAll(ClaimTypes.Role)
                .Concat(principal.FindAll(roleClaimType))
                .Select(c => c.Value).ToArray();

            return groups;
        }
    }
}