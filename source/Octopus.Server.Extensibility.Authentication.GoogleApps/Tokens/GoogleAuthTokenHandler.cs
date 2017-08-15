using System.Linq;
using System.Security.Claims;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Tokens;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Tokens
{
    public class GoogleAuthTokenHandler : OpenIDConnectAuthTokenHandler<IGoogleAppsConfigurationStore, IGoogleKeyRetriever>, IGoogleAuthTokenHandler
    {
        public GoogleAuthTokenHandler(ILog log, IGoogleAppsConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IGoogleKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }

        protected override void DoIssuerSpecificClaimsValidation(ClaimsPrincipal principal, out string error)
        {
            error = string.Empty;
            var hd = ConfigurationStore.GetHostedDomain();
            var hdClaim = principal.Claims.FirstOrDefault(c => c.Type == "hd");
            if (hdClaim == null || hdClaim.Value != hd)
            {
                error = "Incorrect Hosted Domain value. This server is setup to accept users from a specific hosted domain only.";
            }
        }
    }
}