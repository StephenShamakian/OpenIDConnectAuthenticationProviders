using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Tokens
{
    public class OctopusIDAuthTokenHandler : OpenIDConnectAuthTokenWithRolesHandler<IOctopusIDConfigurationStore, IOctopusIDKeyRetriever, IOctopusIdentityProviderConfigDiscoverer>, IOctopusIDAuthTokenHandler
    {
        public OctopusIDAuthTokenHandler(ISystemLog log, IOctopusIDConfigurationStore configurationStore, IOctopusIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IOctopusIDKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }
    }
}