using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;

namespace Octopus.Server.Extensibility.Authentication.Okta.Tokens
{
    public class OktaAuthTokenHandler : OpenIDConnectAuthTokenWithRolesHandler<IOktaConfigurationStore, IOktaKeyRetriever, IIdentityProviderConfigDiscoverer>, IOktaAuthTokenHandler
    {
        public OktaAuthTokenHandler(ISystemLog log, IOktaConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IOktaKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }
    }
}