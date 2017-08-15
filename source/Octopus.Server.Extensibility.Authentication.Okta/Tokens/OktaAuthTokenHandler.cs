using Microsoft.IdentityModel.Tokens;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Tokens;

namespace Octopus.Server.Extensibility.Authentication.Okta.Tokens
{
    public class OktaAuthTokenHandler : OpenIDConnectAuthTokenHandler<IOktaConfigurationStore, IKeyRetriever>, IOktaAuthTokenHandler
    {
        public OktaAuthTokenHandler(ILog log, IOktaConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }

        protected override void SetIssuerSpecificTokenValidationParameters(TokenValidationParameters validationParameters)
        {
            if (!string.IsNullOrWhiteSpace(ConfigurationStore.GetRoleClaimType()))
                validationParameters.RoleClaimType = ConfigurationStore.GetRoleClaimType();
        }
    }
}