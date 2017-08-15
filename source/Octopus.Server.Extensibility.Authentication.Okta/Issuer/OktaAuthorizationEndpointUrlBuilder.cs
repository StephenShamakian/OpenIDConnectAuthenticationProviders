using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;

namespace Octopus.Server.Extensibility.Authentication.Okta.Issuer
{
    public class OktaAuthorizationEndpointUrlBuilder : AuthorizationEndpointUrlBuilder<IOktaConfigurationStore>, IOktaAuthorizationEndpointUrlBuilder
    {
        public OktaAuthorizationEndpointUrlBuilder(IOktaConfigurationStore configurationStore) : base(configurationStore)
        {
        }
    }
}