using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaUserAuthenticationAction : UserAuthenticationAction<IOktaConfigurationStore>
    {
        public OktaUserAuthenticationAction(
            ILog log,
            IOktaConfigurationStore configurationStore, 
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, 
            IOktaAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionResponseCreator responseCreator,
            IApiActionModelBinder modelBinder,
            IWebPortalConfigurationStore webPortalConfigurationStore) : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, responseCreator, modelBinder, webPortalConfigurationStore)
        {
        }
    }
}