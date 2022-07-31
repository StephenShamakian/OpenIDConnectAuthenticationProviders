using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.Mediator;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    class OktaUserAuthenticationAction : UserAuthenticationAction<IOktaConfigurationStore>
    {
        public OktaUserAuthenticationAction(
            ISystemLog log,
            IOktaConfigurationStore configurationStore,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IOktaAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore,
            IMediator mediator) : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, modelBinder, authenticationConfigurationStore, mediator)
        {
        }
    }
}