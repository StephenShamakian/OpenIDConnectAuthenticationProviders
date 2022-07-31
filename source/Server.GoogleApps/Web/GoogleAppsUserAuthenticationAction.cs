using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Issuer;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.Mediator;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Web
{
    class GoogleAppsUserAuthenticationAction : UserAuthenticationAction<IGoogleAppsConfigurationStore>
    {
        public GoogleAppsUserAuthenticationAction(
            ISystemLog log,
            IGoogleAppsConfigurationStore configurationStore,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IGoogleAppsAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore,
            IMediator mediator)
                : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, modelBinder, authenticationConfigurationStore, mediator)
        {
        }
    }
}