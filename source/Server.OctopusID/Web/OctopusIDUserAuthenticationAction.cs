using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.Mediator;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    class OctopusIDUserAuthenticationAction : UserAuthenticationAction<IOctopusIDConfigurationStore>
    {
        public OctopusIDUserAuthenticationAction(
            ISystemLog log,
            IOctopusIDConfigurationStore configurationStore,
            IOctopusIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IOctopusIDAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore,
            IMediator mediator) : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, modelBinder, authenticationConfigurationStore, mediator)
        {
        }
    }
}