using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    public class OctopusIDUserAuthenticationAction : UserAuthenticationAction<IOctopusIDConfigurationStore>
    {
        public OctopusIDUserAuthenticationAction(
            ISystemLog log,
            IOctopusIDConfigurationStore configurationStore, 
            IOctopusIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, 
            IOctopusIDAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore) : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, modelBinder, authenticationConfigurationStore)
        {
        }
    }
}