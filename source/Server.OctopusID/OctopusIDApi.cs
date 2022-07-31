using System;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Identities;
using Octopus.Server.Extensibility.Authentication.OctopusID.Tokens;
using Octopus.Server.Extensibility.Authentication.OctopusID.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    class OctopusIDApi : OpenIDConnectModule<OctopusIDUserAuthenticationAction, IOctopusIDConfigurationStore, OctopusIDUserAuthenticatedAction, IOctopusIDAuthTokenHandler, IOctopusIDIdentityCreator>
    {
        public OctopusIDApi(
            IOctopusIDConfigurationStore configurationStore, OctopusIDAuthenticationProvider authenticationProvider)
            : base(configurationStore, authenticationProvider)
        {
            Add<OctopusIDUserAuthenticationAction>("POST", authenticationProvider.AuthenticateUri, RouteCategory.Raw, new AnonymousWhenEnabledEndpointInvocation<IOctopusIDConfigurationStore>(), null, "OpenIDConnect");
            Add<OctopusIDUserAuthenticatedAction>("POST", configurationStore.RedirectUri, RouteCategory.Raw, new AnonymousWhenEnabledEndpointInvocation<IOctopusIDConfigurationStore>(), null, "OpenIDConnect");
            Add<OctopusIDUserAuthenticatedPkceAction>("GET", configurationStore.RedirectUri, RouteCategory.Raw, new AnonymousWhenEnabledEndpointInvocation<IOctopusIDConfigurationStore>(), null, "OpenIDConnect");
        }
    }
}