using System;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Identities;
using Octopus.Server.Extensibility.Authentication.AzureAD.Tokens;
using Octopus.Server.Extensibility.Authentication.AzureAD.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.AzureAD
{
    class AzureADApi : OpenIDConnectModule<AzureADUserAuthenticationAction, IAzureADConfigurationStore, AzureADUserAuthenticatedAction, IAzureADAuthTokenHandler, IAzureADIdentityCreator>
    {
        public AzureADApi(
            IAzureADConfigurationStore configurationStore, AzureADAuthenticationProvider authenticationProvider)
            : base(configurationStore, authenticationProvider)
        {
            Add<AzureADUserAuthenticationAction>("POST", authenticationProvider.AuthenticateUri, RouteCategory.Raw, new AnonymousWhenEnabledEndpointInvocation<IAzureADConfigurationStore>(), null, "OpenIDConnect");
            Add<AzureADUserAuthenticatedAction>("POST", configurationStore.RedirectUri, RouteCategory.Raw, new AnonymousWhenEnabledEndpointInvocation<IAzureADConfigurationStore>(), null, "OpenIDConnect");
            Add<AzureADUserAuthenticatedPkceAction>("GET", configurationStore.RedirectUri, RouteCategory.Raw, new AnonymousWhenEnabledEndpointInvocation<IAzureADConfigurationStore>(), null, "OpenIDConnect");
        }
    }
}