using System;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.Okta.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.Okta
{
    public class OktaApi : OpenIDConnectModule<OktaUserAuthenticationAction, IOktaConfigurationStore, OktaUserAuthenticatedAction, IOktaAuthTokenHandler>
    {
        public OktaApi(
            IOktaConfigurationStore configurationStore, 
            OktaAuthenticationProvider authenticationProvider,
            Func<WhenEnabledAsyncActionInvoker<OktaUserAuthenticationAction, IOktaConfigurationStore>> authenticateUserActionFactory,
            Func<WhenEnabledAsyncActionInvoker<OktaUserAuthenticatedAction, IOktaConfigurationStore>> userAuthenticatedActionFactory) : base(configurationStore, authenticationProvider)
        {
            Post[authenticationProvider.AuthenticateUri, true] = async (_, token) => await authenticateUserActionFactory().ExecuteAsync(Context, Response);
            Post[configurationStore.RedirectUri, true] = async (_, token) => await userAuthenticatedActionFactory().ExecuteAsync(Context, Response);
        }
    }
}