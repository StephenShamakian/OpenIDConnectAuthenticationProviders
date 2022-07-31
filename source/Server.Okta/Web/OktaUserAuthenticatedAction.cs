using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Infrastructure;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Okta.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    class OktaUserAuthenticatedAction : UserAuthenticatedAction<IOktaConfigurationStore, IOktaAuthTokenHandler, IOktaIdentityCreator>
    {
        public OktaUserAuthenticatedAction(
            ISystemLog log,
            IOktaAuthTokenHandler authTokenHandler,
            IOktaPrincipalToUserResourceMapper principalToUserResourceMapper,
            IOktaConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IOktaIdentityCreator identityCreator,
            IUrlEncoder encoder,
            IUserService userService) :
            base(
                log,
                authTokenHandler,
                principalToUserResourceMapper,
                configurationStore,
                authCookieCreator,
                loginTracker,
                sleep,
                identityCreator,
                encoder,
                userService)
        {
        }

        protected override string ProviderName => OktaAuthenticationProvider.ProviderName;
    }
}