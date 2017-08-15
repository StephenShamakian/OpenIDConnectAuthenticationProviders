using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Infrastructure;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaUserAuthenticatedAction : UserAuthenticatedAction<IOktaConfigurationStore, IOktaAuthTokenHandler>
    {
        public OktaUserAuthenticatedAction(
            ILog log,
            IOktaAuthTokenHandler authTokenHandler,
            IOktaPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUserStore userStore,
            IOktaConfigurationStore configurationStore,
            IApiActionResponseCreator responseCreator,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep) :
            base(
                log,
                authTokenHandler,
                principalToUserResourceMapper,
                userStore,
                configurationStore,
                responseCreator,
                authCookieCreator,
                loginTracker,
                sleep)
        {
        }
    }
}