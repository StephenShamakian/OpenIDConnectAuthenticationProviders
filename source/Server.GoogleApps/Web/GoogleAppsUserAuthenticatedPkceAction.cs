using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Identities;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Web
{
    class GoogleAppsUserAuthenticatedPkceAction
        : UserAuthenticatedPkceAction<IGoogleAppsConfigurationStore, IGoogleAuthTokenHandler, IGoogleAppsIdentityCreator>
    {
        public GoogleAppsUserAuthenticatedPkceAction(
            ISystemLog log,
            IGoogleAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IGoogleAppsConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IGoogleAppsIdentityCreator identityCreator,
            IUrlEncoder encoder,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IMediator mediator,
            IUserService service)
            : base(log,
                authTokenHandler,
                principalToUserResourceMapper,
                configurationStore,
                authCookieCreator,
                loginTracker,
                sleep,
                identityCreator,
                encoder,
                identityProviderConfigDiscoverer,
                mediator,
                service)
        {
        }

        protected override string ProviderName => GoogleAppsAuthenticationProvider.ProviderName;
    }
}