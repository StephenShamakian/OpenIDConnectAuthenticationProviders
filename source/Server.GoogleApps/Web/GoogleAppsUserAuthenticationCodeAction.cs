using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Identities;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Web
{
    class GoogleAppsUserAuthenticationCodeAction : UserAuthenticationCodeAction<IGoogleAppsConfigurationStore, IGoogleAuthTokenHandler, IGoogleAppsIdentityCreator>
    {
        public GoogleAppsUserAuthenticationCodeAction(
            ISystemLog log,
            IGoogleAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            IGoogleAppsConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IGoogleAppsIdentityCreator identityCreator,
            IClock clock,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IUrlEncoder urlEncoder)
            : base(log, authTokenHandler, principalToUserResourceMapper, userStore, configurationStore, authCookieCreator, loginTracker, sleep, identityCreator, clock, identityProviderConfigDiscoverer, urlEncoder)
        {
        }

        protected override string ProviderName => GoogleAppsAuthenticationProvider.ProviderName;
    }
}