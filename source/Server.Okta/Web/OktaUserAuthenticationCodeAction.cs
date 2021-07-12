using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Identities;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    class OktaUserAuthenticationCodeAction : UserAuthenticationCodeAction<IOktaConfigurationStore, IOktaAuthTokenHandler, IOktaIdentityCreator>
    {
        public OktaUserAuthenticationCodeAction(
            ISystemLog log,
            IOktaAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            IOktaConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IOktaIdentityCreator identityCreator,
            IClock clock,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IUrlEncoder urlEncoder)
            : base(log, authTokenHandler, principalToUserResourceMapper, userStore, configurationStore, authCookieCreator, loginTracker, sleep, identityCreator, clock, identityProviderConfigDiscoverer, urlEncoder)
        {
        }

        protected override string ProviderName => OktaAuthenticationProvider.ProviderName;
    }
}