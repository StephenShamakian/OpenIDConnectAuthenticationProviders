using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Identities;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    class OktaUserAuthenticatedPkceAction
        : UserAuthenticatedPkceAction<IOktaConfigurationStore, IOktaAuthTokenHandler, IOktaIdentityCreator>
    {
        public OktaUserAuthenticatedPkceAction(
            ISystemLog log,
            IOktaAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IOktaConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IOktaIdentityCreator identityCreator,
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

        protected override string ProviderName => OktaAuthenticationProvider.ProviderName;
    }
}