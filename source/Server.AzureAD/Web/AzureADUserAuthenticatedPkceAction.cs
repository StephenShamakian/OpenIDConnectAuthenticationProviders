using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Identities;
using Octopus.Server.Extensibility.Authentication.AzureAD.Infrastructure;
using Octopus.Server.Extensibility.Authentication.AzureAD.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Web
{
    class AzureADUserAuthenticatedPkceAction : UserAuthenticatedPkceAction<IAzureADConfigurationStore, IAzureADAuthTokenHandler, IAzureADIdentityCreator>
    {
        public AzureADUserAuthenticatedPkceAction(
            ISystemLog log,
            IAzureADAuthTokenHandler authTokenHandler,
            IAzureADPrincipalToUserResourceMapper principalToUserResourceMapper,
            IAzureADConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IAzureADIdentityCreator identityCreator,
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

        protected override string ProviderName => AzureADAuthenticationProvider.ProviderName;
    }
}