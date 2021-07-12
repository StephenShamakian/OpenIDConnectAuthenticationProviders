using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Identities;
using Octopus.Server.Extensibility.Authentication.AzureAD.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Web
{
    class AzureADUserAuthenticationCodeAction : UserAuthenticationCodeAction<IAzureADConfigurationStore, IAzureADAuthTokenHandler, IAzureADIdentityCreator>
    {
        public AzureADUserAuthenticationCodeAction(
            ISystemLog log,
            IAzureADAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            IAzureADConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IAzureADIdentityCreator identityCreator,
            IClock clock,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IUrlEncoder urlEncoder)
            : base(log, authTokenHandler, principalToUserResourceMapper, userStore, configurationStore, authCookieCreator, loginTracker, sleep, identityCreator, clock, identityProviderConfigDiscoverer, urlEncoder)
        {
        }

        protected override string ProviderName => AzureADAuthenticationProvider.ProviderName;
    }
}