using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Identities;
using Octopus.Server.Extensibility.Authentication.OctopusID.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OctopusID.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    public class OctopusIDUserAuthenticatedAction : UserAuthenticatedAction<IOctopusIDConfigurationStore, IOctopusIDAuthTokenHandler, IOctopusIDIdentityCreator>
    {
        public OctopusIDUserAuthenticatedAction(
            ISystemLog log,
            IOctopusIDAuthTokenHandler authTokenHandler,
            IOctopusIDPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            IOctopusIDConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IOctopusIDIdentityCreator identityCreator,
            IClock clock, IUrlEncoder encoder) :
            base(
                log,
                authTokenHandler,
                principalToUserResourceMapper,
                userStore,
                configurationStore,
                authCookieCreator,
                loginTracker,
                sleep,
                identityCreator, 
                clock, 
                encoder)
        {
        }

        protected override string ProviderName => OctopusIDAuthenticationProvider.ProviderName;
    }
}