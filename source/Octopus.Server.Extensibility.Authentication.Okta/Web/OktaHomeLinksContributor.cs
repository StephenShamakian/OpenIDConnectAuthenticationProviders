using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaHomeLinksContributor : OpenIDConnectHomeLinksContributor<IOktaConfigurationStore, OktaAuthenticationProvider>
    {
        public OktaHomeLinksContributor(IOktaConfigurationStore configurationStore, OktaAuthenticationProvider authenticationProvider) : base(configurationStore, authenticationProvider)
        {
        }
    }
}