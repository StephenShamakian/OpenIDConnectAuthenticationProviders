using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaCSSContributor : OpenIDConnectCSSContributor<IOktaConfigurationStore>
    {
        public OktaCSSContributor(IOktaConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public override string CSSFilename => "okta";
    }
}