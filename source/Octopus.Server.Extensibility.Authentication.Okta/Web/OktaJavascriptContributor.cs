using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaJavascriptContributor : OpenIDConnectJavascriptContributor<IOktaConfigurationStore>
    {
        public OktaJavascriptContributor(IOktaConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        protected override string AngularModuleNameSuffix => "okta";
        public override string JavascriptFilenamePrefix => "okta";
    }
}