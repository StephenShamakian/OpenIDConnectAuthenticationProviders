using System;
using System.Linq;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaLoginParametersHandler : ICanHandleLoginParameters
    {
        readonly IOktaConfigurationStore configurationStore;

        public OktaLoginParametersHandler(IOktaConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public bool WasExternalLoginInitiated(string encodedQueryString, out string providerName)
        {
            providerName = null;

            if (!configurationStore.GetIsEnabled())
            {
                return false;
            }

            var parser = new EncodedQueryStringParser();
            var parameters = parser.Parse(encodedQueryString);

            var issuerParam = parameters.FirstOrDefault(p => p.Name == "iss");

            var configuredIssuer = configurationStore.GetIssuer();

            if (issuerParam != null && string.Compare(configuredIssuer, issuerParam.Value, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                providerName = OktaAuthenticationProvider.ProviderName;
                return true;
            }

            return false;
        }
    }
}