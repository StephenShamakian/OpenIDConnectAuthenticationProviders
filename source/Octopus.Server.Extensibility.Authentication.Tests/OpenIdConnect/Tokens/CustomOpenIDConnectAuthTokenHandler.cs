using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Tokens;

namespace Octopus.Server.Extensibility.Authentication.Tests.OpenIdConnect.Tokens
{
    public class CustomOpenIDConnectAuthTokenHandler : OpenIDConnectAuthTokenHandler<IOpenIDConnectConfigurationStore, IKeyRetriever>
    { 
        public CustomOpenIDConnectAuthTokenHandler(ILog log, IOpenIDConnectConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
            
        }
    }

}
