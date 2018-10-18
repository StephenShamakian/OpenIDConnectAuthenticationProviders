﻿using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaUserAuthenticationAction : UserAuthenticationAction<IOktaConfigurationStore>
    {
        public OktaUserAuthenticationAction(
            ILog log,
            IOktaConfigurationStore configurationStore, 
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, 
            IOktaAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore) : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, modelBinder, authenticationConfigurationStore)
        {
        }
    }
}