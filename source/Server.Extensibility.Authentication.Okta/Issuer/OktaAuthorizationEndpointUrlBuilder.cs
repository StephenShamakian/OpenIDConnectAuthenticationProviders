﻿using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Issuer
{
    public class OktaAuthorizationEndpointUrlBuilder : AuthorizationEndpointUrlBuilder<IOktaConfigurationStore>, IOktaAuthorizationEndpointUrlBuilder
    {
        public OktaAuthorizationEndpointUrlBuilder(IOktaConfigurationStore configurationStore, IUrlEncoder urlEncoder) : base(configurationStore, urlEncoder)
        {
        }
    }
}