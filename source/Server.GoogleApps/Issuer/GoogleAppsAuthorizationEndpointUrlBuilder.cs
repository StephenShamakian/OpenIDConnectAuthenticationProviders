using System;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Issuer
{
    class GoogleAppsAuthorizationEndpointUrlBuilder : AuthorizationEndpointUrlBuilder<IGoogleAppsConfigurationStore>, IGoogleAppsAuthorizationEndpointUrlBuilder
    {
        public GoogleAppsAuthorizationEndpointUrlBuilder(IGoogleAppsConfigurationStore configurationStore, IUrlEncoder urlEncoder) : base(configurationStore, urlEncoder)
        {
        }

        public override string Build(string requestDirectoryPath, IssuerConfiguration issuerConfiguration, string? nonce = null, string? state = null, string? codeChallenge = null)
        {
            var url = base.Build(requestDirectoryPath, issuerConfiguration, nonce, state, codeChallenge);

            var hd = ConfigurationStore.GetHostedDomain();
            if (!string.IsNullOrWhiteSpace(hd))
            {
                url += $"&hd={hd}";
            }

            return url;
        }
    }
}