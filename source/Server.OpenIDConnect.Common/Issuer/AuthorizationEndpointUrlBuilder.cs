using System;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer
{
    public abstract class AuthorizationEndpointUrlBuilder<TStore> : IAuthorizationEndpointUrlBuilder
        where TStore : IOpenIDConnectConfigurationStore
    {
        protected TStore ConfigurationStore { get; }
        readonly IUrlEncoder urlEncoder;

        protected AuthorizationEndpointUrlBuilder(TStore configurationStore, IUrlEncoder urlEncoder)
        {
            ConfigurationStore = configurationStore;
            this.urlEncoder = urlEncoder;
        }

        // TODO: Remove the explicit check for OctopusID once OctopusID supports auth code flow
        protected virtual string ResponseType => ConfigurationStore.HasClientSecret && ConfigurationStore.ConfigurationSettingsName != "OctopusID"
            ? OpenIDConnectConfiguration.AuthCodeResponseType
            : OpenIDConnectConfiguration.HybridResponseType;
        protected virtual string ResponseMode => OpenIDConnectConfiguration.DefaultResponseMode;

        public virtual string Build(string requestDirectoryPath, IssuerConfiguration issuerConfiguration, string? nonce = null, string? state = null, string? codeChallenge = null)
        {
            if (issuerConfiguration == null)
                throw new ArgumentException("issuerConfiguration is required", nameof(issuerConfiguration));

            var issuerEndpoint = issuerConfiguration.AuthorizationEndpoint;
            var clientId = ConfigurationStore.GetClientId();
            var scope = ConfigurationStore.GetScope();
            var responseType = ResponseType;
            var responseMode = ResponseMode;
            var redirectUri = requestDirectoryPath.Trim('/') + ConfigurationStore.RedirectUri;

            var url = $"{issuerEndpoint}?client_id={clientId}&scope={scope}&response_type={responseType}&redirect_uri={redirectUri}";

            if (!ConfigurationStore.HasClientSecret)
            {
                url += $"&response_mode={responseMode}";
            }
            if (!string.IsNullOrWhiteSpace(state))
            {
                url += $"&state={urlEncoder.UrlEncode(state)}";
            }
            if (!string.IsNullOrWhiteSpace(nonce))
            {
                url += $"&nonce={nonce}";
            }
            if (!string.IsNullOrWhiteSpace(codeChallenge))
            {
                url += $"&code_challenge={codeChallenge}";
                url += "&code_challenge_method=S256";
            }

            return url;
        }
    }
}