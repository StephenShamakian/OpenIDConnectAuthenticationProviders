using System.Collections.Generic;
using System.Threading.Tasks;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens
{
    public abstract class OpenIDConnectAuthTokenHandler<TStore, TRetriever, TDiscoverer> : AuthTokenHandler<TStore, TRetriever, TDiscoverer>, IAuthTokenHandler
        where TStore : IOpenIDConnectConfigurationStore
        where TRetriever : IKeyRetriever
        where TDiscoverer : IIdentityProviderConfigDiscoverer
    {
        protected OpenIDConnectAuthTokenHandler(
            ISystemLog log,
            TStore configurationStore,
            TDiscoverer identityProviderConfigDiscoverer,
            TRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }

        public Task<ClaimsPrincipalContainer> GetPrincipalAsync(IDictionary<string, string?> requestForm, out string? stateString)
        {
            stateString = null;

            if (requestForm.ContainsKey("error"))
            {
                var errorDescription = requestForm["error_description"] ?? string.Empty;
                Log.Error($"Failed to authenticate user: {errorDescription}");
                return Task.FromResult(new ClaimsPrincipalContainer(errorDescription));
            }

            string? accessToken = null;
            if (requestForm.ContainsKey("access_token"))
            {
                accessToken = requestForm["access_token"];
            }

            string? idToken = null;
            if (requestForm.ContainsKey("id_token"))
            {
                idToken = requestForm["id_token"];
            }

            if (requestForm.ContainsKey("state"))
            {
                stateString = requestForm["state"];
            }

            return GetPrincipalFromToken(accessToken, idToken);
        }
    }
}