using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Nancy;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Tokens
{
    public abstract class OpenIDConnectAuthTokenHandler<TStore, TRetriever> : IAuthTokenHandler
        where TStore : IOpenIDConnectConfigurationStore
        where TRetriever : IKeyRetriever
    {
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        readonly TRetriever keyRetriever;

        readonly ILog log;
        protected readonly TStore ConfigurationStore;

        protected OpenIDConnectAuthTokenHandler(
            ILog log,
            TStore configurationStore,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            TRetriever keyRetriever)
        {
            this.log = log;
            ConfigurationStore = configurationStore;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.keyRetriever = keyRetriever;
        }

        public Task<ClaimsPrincipleContainer> GetPrincipalAsync(Request request, out string state)
        {
            state = null;
            if (request.Form.ContainsKey("error"))
            {
                var errorDescription = request.Form["error_description"];
                log.Error($"Failed to authenticate user: {errorDescription}");
                return Task.FromResult(new ClaimsPrincipleContainer(errorDescription));
            }

            var accessToken = request.Form["access_token"];
            var idToken = request.Form["id_token"];

            state = request.Form["state"];

            return GetPrincipalFromToken(accessToken, idToken);
        }

        internal async Task<ClaimsPrincipleContainer> GetPrincipalFromToken(string accessToken, string idToken)
        {
            var handler = new JwtSecurityTokenHandler();

            var issuer = ConfigurationStore.GetIssuer();
            var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(issuer);

            var keys = await keyRetriever.GetCertificatesAsync(issuerConfig);

            var validationParameters = new TokenValidationParameters
            {
                ValidateActor = true,
                ValidateAudience = true,
                ValidAudience = issuer + "/resources",
                ValidateIssuer = true,
                ValidIssuer = issuerConfig.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeyResolver = (s, securityToken, identifier, parameters) => !keys.ContainsKey(identifier) ? null : new[] { keys[identifier] }
            };

            if (!string.IsNullOrWhiteSpace(ConfigurationStore.GetNameClaimType()))
                validationParameters.NameClaimType = ConfigurationStore.GetNameClaimType();

            var tokenToValidate = accessToken;
            if (string.IsNullOrWhiteSpace(tokenToValidate))
            {
                // if we're validating the id_token then the audience is based on the client_id, not the issuer/resource like access_token
                tokenToValidate = idToken;
                validationParameters.ValidAudience = ConfigurationStore.GetClientId();
            }

            SetIssuerSpecificTokenValidationParameters(validationParameters);

            // This is where we actually interpret the token, validate it, and pump out a ClaimsPrincipal
            SecurityToken unused;

            var signatureError = false;
            ClaimsPrincipal principal = null;
            try
            {
                principal = handler.ValidateToken(tokenToValidate, validationParameters, out unused);
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                signatureError = true;
            }

            // If we receive an invalid signature, it might be because the provider has recylced their keys.
            // So reflush the key cache, reload the keys, and try once more.
            if (signatureError)
            {
                keys = await keyRetriever.GetCertificatesAsync(issuerConfig, true);
                principal = handler.ValidateToken(tokenToValidate, validationParameters, out unused);
            }

            var error = string.Empty;
            DoIssuerSpecificClaimsValidation(principal, out error);
            if (string.IsNullOrEmpty(error))
                return new ClaimsPrincipleContainer(principal);
            else
                return new ClaimsPrincipleContainer(error);
        }

        protected virtual void SetIssuerSpecificTokenValidationParameters(TokenValidationParameters validationParameters)
        { }

        protected virtual void DoIssuerSpecificClaimsValidation(ClaimsPrincipal principal, out string error)
        {
            error = string.Empty;
        }
    }
}