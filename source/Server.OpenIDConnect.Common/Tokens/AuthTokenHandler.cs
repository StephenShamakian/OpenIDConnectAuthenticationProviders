using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens
{
    public abstract class AuthTokenHandler<TStore, TRetriever, TDiscoverer>
        where TStore : IOpenIDConnectConfigurationStore
        where TRetriever : IKeyRetriever
        where TDiscoverer : IIdentityProviderConfigDiscoverer
    {
        static string[] hmacAlgorithms = {SecurityAlgorithms.HmacSha256, SecurityAlgorithms.HmacSha384, SecurityAlgorithms.HmacSha512};
        
        readonly TDiscoverer identityProviderConfigDiscoverer;
        readonly TRetriever keyRetriever;
        protected readonly ISystemLog Log;
        protected readonly TStore ConfigurationStore;

        protected AuthTokenHandler(TStore configurationStore,
            TDiscoverer identityProviderConfigDiscoverer,
            TRetriever keyRetriever,
            ISystemLog log)
        {
            ConfigurationStore = configurationStore;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.keyRetriever = keyRetriever;
            Log = log;
        }

        protected async Task<ClaimsPrincipleContainer> GetPrincipalFromToken(string accessToken, string idToken)
        {
            ClaimsPrincipal principal = null;

            var issuer = ConfigurationStore.GetIssuer();
            var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(issuer);

            var validationParameters = new TokenValidationParameters
            {
                ValidateActor = true,
                ValidateAudience = true,
                ValidAudience = issuer + "/resources",
                ValidateIssuer = true,
                ValidIssuer = issuerConfig.Issuer,
                ValidateIssuerSigningKey = true
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
            
            var jwt = new JwtSecurityToken(idToken);
            
            if (hmacAlgorithms.Contains(jwt.Header.Alg))
            {
                principal = ValidateUsingSharedSecret(validationParameters, tokenToValidate);
            }
            else
            {
                principal = await ValidateUsingIssuerCerficate(validationParameters, tokenToValidate, issuerConfig);
            }

            var error = string.Empty;
            DoIssuerSpecificClaimsValidation(principal, out error);

            if (string.IsNullOrWhiteSpace(error))
                return new ClaimsPrincipleContainer(principal, GetProviderGroupIds(principal));

            return new ClaimsPrincipleContainer(error);
        }

        ClaimsPrincipal ValidateUsingSharedSecret(TokenValidationParameters validationParameters, string tokenToValidate)
        {
            if (ConfigurationStore is IOpenIDConnectWithClientSecretConfigurationStore clientSecretStore)
            {
                var clientSecret = clientSecretStore.GetClientSecret();
                validationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientSecret));
            }
            else
            {
                throw new InvalidOperationException($"The received token was signed with a client secret, which is not supported by the {ConfigurationStore.ConfigurationSettingsName} authentication provider.");
            }
            
            SecurityToken unused;
            var handler = new JwtSecurityTokenHandler();
            try
            {
                return handler.ValidateToken(tokenToValidate, validationParameters, out unused);
            }
            catch (SecurityTokenInvalidSignatureException ex)
            {
                Log.Error(ex, "Token signature validation failed, ensure the clientId and clientSecret are set correctly.");
                throw new ApplicationException("Token signature validation failed, ensure the clientId and clientSecret are set correctly.", ex);
            }
        }

        async Task<ClaimsPrincipal> ValidateUsingIssuerCerficate(TokenValidationParameters validationParameters, string tokenToValidate, IssuerConfiguration issuerConfig)
        {
            var keys = !string.IsNullOrWhiteSpace(issuerConfig.JwksUri) ? await keyRetriever.GetKeysAsync(issuerConfig) : new Dictionary<string, AsymmetricSecurityKey>();
            validationParameters.IssuerSigningKeyResolver = (s, securityToken, identifier, parameters) =>
            {
                if (!keys.ContainsKey(identifier))
                {
                    Log.InfoFormat("No signing key found for kid {0}", identifier);
                    return null;
                }

                return new[] {keys[identifier]};
            };
            
            SecurityToken unused;
            ClaimsPrincipal principal = null;

            var signatureError = false;
            var handler = new JwtSecurityTokenHandler();

            try
            {
                principal = handler.ValidateToken(tokenToValidate, validationParameters, out unused);
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                signatureError = true;
            }

            // If we receive an invalid signature, it might be because the provider has cycled their keys.
            // So flush the key cache, reload the keys, and try once more.
            if (signatureError)
            {
                try
                {
                    Log.InfoFormat("Unable to locate signature key, attempting reload. Currently cached kids are {0}", string.Join(", ", keys.Keys));
                    keys = await keyRetriever.GetKeysAsync(issuerConfig, true);
                    principal = handler.ValidateToken(tokenToValidate, validationParameters, out unused);
                }
                catch (SecurityTokenInvalidSignatureException)
                {
                    // we still didn't find the right key. Log the kids we have
                    Log.WarnFormat("Unable to locate signature key. Cached kids are {0}", string.Join(", ", keys.Keys));
                    throw;
                }
            }

            return principal;
        }
        
        protected virtual void SetIssuerSpecificTokenValidationParameters(TokenValidationParameters validationParameters)
        { }

        protected virtual void DoIssuerSpecificClaimsValidation(ClaimsPrincipal principal, out string error)
        {
            error = string.Empty;
        }

        protected virtual string[] GetProviderGroupIds(ClaimsPrincipal principal)
        {
            return new string[0];
        }
    }
}