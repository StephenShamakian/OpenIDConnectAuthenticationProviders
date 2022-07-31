using System;
using Octopus.Data.Model;
using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIDConnectConfigurationStore<TConfiguration> : ExtensionConfigurationStore<TConfiguration>, IOpenIDConnectConfigurationStore<TConfiguration>
        where TConfiguration : OpenIDConnectConfiguration, IId, new()
    {
        public abstract string ConfigurationSettingsName { get; }

        protected OpenIDConnectConfigurationStore(
            IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string? GetIssuer()
        {
            return GetProperty(doc => doc.Issuer);
        }

        public void SetIssuer(string? issuer)
        {
            Guid issuerAsGuid;
            if (Guid.TryParse(issuer, out issuerAsGuid))
                throw new ArgumentException($"The {ConfigurationSettingsName} issuer must be an absolute URI and not a GUID (please refer to the Octopus auth-provider's documentation for details)");
            if (!Uri.IsWellFormedUriString(issuer, UriKind.Absolute))
                throw new ArgumentException($"The {ConfigurationSettingsName} issuer must be an absolute URI (please refer to the Octopus auth-provider's documentation for details)");
            SetProperty(doc => doc.Issuer = issuer);
        }

        public string? GetClientId()
        {
            return GetProperty(doc => doc.ClientId);
        }

        public void SetClientId(string? clientId)
        {
            SetProperty(doc => doc.ClientId = clientId);
        }

        public SensitiveString? GetClientSecret()
        {
            return GetProperty(doc => doc.ClientSecret);
        }

        public void SetClientSecret(SensitiveString? clientSecret)
        {
            SetProperty(doc => doc.ClientSecret = clientSecret);
        }

        public bool HasClientSecret => GetClientSecret() != null;

        public string? GetScope()
        {
            return GetProperty(doc => doc.Scope);
        }

        public void SetScope(string? scope)
        {
            SetProperty(doc => doc.Scope = scope);
        }

        public string? GetNameClaimType()
        {
            return GetProperty(doc => doc.NameClaimType);
        }

        public void SetNameClaimType(string? nameClaimType)
        {
            SetProperty(doc => doc.NameClaimType = nameClaimType);
        }

        public bool GetAllowAutoUserCreation()
        {
            return GetProperty(doc => doc.AllowAutoUserCreation);
        }

        public void SetAllowAutoUserCreation(bool allowAutoUserCreation)
        {
            SetProperty(doc => doc.AllowAutoUserCreation = allowAutoUserCreation);
        }

        public string RedirectUri => $"/api/users/authenticatedToken/{ConfigurationSettingsName}";
    }
}