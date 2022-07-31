using System.Collections.Generic;
using Octopus.Data.Model;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Mapping;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIDConnectConfigurationSettings<TConfiguration, TResource, TDocumentStore> : ExtensionConfigurationSettings<TConfiguration, TResource, TDocumentStore>
        where TConfiguration : OpenIDConnectConfiguration, new()
        where TResource : ExtensionConfigurationResource
        where TDocumentStore : IOpenIDConnectConfigurationStore<TConfiguration>
    {
        protected OpenIDConnectConfigurationSettings(TDocumentStore configurationDocumentStore) : base(configurationDocumentStore)
        {
        }

        public override string ConfigurationSetName => ConfigurationDocumentStore.ConfigurationSettingsName;

        public override IEnumerable<IConfigurationValue> GetConfigurationValues()
        {
            var configurationSettingsName = ConfigurationDocumentStore.ConfigurationSettingsName;
            var isEnabled = ConfigurationDocumentStore.GetIsEnabled();

            yield return new ConfigurationValue<bool>($"Octopus.{configurationSettingsName}.IsEnabled", isEnabled, isEnabled, "Is Enabled");
            yield return new ConfigurationValue<string?>($"Octopus.{configurationSettingsName}.Issuer", ConfigurationDocumentStore.GetIssuer(), isEnabled, "Issuer");
            yield return new ConfigurationValue<string?>($"Octopus.{configurationSettingsName}.ClientId", ConfigurationDocumentStore.GetClientId(), isEnabled, "ClientId");
            yield return new ConfigurationValue<string?>($"Octopus.{configurationSettingsName}.Scope", ConfigurationDocumentStore.GetScope(), isEnabled && ConfigurationDocumentStore.GetScope() != OpenIDConnectConfiguration.DefaultScope, "Scope");
            yield return new ConfigurationValue<string?>($"Octopus.{configurationSettingsName}.RedirectUri", ConfigurationDocumentStore.RedirectUri, isEnabled, "RedirectUri");
            yield return new ConfigurationValue<string?>($"Octopus.{configurationSettingsName}.NameClaimType", ConfigurationDocumentStore.GetNameClaimType(), isEnabled && ConfigurationDocumentStore.GetNameClaimType() != OpenIDConnectConfiguration.DefaultNameClaimType, "Name Claim Type");
            yield return new ConfigurationValue<bool>($"Octopus.{configurationSettingsName}.AllowAutoUserCreation", ConfigurationDocumentStore.GetAllowAutoUserCreation(), isEnabled, "Allow auto user creation");
        }

        public override void BuildMappings(IResourceMappingsBuilder builder)
        {
            builder.Map<TResource, TConfiguration>();
        }
    }
}