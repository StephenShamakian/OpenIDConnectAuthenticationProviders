using System.Collections.Generic;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    class GoogleAppsConfigurationSettings : OpenIDConnectConfigurationSettings<GoogleAppsConfiguration, GoogleAppsConfigurationResource, IGoogleAppsConfigurationStore>, IGoogleAppsConfigurationSettings
    {
        public GoogleAppsConfigurationSettings(IGoogleAppsConfigurationStore configurationDocumentStore) : base(configurationDocumentStore)
        {
        }

        public override string Id => GoogleAppsConfigurationStore.SingletonId;
        public override string Description => "GoogleApps authentication settings";

        public override IEnumerable<IConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }

            yield return new ConfigurationValue<string?>($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.HostedDomain", ConfigurationDocumentStore.GetHostedDomain(), ConfigurationDocumentStore.GetIsEnabled(), "Hosted Domain");
        }
    }
}