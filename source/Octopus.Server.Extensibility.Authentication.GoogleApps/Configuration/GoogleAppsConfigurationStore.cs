using System.Collections.Generic;
using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    public class GoogleAppsConfigurationStore : OpenIdConnectConfigurationStore<GoogleAppsConfiguration>, IGoogleAppsConfigurationStore
    {
        protected override string SingletonId => "authentication-googleapps";
        public override string ConfigurationSettingsName => "GoogleApps";

        public GoogleAppsConfigurationStore(IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string GetHostedDomain()
        {
            var doc = ConfigurationStore.Get<GoogleAppsConfiguration>(SingletonId);
            return doc?.HostedDomain;
        }

        public void SetHostedDomain(string hostedDomain)
        {
            ConfigurationStore.CreateOrUpdate<GoogleAppsConfiguration>(SingletonId, doc => doc.HostedDomain = hostedDomain);
        }

        public override string ConfigurationSetName => "GoogleApps";
        public override IEnumerable<ConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }

            yield return new ConfigurationValue($"Octopus.{ConfigurationSettingsName}.HostedDomain", GetHostedDomain(), GetIsEnabled(), "Hosted Domain");
        }
    }
}