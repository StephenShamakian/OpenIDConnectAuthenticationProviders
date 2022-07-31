using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    class GoogleAppsConfigurationStore : OpenIDConnectConfigurationStore<GoogleAppsConfiguration>, IGoogleAppsConfigurationStore
    {
        public const string SingletonId = "authentication-googleapps";

        public override string Id => SingletonId;
        public override string ConfigurationSettingsName => "GoogleApps";

        public GoogleAppsConfigurationStore(
            IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string? GetHostedDomain()
        {
            return GetProperty(doc => doc.HostedDomain);
        }

        public void SetHostedDomain(string? hostedDomain)
        {
            SetProperty(doc => doc.HostedDomain = hostedDomain);
        }
    }
}