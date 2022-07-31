using Octopus.Data.Model;
using Octopus.Data.Storage.Configuration;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigurationStore : OpenIDConnectConfigurationWithRoleStore<AzureADConfiguration>, IAzureADConfigurationStore
    {
        public const string SingletonId = "authentication-aad";
        ISystemLog log;

        public override string Id => SingletonId;

        public override string ConfigurationSettingsName => "AzureAD";

        public AzureADConfigurationStore(
            IConfigurationStore configurationStore, ISystemLog log) : base(configurationStore)
        {
            this.log = log;
        }

        public void SetClientKey(string? clientkey)
        {
            SetProperty(doc => doc.RoleClaimType = clientkey);
        }

        public SensitiveString? GetClientKey() => GetProperty(doc => doc.ClientKey);
        
        public void SetClientKey(SensitiveString? key) => SetProperty(doc =>
        {
            if (!string.IsNullOrEmpty(key?.Value))
                log.WithSensitiveValue(key.Value);

            doc.ClientKey = key;
        });
    }
}