using System.Collections.Generic;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    class OktaConfigurationSettings : OpenIDConnectConfigurationSettings<OktaConfiguration, OktaConfigurationResource, IOktaConfigurationStore>, IOktaConfigurationSettings
    {
        public OktaConfigurationSettings(IOktaConfigurationStore configurationDocumentStore) : base(configurationDocumentStore)
        {
        }

        public override string Id => OktaConfigurationStore.SingletonId;
        public override string Description => "Okta authentication settings";

        public override IEnumerable<IConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }
            yield return new ConfigurationValue<string?>($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.RoleClaimType", ConfigurationDocumentStore.GetRoleClaimType(), ConfigurationDocumentStore.GetIsEnabled() && ConfigurationDocumentStore.GetRoleClaimType() != OktaConfiguration.DefaultRoleClaimType, "Role Claim Type");
            yield return new ConfigurationValue<string?>($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.UsernameClaimType", ConfigurationDocumentStore.GetUsernameClaimType(), ConfigurationDocumentStore.GetIsEnabled() && ConfigurationDocumentStore.GetUsernameClaimType() != OktaConfiguration.DefaultUsernameClaimType, "Username Claim Type");
        }
    }
}
