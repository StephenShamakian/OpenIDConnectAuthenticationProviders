using System.Collections.Generic;
using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    public class OktaConfigurationStore : OpenIdConnectConfigurationStore<OktaConfiguration>, IOktaConfigurationStore
    {
        protected override string SingletonId => "authentication-od";
        public override string ConfigurationSettingsName => "Okta";

        public OktaConfigurationStore(IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string GetRoleClaimType()
        {
            var doc = ConfigurationStore.Get<OktaConfiguration>(SingletonId);
            return doc?.RoleClaimType;
        }

        public void SetRoleClaimType(string roleClaimType)
        {
            ConfigurationStore.CreateOrUpdate<OktaConfiguration>(SingletonId, doc => doc.RoleClaimType = roleClaimType);
        }

        public override string ConfigurationSetName => "Okta";
        public override IEnumerable<ConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }
            yield return new ConfigurationValue($"Octopus.{ConfigurationSettingsName}.RoleClaimType", GetRoleClaimType(), GetIsEnabled() && GetRoleClaimType() != OktaConfiguration.DefaultRoleClaimType, "Role Claim Type");
        }
    }
}