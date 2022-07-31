using System;
using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    class OktaConfigureCommands : OpenIDConnectConfigureCommands<IOktaConfigurationStore>
    {
        public OktaConfigureCommands(
            ISystemLog log,
            Lazy<IOktaConfigurationStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
            : base(log, configurationStore, webPortalConfigurationStore)
        {
        }

        protected override string ConfigurationSettingsName => "okta";

        public override IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in base.GetOptions())
            {
                yield return option;
            }
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}RoleClaimType=", "Tell Octopus how to find the roles in the security token from Okta.", v =>
            {
                ConfigurationStore.Value.SetRoleClaimType(v);
                Log.Info($"{ConfigurationSettingsName} RoleClaimType set to: {v}");
            });
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}UsernameClaimType=", "Tell Octopus how to find the value for the Octopus Username in the Okta token. Defaults to \"preferred_username\" if left blank.", v =>
            {
                ConfigurationStore.Value.SetUsernameClaimType(v);
                Log.Info($"{ConfigurationSettingsName} UsernameClaimType set to: {v}");
            });
        }
    }
}