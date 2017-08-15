using System;
using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    public class AzureADConfigureCommands : OpenIdConnectConfigureCommands<IAzureADConfigurationStore>
    {
        public AzureADConfigureCommands(
            ILog log,
            Lazy<IAzureADConfigurationStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
            : base(log, configurationStore, webPortalConfigurationStore)
        {
        }

        protected override string ConfigurationSettingsName => "azureAD";

        public override IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in base.GetOptions())
            {
                yield return option;
            }
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}RoleClaimType=", "Set the RoleClaimType.", v =>
            {
                ConfigurationStore.Value.SetRoleClaimType(v);
                Log.Info($"{ConfigurationSettingsName} RoleClaimType set to: {v}");
            });
        }
    }
}