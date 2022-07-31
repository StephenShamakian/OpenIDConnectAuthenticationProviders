using System;
using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    class GoogleAppsConfigureCommands : OpenIDConnectConfigureCommands<IGoogleAppsConfigurationStore>
    {
        public GoogleAppsConfigureCommands(
            ISystemLog log,
            Lazy<IGoogleAppsConfigurationStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
            : base(log, configurationStore, webPortalConfigurationStore)
        {
        }

        protected override string ConfigurationSettingsName => "googleApps";

        public override IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in base.GetOptions())
            {
                yield return option;
            }
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}HostedDomain=", $"Tell Octopus which Google Apps domain to trust.", v =>
            {
                ConfigurationStore.Value.SetHostedDomain(v);
                Log.Info($"{ConfigurationSettingsName} HostedDomain set to: {v}");
            });
        }
    }
}