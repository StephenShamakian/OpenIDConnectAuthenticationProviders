using System;
using System.Collections.Generic;
using Octopus.Data.Model;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    class OctopusIDConfigureCommands : OpenIDConnectConfigureCommands<IOctopusIDConfigurationStore>
    {
        public OctopusIDConfigureCommands(
            ISystemLog log,
            Lazy<IOctopusIDConfigurationStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
            : base(log, configurationStore, webPortalConfigurationStore)
        {
        }

        protected override string ConfigurationSettingsName => "octopusId";

        public override IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in base.GetCoreOptions(hide: true))
            {
                yield return option;
            }
        }
    }
}