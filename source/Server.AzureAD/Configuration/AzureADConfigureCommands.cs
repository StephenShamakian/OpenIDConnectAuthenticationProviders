using System;
using System.Collections.Generic;
using Octopus.Data.Model;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigureCommands : OpenIdConnectConfigureCommands<IAzureADConfigurationStore>
    {
        readonly ISystemLog log;

        public AzureADConfigureCommands(
            ISystemLog log,
            Lazy<IAzureADConfigurationStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
            : base(log, configurationStore, webPortalConfigurationStore)
        {
            this.log = log;
        }

        protected override string ConfigurationSettingsName => "azureAD";

        public override IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in base.GetOptions())
            {
                yield return option;
            }
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}RoleClaimType=", "Tell Octopus how to find the roles in the security token from Azure Active Directory.", v =>
            {
                ConfigurationStore.Value.SetRoleClaimType(v);
                Log.Info($"{ConfigurationSettingsName} RoleClaimType set to: {v}");
            });
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}ClientKey=", "The App Registration secret access key. Used for authenticating against the GraphAPI for group overage lookups.", v =>
            {
                if (!string.IsNullOrEmpty(v))
                {
                    ConfigurationStore.Value.SetClientKey(v.ToSensitiveString());
                    log.Info("Azure AD Graph API Client Key set to provided value");
                }
                else
                {
                    ConfigurationStore.Value.SetClientKey(null);
                    log.Info("Azure AD Graph API Client Key set to null (anonymous bind)");
                }
            });
        }
    }
}