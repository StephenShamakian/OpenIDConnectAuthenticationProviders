using System;
using System.Collections.Generic;
using System.Linq;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIdConnectConfigureCommands<TStore> : IContributeToConfigureCommand
        where TStore : IOpenIDConnectConfigurationStore
    {
        protected readonly ISystemLog Log;
        protected readonly Lazy<TStore> ConfigurationStore;
        readonly Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore;

        protected OpenIdConnectConfigureCommands(
            ISystemLog log,
            Lazy<TStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
        {
            Log = log;
            ConfigurationStore = configurationStore;
            this.webPortalConfigurationStore = webPortalConfigurationStore;
        }

        protected abstract string ConfigurationSettingsName { get; }

        protected IEnumerable<ConfigureCommandOption> GetCoreOptions(bool hide)
        {
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}IsEnabled=", $"Set the {ConfigurationSettingsName} IsEnabled, used for authentication.", v =>
            {
                var isEnabled = bool.Parse(v);
                ConfigurationStore.Value.SetIsEnabled(isEnabled);
                Log.Info($"{ConfigurationSettingsName} IsEnabled set to: {isEnabled}");

                var currentNodeWebPortalConfiguration = webPortalConfigurationStore.Value.GetCurrentNodeWebPortalConfiguration();

                var listenPrefixes = currentNodeWebPortalConfiguration.ListenPrefixes;

                if (isEnabled && currentNodeWebPortalConfiguration.ForceSSL == false && listenPrefixes.Any(s => s.ToLower().Contains("http://")))
                    Log.Warn($"{ConfigurationSettingsName} user authentication API was called from an instance including listening prefixes that are not using https.");

                if (isEnabled && listenPrefixes.Any())
                {
                    Log.Info("Add the following to the Authorized redirect URIs for your app");
                    var prefixes = listenPrefixes.Where(u => !string.IsNullOrWhiteSpace(u));
                    foreach (var prefix in prefixes)
                    {
                        Log.Info(prefix.TrimEnd('/') + "/api/users/authenticatedToken/" + ConfigurationStore.Value.ConfigurationSettingsName);
                    }
                }
            }, hide: hide);
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}Issuer=", $"Follow our documentation to find the Issuer for {ConfigurationSettingsName}.", v =>
            {
                ConfigurationStore.Value.SetIssuer(v);
                Log.Info($"{ConfigurationSettingsName} Issuer set to: {v}");
            }, hide: hide);
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}ClientId=", $"Follow our documentation to find the Client ID for {ConfigurationSettingsName}.", v =>
            {
                ConfigurationStore.Value.SetClientId(v);
                Log.Info($"{ConfigurationSettingsName} ClientId set to: {v}");
            }, hide: hide);
        }

        public virtual IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in GetCoreOptions(hide: false))
            {
                yield return option;
            }
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}Scope=", $"Only change this if you need to change the OpenID Connect scope requested by Octopus for {ConfigurationSettingsName}.", v =>
            {
                ConfigurationStore.Value.SetScope(v);
                Log.Info($"{ConfigurationSettingsName} Scope set to: {v}");
            });
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}NameClaimType=", $"Only change this if you want to use a different security token claim for the name from {ConfigurationSettingsName}.", v =>
            {
                ConfigurationStore.Value.SetNameClaimType(v);
                Log.Info($"{ConfigurationSettingsName} NameClaimType set to: {v}");
            });
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}AllowAutoUserCreation=", $"Tell Octopus to automatically create a user account when a person signs in with {ConfigurationSettingsName}.", v =>
            {
                var isAllowed = bool.Parse(v);
                ConfigurationStore.Value.SetAllowAutoUserCreation(isAllowed);
                Log.Info($"{ConfigurationSettingsName} AllowAutoUserCreation set to: {isAllowed}");
            });
        }
    }
}