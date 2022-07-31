using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    class OktaConfigurationStore : OpenIDConnectConfigurationWithRoleStore<OktaConfiguration>, IOktaConfigurationStore
    {
        public const string SingletonId = "authentication-od";

        public override string Id => SingletonId;

        public override string ConfigurationSettingsName => "Okta";

        public OktaConfigurationStore(
            IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string GetUsernameClaimType()
        {
            return GetProperty(doc => doc.UsernameClaimType);
        }

        public void SetUsernameClaimType(string usernameClaimType)
        {
            SetProperty(doc => doc.UsernameClaimType = usernameClaimType);
        }
    }
}