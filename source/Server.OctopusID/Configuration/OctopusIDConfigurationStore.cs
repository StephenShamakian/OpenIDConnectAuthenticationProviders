using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    class OctopusIDConfigurationStore : OpenIDConnectConfigurationStore<OctopusIDConfiguration>, IOctopusIDConfigurationStore
    {
        public const string SingletonId = "authentication-octopusid";

        public override string Id => SingletonId;

        public override string ConfigurationSettingsName => "OctopusID";

        public OctopusIDConfigurationStore(
            IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string? GetRoleClaimType()
        {
            return GetProperty(doc => doc.RoleClaimType);
        }

        public void SetRoleClaimType(string? roleClaimType)
        {
            SetProperty(doc => doc.RoleClaimType = roleClaimType);
        }
   }
}