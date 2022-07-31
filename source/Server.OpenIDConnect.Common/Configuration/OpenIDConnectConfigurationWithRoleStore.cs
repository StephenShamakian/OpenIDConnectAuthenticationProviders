using Octopus.Data.Model;
using Octopus.Data.Storage.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIDConnectConfigurationWithRoleStore<TConfiguration> : OpenIDConnectConfigurationStore<TConfiguration>, IOpenIDConnectConfigurationWithRoleStore<TConfiguration>
        where TConfiguration : OpenIDConnectConfigurationWithRole, IId, new()
    {
        protected OpenIDConnectConfigurationWithRoleStore(IConfigurationStore configurationStore) : base(configurationStore)
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