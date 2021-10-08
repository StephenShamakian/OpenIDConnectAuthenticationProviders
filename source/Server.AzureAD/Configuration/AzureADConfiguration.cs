using Octopus.Data.Model;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfiguration : OpenIDConnectConfigurationWithRole
    {
        public static string DefaultRoleClaimType = "roles";

        public AzureADConfiguration() : base(AzureADConfigurationStore.SingletonId, "AzureAD", "Octopus Deploy", "1.0")
        {
            RoleClaimType = DefaultRoleClaimType;
        }

        public SensitiveString ClientKey { get; set; }
    }
}