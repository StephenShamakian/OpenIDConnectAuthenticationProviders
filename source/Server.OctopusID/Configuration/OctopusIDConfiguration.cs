using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    class OctopusIDConfiguration : OpenIDConnectConfiguration, IOpenIDConnectConfigurationWithRole
    {
        public static string DefaultRoleClaimType = "roles";

        public OctopusIDConfiguration() : base(OctopusIDConfigurationStore.SingletonId, "OctopusID", "Octopus Deploy", "1.1")
        {
            Issuer = "https://account.octopus.com";
            Scope = DefaultScope;
            RoleClaimType = DefaultRoleClaimType;
        }
        
        public string? RoleClaimType { get; set; }
    }
}