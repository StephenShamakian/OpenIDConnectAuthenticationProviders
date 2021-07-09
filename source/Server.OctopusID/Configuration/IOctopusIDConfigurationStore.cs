using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    interface IOctopusIDConfigurationStore : IOpenIDConnectConfigurationWithRoleStore<OctopusIDConfiguration>
    {
    }
}