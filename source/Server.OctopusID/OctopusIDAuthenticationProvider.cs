using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;

namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    public class OctopusIDAuthenticationProvider : OpenIDConnectAuthenticationProvider<IOctopusIDConfigurationStore>
    {
        public const string ProviderName = "Octopus ID";

        public OctopusIDAuthenticationProvider(ISystemLog log, IOctopusIDConfigurationStore configurationStore) : base(log, configurationStore)
        {
        }

        public override string IdentityProviderName => ProviderName;
        public override string FilenamePrefix => "octopusId";

        protected override IEnumerable<string> ReasonsWhyConfigIsIncomplete()
        {
            var issuer = ConfigurationStore.GetIssuer();
            if (string.IsNullOrWhiteSpace(issuer))
                yield return $"No {IdentityProviderName} issuer specified";
            if (string.IsNullOrWhiteSpace(ConfigurationStore.GetClientId()))
                yield return $"No {IdentityProviderName} Client ID specified";
        }
    }
}
