using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Issuer
{
    public class OctopusIDKeyRetriever : KeyRetriever<IOctopusIDConfigurationStore, IKeyJsonParser>, IOctopusIDKeyRetriever
    {
        public OctopusIDKeyRetriever(IOctopusIDConfigurationStore configurationStore, IKeyJsonParser keyParser, ISystemLog log) : base(configurationStore, keyParser, log)
        {
        }
    }
}