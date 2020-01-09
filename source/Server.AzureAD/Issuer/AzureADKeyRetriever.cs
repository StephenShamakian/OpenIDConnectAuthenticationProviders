using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Issuer
{
    public class AzureADKeyRetriever : KeyRetriever<IAzureADConfigurationStore, IKeyJsonParser>, IAzureADKeyRetriever
    {
        public AzureADKeyRetriever(IAzureADConfigurationStore configurationStore, IKeyJsonParser keyParser, ISystemLog log) : base(configurationStore, keyParser, log)
        {
        }
    }
}