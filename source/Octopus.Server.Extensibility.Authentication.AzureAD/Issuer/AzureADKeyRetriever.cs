using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Issuer
{
    public class AzureADKeyRetriever : KeyRetriever<IAzureADConfigurationStore, IKeyJsonParser>, IAzureADKeyRetriever
    {
        public AzureADKeyRetriever(IClock clock, IAzureADConfigurationStore configurationStore, IKeyJsonParser keyParser) : base(configurationStore, keyParser)
        {
        }
    }
}