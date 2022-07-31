using System.ComponentModel;
using Octopus.Client.Extensibility.Attributes;
using Octopus.Client.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Client.Extensibility.Authentication.OctopusID.Configuration
{
    [Description("Sign in to your Octopus Server with your Octopus ID. [Learn more](https://g.octopushq.com/AuthOctopusID).")]
    public class OctopusIDConfigurationResource : OpenIDConnectConfigurationResource
    {
        public OctopusIDConfigurationResource()
        {
            Id = "authentication-octopusid";
        }
    }
}