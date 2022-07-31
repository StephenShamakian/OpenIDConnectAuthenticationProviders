using System.ComponentModel;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.MessageContracts;
using Octopus.Server.MessageContracts.Attributes;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    [Description("Sign in to your Octopus Server with an Octopus ID. [Learn more](https://g.octopushq.com/AuthOctopusID).")]
    class OctopusIDConfigurationResource : OpenIDConnectConfigurationResource
    {
        [Writeable]
        public override string? Issuer { get; set; }

        /// <summary>
        /// NOTE: the following properties are here to control the order they appear on the settings page
        /// </summary>

        [Writeable]
        public override string? ClientId { get; set; }

        [Writeable]
        public override SensitiveValue? ClientSecret { get; set; }

        [Writeable]
        public override bool? AllowAutoUserCreation { get; set; }
    }
}