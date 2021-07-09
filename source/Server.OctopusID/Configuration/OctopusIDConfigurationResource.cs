using System.ComponentModel;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.MessageContracts;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    [Description("Sign in to your Octopus Server with an Octopus ID. [Learn more](https://g.octopushq.com/AuthOctopusID).")]
    class OctopusIDConfigurationResource : OpenIDConnectConfigurationResource
    {
        [ReadOnly(true)]
        public override string? Issuer { get; set; }

        /// <summary>
        /// NOTE: the following properties are here to control the order they appear on the settings page
        /// </summary>

        [ReadOnly(true)]
        public override string? ClientId { get; set; }
        [ReadOnly(true)]
        public override SensitiveValue? ClientSecret { get; set; }
        [ReadOnly(true)]
        public override bool? AllowAutoUserCreation { get; set; }

        [ReadOnly(true)]
        public new bool IsEnabled { get; set; }
    }
}