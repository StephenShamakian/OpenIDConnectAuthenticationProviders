﻿using System.ComponentModel;
using Octopus.Data.Resources.Attributes;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Node.Extensibility.Authentication.OpenIDConnect.Configuration
{
    public class OpenIDConnectConfigurationResource : ExtensionConfigurationResource
    {
        [Description("Follow our documentation to find the Issuer for your identity provider")]
        [Writeable]
        public virtual string Issuer { get; set; }

        [DisplayName("Client ID")]
        [Description("Follow our documentation to find the Client ID for your identity provider")]
        [Writeable]
        public string ClientId { get; set; }

        [Writeable]
        [Description("Only change this if you need to change the OpenID Connect scope requested by Octopus")]
        public string Scope { get; set; }

        [DisplayName("Name Claim Type")]
        [Description("Only change this if you want to use a different security token claim for the name")]
        [Writeable]
        public string NameClaimType { get; set; }

        [DisplayName("Allow Auto User Creation")]
        [Description("Tell Octopus to automatically create a user account when a person signs in for the first time with this identity provider")]
        [Writeable]
        public bool? AllowAutoUserCreation { get; set; }
    }
}