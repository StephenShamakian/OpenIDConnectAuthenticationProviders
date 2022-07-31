using System;
using Octopus.Data.Model;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIDConnectConfiguration : ExtensionConfigurationDocument, IOpenIDConnectConfiguration
    {
        public const string AuthCodeResponseType = "code";
        public const string HybridResponseType = "code+id_token";
        public const string DefaultResponseMode = "form_post";
        public const string DefaultScope = "openid%20profile%20email";
        public const string DefaultNameClaimType = "name";
        public const string AuthCodeGrantType = "authorization_code";

        protected OpenIDConnectConfiguration(string id) : base(id)
        {
            AllowAutoUserCreation = true;
        }

        protected OpenIDConnectConfiguration(string id, string name, string author, string configurationSchemaVersion) : base(id, name, author, configurationSchemaVersion)
        {
            Scope = DefaultScope;

            NameClaimType = DefaultNameClaimType;

            AllowAutoUserCreation = true;
        }

        public string? Issuer { get; set; }

        public string? ClientId { get; set; }

        public SensitiveString? ClientSecret { get; set; }

        public string? Scope { get; set; }

        public string? NameClaimType { get; set; }

        public bool AllowAutoUserCreation { get; set; }
    }
}