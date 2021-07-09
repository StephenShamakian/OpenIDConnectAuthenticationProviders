using Octopus.Data.Model;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public interface IOpenIDConnectConfiguration
    {
        string? Issuer { get; set; }
        string? ClientId { get; set; }
        SensitiveString? ClientSecret { get; set; }
        string? Scope { get; set; }
        string? NameClaimType { get; set; }
        bool AllowAutoUserCreation { get; set; }
    }
}