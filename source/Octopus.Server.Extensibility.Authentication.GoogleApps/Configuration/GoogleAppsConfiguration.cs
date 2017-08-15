using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    public class GoogleAppsConfiguration : OpenIDConnectConfiguration
    {
        public GoogleAppsConfiguration() : base("GoogleApps", "Octopus Deploy")
        {
            Issuer = "https://accounts.google.com";
            LoginLinkLabel = "Sign in with your Google Apps account";
        }

        public string HostedDomain { get; set; }
    }
}