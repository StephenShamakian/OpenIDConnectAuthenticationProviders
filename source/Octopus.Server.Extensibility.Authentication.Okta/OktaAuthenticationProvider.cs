using System;
using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;

namespace Octopus.Server.Extensibility.Authentication.Okta
{
    public class OktaAuthenticationProvider : OpenIDConnectAuthenticationProvider<IOktaConfigurationStore>
    {
        public OktaAuthenticationProvider(ILog log, IOktaConfigurationStore configurationStore) : base(log, configurationStore)
        {
        }

        public override string IdentityProviderName => "Okta";

        protected override IEnumerable<string> ReasonsWhyConfigIsIncomplete()
        {
            var issuer = ConfigurationStore.GetIssuer();
            if (string.IsNullOrWhiteSpace(issuer))
                yield return $"No {IdentityProviderName} issuer specified";
            if (!Uri.IsWellFormedUriString(issuer, UriKind.Absolute))
                yield return $"The {IdentityProviderName} issuer must be an absolute URI (expected format: https://dev-[customer id]-admin.oktapreview.com)";
            if (string.IsNullOrWhiteSpace(ConfigurationStore.GetClientId()))
                yield return $"No {IdentityProviderName} Client ID specified";
        }

        protected override string LoginLinkHtml()
        {
            return "<okta-auth-provider provider='provider' should-auto-login='shouldAutoLogin' is-submitting='isSubmitting' handle-sign-in-error='handleSignInError'></okta-auth-provider>";
        }
    }
}
