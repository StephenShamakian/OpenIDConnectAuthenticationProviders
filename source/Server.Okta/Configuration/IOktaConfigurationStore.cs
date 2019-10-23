﻿using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    public interface IOktaConfigurationStore : IOpenIDConnectConfigurationWithRoleStore<OktaConfiguration>
    {
        string GetUsernameClaimType();
        void SetUsernameClaimType(string usernameClaimType);
    }
}