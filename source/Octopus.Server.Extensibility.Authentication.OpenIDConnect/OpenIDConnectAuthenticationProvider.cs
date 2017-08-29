﻿using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Extensions.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Identities;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect
{
    public abstract class OpenIDConnectAuthenticationProvider<TStore> : IAuthenticationProviderWithGroupSupport, IUseAuthenticationIdentities
        where TStore : IOpenIDConnectConfigurationStore
    {
        readonly ILog log;

        protected OpenIDConnectAuthenticationProvider(ILog log, TStore configurationStore)
        {
            this.log = log;
            ConfigurationStore = configurationStore;
        }

        protected TStore ConfigurationStore { get; }

        public abstract string IdentityProviderName { get; }

        public bool IsEnabled => ConfigurationStore.GetIsEnabled() && IsProviderConfigComplete();

        bool IsProviderConfigComplete()
        {
            var isComplete = true;
            foreach (var reason in ReasonsWhyConfigIsIncomplete())
            {
                log.Warn(reason);
                isComplete = false;
            }
            return isComplete;
        }

        protected abstract IEnumerable<string> ReasonsWhyConfigIsIncomplete();

        public bool SupportsPasswordManagement => false;

        public string AuthenticateUri => $"/api/users/authenticate/{ConfigurationStore.ConfigurationSettingsName}";

        protected abstract string LoginLinkHtml();

        public AuthenticationProviderElement GetAuthenticationProviderElement()
        {
            var authenticationProviderElement = new AuthenticationProviderElement
            {
                Name = IdentityProviderName,
                LinkHtml = LoginLinkHtml()
            };
            authenticationProviderElement.Links.Add(AuthenticationProviderElement.AuthenticateLinkName, "~" + AuthenticateUri);

            return authenticationProviderElement;
        }

        public AuthenticationProviderThatSupportsGroups GetGroupLookupElement()
        {
            return new AuthenticationProviderThatSupportsGroups
            {
                Name = IdentityProviderName,
                IsRoleBased = true,
                SupportsGroupLookup = false
            };
        }

        public string[] GetAuthenticationUrls()
        {
            return new[] { AuthenticateUri, ConfigurationStore.RedirectUri };
        }

        public IdentityMetadataResource GetMetadata()
        {
            return new IdentityMetadataResource
            {
                ProviderName = IdentityProviderName,
                ClaimDescriptors = new[]
                {
                    new ClaimDescriptor { Type = ClaimDescriptor.DisplayNameClaimType, Label = "Display name", IsIdentifyingClaim = false},
                    new ClaimDescriptor { Type = ClaimDescriptor.EmailClaimType, Label = "Email address", IsIdentifyingClaim = true}
                }
            };
        }
    }
}