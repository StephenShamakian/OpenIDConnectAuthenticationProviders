﻿using System;
using System.Threading.Tasks;
using Nancy;
using Nancy.Cookies;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web
{
    public abstract class UserAuthenticationAction<TStore> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
    {
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        readonly IAuthorizationEndpointUrlBuilder urlBuilder;

        protected readonly TStore ConfigurationStore;
        protected readonly IApiActionResponseCreator ResponseCreator;

        protected UserAuthenticationAction(
            TStore configurationStore,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, 
            IAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionResponseCreator responseCreator)
        {
            ResponseCreator = responseCreator;
            ConfigurationStore = configurationStore;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.urlBuilder = urlBuilder;
        }

        public async Task<Response> ExecuteAsync(NancyContext context, IResponseFormatter response)
        {
            if (!ConfigurationStore.GetIsEnabled())
                return ResponseCreator.AsStatusCode(HttpStatusCode.BadRequest);

            var postLoginRedirectTo = context.Request.Query["redirectTo"];
            var state = "~/app";
            if (!string.IsNullOrWhiteSpace(postLoginRedirectTo))
                state = postLoginRedirectTo;
            var nonce = Nonce.Generate();

            var issuer = ConfigurationStore.GetIssuer();
            var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(issuer);
            var url = urlBuilder.Build(context.Request.Url.SiteBase, issuerConfig, nonce, state);

            return response.AsRedirect(url)
                .WithCookie(new NancyCookie("s", State.Protect(state), true, false, DateTime.UtcNow.AddMinutes(20)))
                .WithCookie(new NancyCookie("n", Nonce.Protect(nonce), true, false, DateTime.UtcNow.AddMinutes(20)));
        }
    }
}