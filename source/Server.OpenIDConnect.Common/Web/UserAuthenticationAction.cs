using System;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Server.MessageContracts.Features.BlobStorage;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticationAction<TStore> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
    {
        static readonly BadRequestRegistration Disabled = new BadRequestRegistration("This authentication provider is disabled.");
        static readonly BadRequestRegistration PotentialOpenDirect = new BadRequestRegistration("Request not allowed, due to potential Open Redirection attack");
        static readonly BadRequestRegistration LoginFailed = new BadRequestRegistration("Login failed. Please see the Octopus Server logs for more details.");
        static readonly OctopusJsonRegistration<LoginRedirectLinkResponseModel> Result = new OctopusJsonRegistration<LoginRedirectLinkResponseModel>();

        readonly ISystemLog log;
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        readonly IAuthorizationEndpointUrlBuilder urlBuilder;

        protected readonly TStore ConfigurationStore;
        readonly IApiActionModelBinder modelBinder;
        readonly IAuthenticationConfigurationStore authenticationConfigurationStore;
        readonly IMediator mediator;

        protected UserAuthenticationAction(
            ISystemLog log,
            TStore configurationStore,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore,
            IMediator mediator)
        {
            this.log = log;
            this.modelBinder = modelBinder;
            this.authenticationConfigurationStore = authenticationConfigurationStore;
            this.mediator = mediator;
            ConfigurationStore = configurationStore;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.urlBuilder = urlBuilder;
        }

        public async Task<IOctoResponseProvider> ExecuteAsync(IOctoRequest request)
        {
            if (ConfigurationStore.GetIsEnabled() == false)
            {
                log.Warn($"{ConfigurationStore.ConfigurationSettingsName} user authentication API was called while the provider was disabled.");
                return Disabled.Response();
            }

            var model = modelBinder.Bind<LoginRedirectLinkRequestModel>();

            // If the login state object was passed use it, otherwise fall back to a safe default:
            //   1. Redirecting to the root of the local web site
            //   2. Setting the Cookie.Secure flag according to the current request
            var state = model.State ?? new LoginState{RedirectAfterLoginTo = "/", UsingSecureConnection = request.IsHttps};

            // Prevent Open Redirection attacks by ensuring the redirect after successful login is somewhere we trust (local origin or a trusted remote origin)
            var whitelist = authenticationConfigurationStore.GetTrustedRedirectUrls();
            if (!Requests.IsLocalUrl(state.RedirectAfterLoginTo, whitelist))
            {
                log.WarnFormat("Prevented potential Open Redirection attack on an authentication request, to the non-local url {0}", state.RedirectAfterLoginTo);
                return PotentialOpenDirect.Response();
            }

            // Finally, provide the client with the information it requires to initiate the redirect to the external identity provider
            try
            {
                var issuer = ConfigurationStore.GetIssuer() ?? string.Empty;
                var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(issuer);

                // TODO: Remove the explicit check for OctopusID once OctopusID supports auth code flow
                var response = ConfigurationStore.HasClientSecret && ConfigurationStore.ConfigurationSettingsName != "OctopusID"
                    ? await BuildAuthorizationCodePkceResponse(model, new LoginStateWithRequestId(state.RedirectAfterLoginTo, state.UsingSecureConnection, Guid.NewGuid()), issuerConfig)
                    : BuildHybridResponse(model, state, issuerConfig);

                return response;
            }
            catch (ArgumentException ex)
            {
                log.Error(ex);
                return LoginFailed.Response(ex.Message);
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return LoginFailed.Response();
            }
        }

        async Task<IOctoResponseProvider> BuildAuthorizationCodePkceResponse(LoginRedirectLinkRequestModel model, LoginStateWithRequestId state, IssuerConfiguration issuerConfig)
        {
            var codeVerifier = Pkce.GenerateCodeVerifier();
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
            await InsertPkceBlob(new PkceBlob(state.RequestId, codeVerifier, DateTimeOffset.UtcNow), state.RequestId.ToString(), cts.Token);

            var codeChallenge = Pkce.GenerateCodeChallenge(codeVerifier);
            var stateString = JsonConvert.SerializeObject(state);
            var url = urlBuilder.Build(model.ApiAbsUrl, issuerConfig, state: stateString, codeChallenge: codeChallenge);
            var response = Result.Response(new LoginRedirectLinkResponseModel {ExternalAuthenticationUrl = url})
                .WithCookie(new OctoCookie(UserAuthConstants.OctopusStateCookieName, State.Protect(stateString)) {HttpOnly = true, Secure = state.UsingSecureConnection, Expires = DateTimeOffset.UtcNow.AddMinutes(20)});
            return response;
        }

        // For backwards compatibility - if no client secret is specified then the implicit flow will attempt to be used
        IOctoResponseProvider BuildHybridResponse(LoginRedirectLinkRequestModel model, LoginState state, IssuerConfiguration issuerConfig)
        {
            // Use a non-deterministic nonce to prevent replay attacks
            var nonce = Nonce.GenerateUrlSafeNonce();
            var stateString = JsonConvert.SerializeObject(state);
            var url = urlBuilder.Build(model.ApiAbsUrl, issuerConfig, nonce, stateString);
            // These cookies are used to validate the data returned from the external identity provider - this prevents tampering
            var response = Result.Response(new LoginRedirectLinkResponseModel {ExternalAuthenticationUrl = url})
                .WithCookie(new OctoCookie(UserAuthConstants.OctopusStateCookieName, State.Protect(stateString)) {HttpOnly = true, Secure = state.UsingSecureConnection, Expires = DateTimeOffset.UtcNow.AddMinutes(20)})
                .WithCookie(new OctoCookie(UserAuthConstants.OctopusNonceCookieName, Nonce.Protect(nonce)) {HttpOnly = true, Secure = state.UsingSecureConnection, Expires = DateTimeOffset.UtcNow.AddMinutes(20)});
            return response;
        }

        async Task InsertPkceBlob(PkceBlob blob, string requestId, CancellationToken cancellationToken)
        {
            await mediator.Do(
                new PutBlobCommand(ConfigurationStore.ConfigurationSettingsName, requestId, JsonSerializer.SerializeToUtf8Bytes(blob)),
                cancellationToken);
        }
    }
}