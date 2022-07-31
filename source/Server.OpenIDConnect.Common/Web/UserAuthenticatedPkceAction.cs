using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Octopus.Data;
using Octopus.Data.Model.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Server.MessageContracts.Features.BlobStorage;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticatedPkceAction<TStore, TAuthTokenHandler, TIdentityCreator> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthTokenHandler : IAuthTokenHandler
        where TIdentityCreator : IIdentityCreator
    {
        readonly RequiredQueryParameterProperty<string> codeParameter = new("code", "Authorization code provided by the identity provider");
        readonly OptionalQueryParameterProperty<string> stateParameter = new("state", "The state value associated with the authentication session");

        readonly ISystemLog log;
        readonly TAuthTokenHandler authTokenHandler;
        readonly IPrincipalToUserResourceMapper principalToUserResourceMapper;
        readonly TStore configurationStore;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly TIdentityCreator identityCreator;
        readonly IUrlEncoder encoder;
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        readonly IMediator mediator;
        readonly IUserService userService;

        protected UserAuthenticatedPkceAction(ISystemLog log,
            TAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            TStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            TIdentityCreator identityCreator,
            IUrlEncoder encoder,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IMediator mediator,
            IUserService userService)
        {
            this.log = log;
            this.authTokenHandler = authTokenHandler;
            this.principalToUserResourceMapper = principalToUserResourceMapper;
            this.configurationStore = configurationStore;
            this.authCookieCreator = authCookieCreator;
            this.loginTracker = loginTracker;
            this.sleep = sleep;
            this.identityCreator = identityCreator;
            this.encoder = encoder;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.mediator = mediator;
            this.userService = userService;
        }

        protected abstract string ProviderName { get; }

        public async Task<IOctoResponseProvider> ExecuteAsync(IOctoRequest request)
        {
            return await request.HandleAsync(codeParameter, stateParameter, (code, state) => Handle(code, state, request));
        }

        async Task<IOctoResponseProvider> Handle(string code, string state, IOctoRequest request)
        {
            var stateFromRequest = JsonConvert.DeserializeObject<LoginStateWithRequestId>(state)!;
            
            var host = request.Headers.ContainsKey("Host") ? request.Headers["Host"].Single() : request.Host;
            var scheme = stateFromRequest.UsingSecureConnection ? "https" : "http";
            var redirectUri = $"{scheme}://{host}{configurationStore.RedirectUri}";
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
            var codeVerifier = await GetCodeVerifier(stateFromRequest.RequestId, cts.Token);
            var response = await RequestAuthToken(code, redirectUri, codeVerifier);

            var authServerResponseHandler = new AuthServerResponseHandler<TAuthTokenHandler>(
                authTokenHandler,
                principalToUserResourceMapper,
                authCookieCreator,
                loginTracker,
                sleep,
                encoder);
            try
            {
                var principalContainer = await authServerResponseHandler.GetDetailsFromRequestEnsuringNoErrors(response);

                authServerResponseHandler.ValidateState(request, state);

                var authenticationCandidate = authServerResponseHandler.MapPrincipalToUserResource(principalContainer);
                var action = authServerResponseHandler.CheckIfAuthenticationAttemptIsBanned(authenticationCandidate.Username!, request.Host);

                var userResult = userService.GetOrCreateUser(authenticationCandidate, principalContainer.ExternalGroupIds, ProviderName, identityCreator, configurationStore.GetAllowAutoUserCreation(), cts.Token);
                if (userResult is ISuccessResult<IUser> successResult)
                {
                    return authServerResponseHandler.Success(request, successResult, authenticationCandidate.Username!, stateFromRequest);
                }

                authServerResponseHandler.Failure(authenticationCandidate.Username!, request.Host, action);
                throw new FailedAuthenticationException($"User login failed: {((IFailureResult) userResult).ErrorString}");
            }
            catch (FailedAuthenticationException e)
            {
                return UserAuthenticatedValidator.BadRequest(log, e.Message);
            }
        }

        async Task<IDictionary<string, string?>> RequestAuthToken(string code, string redirectUri, string codeVerifier)
        {
            var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(configurationStore.GetIssuer() ?? string.Empty);
            using var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, issuerConfig.TokenEndpoint);

            var formValues = new Dictionary<string, string>
            {
                ["grant_type"] = OpenIDConnectConfiguration.AuthCodeGrantType,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = configurationStore.GetClientId()!,
                ["client_secret"] = configurationStore.GetClientSecret()!.Value,
                ["code_verifier"] = codeVerifier
            };
            request.Content = new FormUrlEncodedContent(formValues!);
            var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            var body = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<Dictionary<string, string?>>(body)!;
        }

        async Task<string> GetCodeVerifier(Guid requestId, CancellationToken cancellationToken)
        {
            var blobs = await GetAllPkceBlobsBelongingToExtension(cancellationToken);
            var currentBlob = blobs.SingleOrDefault(b => b.RequestId == requestId);

            if (currentBlob == null)
            {
                throw new TimeoutException("Your session has expired. Please try signing in again.");
            }

            await DeleteCurrentAndExpiredBlobs(blobs, requestId, cancellationToken);
            return currentBlob.CodeVerifier;
        }

        async Task<List<PkceBlob>> GetAllPkceBlobsBelongingToExtension(CancellationToken cancellationToken)
        {
            var allBlobsBelongingToExtension = await mediator.Request(new GetAllBlobsRequest(configurationStore.ConfigurationSettingsName), cancellationToken);
            var pkceBlobs = new List<PkceBlob>();
            foreach (var blob in allBlobsBelongingToExtension.Blobs)
            {
                try
                {
                    pkceBlobs.Add(JsonConvert.DeserializeObject<PkceBlob>(Encoding.UTF8.GetString(blob))!);
                }
                catch (Exception e)
                {
                    log.Warn($"Could not parse blob. This is most likely not a PkceBlob and will be skipped: {e.Message}");
                }
            }
            return pkceBlobs;
        }

        async Task DeleteCurrentAndExpiredBlobs(IEnumerable<PkceBlob> blobs, Guid requestId, CancellationToken cancellationToken)
        {
            bool BlobIsCurrentOrIsExpired(PkceBlob blob) => blob.RequestId == requestId || DateTimeOffset.UtcNow.Subtract(blob.TimeStamp).TotalMinutes > 5;

            foreach (var blob in blobs.Where(BlobIsCurrentOrIsExpired))
            {
                await DeleteBlob(blob, cancellationToken);
            }
        }

        async Task DeleteBlob(PkceBlob blob, CancellationToken cancellationToken)
        {
            await mediator.Do(new DeleteBlobCommand(configurationStore.ConfigurationSettingsName, blob.RequestId.ToString()), cancellationToken);
        }
    }
}
