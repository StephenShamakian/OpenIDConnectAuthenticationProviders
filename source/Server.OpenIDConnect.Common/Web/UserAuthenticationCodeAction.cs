using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Octopus.Data;
using Octopus.Data.Model.User;
using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.Results;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticationCodeAction<TStore, TAuthTokenHandler, TIdentityCreator> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthTokenHandler : IAuthTokenHandler
        where TIdentityCreator : IIdentityCreator
    {
        static readonly BadRequestRegistration LoginFailed = new BadRequestRegistration("User login failed");
        static readonly RedirectRegistration Redirect = new RedirectRegistration("Redirects back to the Octopus portal");
        static readonly RequiredQueryParameterProperty<string> Code = new RequiredQueryParameterProperty<string>("code", "Authorization code provided by the IdP");
        static readonly OptionalQueryParameterProperty<string> State = new OptionalQueryParameterProperty<string>("state", "The state value associated with the authentication session");

        readonly ISystemLog log;
        readonly TAuthTokenHandler authTokenHandler;
        readonly IPrincipalToUserResourceMapper principalToUserResourceMapper;
        readonly IUpdateableUserStore userStore;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly TIdentityCreator identityCreator;
        readonly IClock clock;
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;

        protected UserAuthenticationCodeAction(
            ISystemLog log,
            TAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            TStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            TIdentityCreator identityCreator,
            IClock clock,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer)
        {
            this.log = log;
            this.authTokenHandler = authTokenHandler;
            this.principalToUserResourceMapper = principalToUserResourceMapper;
            this.userStore = userStore;
            this.authCookieCreator = authCookieCreator;
            this.loginTracker = loginTracker;
            this.sleep = sleep;
            this.identityCreator = identityCreator;
            this.clock = clock;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            ConfigurationStore = configurationStore;
        }

        protected abstract string ProviderName { get; }
        protected TStore ConfigurationStore { get; }

        public async Task<IOctoResponseProvider> ExecuteAsync(IOctoRequest request)
        {
            return await request.HandleAsync(Code, State, (code, state) => Handle(state, code, request));
        }

        async Task<IOctoResponseProvider> Handle(string code, string state, IOctoRequest request)
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                return BadRequest("No authorization code was provided.");
            }

            var redirectUri = $"{request.Scheme}://{request.Host}{ConfigurationStore.RedirectUri}";
            var response = await RequestAuthToken(code, redirectUri);

            // Step 1: Try and get all of the details from the request making sure there are no errors passed back from the external identity provider
            var principalContainer = await authTokenHandler.GetPrincipalAsync(response, out var stateStringFromRequest);
            var principal = principalContainer.Principal;
            if (principal == null || !string.IsNullOrEmpty(principalContainer.Error))
            {
                return BadRequest($"The response from the external identity provider contained an error: {principalContainer.Error}");
            }

            var stateFromRequest = JsonConvert.DeserializeObject<LoginState>(stateStringFromRequest ?? state ?? string.Empty);

            // Step 3: Now the integrity of the request has been validated we can figure out which Octopus User this represents
            var authenticationCandidate = principalToUserResourceMapper.MapToUserResource(principal);
            if (authenticationCandidate.Username == null)
            {
                return BadRequest("Unable to determine username.");
            }

            // Step 3a: Check if this authentication attempt is already being banned
            var action = loginTracker.BeforeAttempt(authenticationCandidate.Username, request.Host);
            if (action == InvalidLoginAction.Ban)
            {
                return BadRequest("You have had too many failed login attempts in a short period of time. Please try again later.");
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                // Step 3b: Try to get or create a the Octopus User this external identity represents
                var userResult = GetOrCreateUser(authenticationCandidate, principalContainer.ExternalGroupIds, cts.Token);
                if (userResult is ISuccessResult<IUser> successResult)
                {
                    loginTracker.RecordSucess(authenticationCandidate.Username, request.Host);

                    if (!successResult.Value.IsActive)
                    {
                        return BadRequest($"The Octopus User Account '{authenticationCandidate.Username}' has been disabled by an Administrator. If you believe this to be a mistake, please contact your Octopus Administrator to have your account re-enabled.");
                    }

                    if (successResult.Value.IsService)
                    {
                        return BadRequest($"The Octopus User Account '{authenticationCandidate.Username}' is a Service Account, which are prevented from using Octopus interactively. Service Accounts are designed to authorize external systems to access the Octopus API using an API Key.");
                    }

                    var octoResponse = Redirect.Response(stateFromRequest.RedirectAfterLoginTo)
                        .WithHeader("Expires", new[] {DateTime.UtcNow.AddYears(1).ToString("R", DateTimeFormatInfo.InvariantInfo)})
                        .WithCookie(new OctoCookie(UserAuthConstants.OctopusStateCookieName, Guid.NewGuid().ToString()) {HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue})
                        .WithCookie(new OctoCookie(UserAuthConstants.OctopusNonceCookieName, Guid.NewGuid().ToString()) {HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue});

                    var authCookies = authCookieCreator.CreateAuthCookies(successResult.Value.IdentificationToken, SessionExpiry.TwentyDays, request.IsHttps, stateFromRequest.UsingSecureConnection);

                    foreach (var cookie in authCookies)
                    {
                        octoResponse = octoResponse.WithCookie(cookie);
                    }

                    return octoResponse;
                }

                // Step 4: Handle other types of failures
                loginTracker.RecordFailure(authenticationCandidate.Username, request.Host);

                // Step 4a: Slow this potential attacker down a bit since they seem to keep failing
                if (action == InvalidLoginAction.Slow)
                {
                    sleep.For(1000);
                }

                return BadRequest($"User login failed: {((IFailureResult) userResult).ErrorString}");
            }
        }

        async Task<IDictionary<string, string?>> RequestAuthToken(string code, string redirectUri)
        {
            var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(ConfigurationStore.GetIssuer() ?? string.Empty);
            using var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, issuerConfig.TokenEndpoint);
            var formValues = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = ConfigurationStore.GetClientId()!,
                ["client_secret"] = ConfigurationStore.GetClientSecret()!.Value
            };
            request.Content = new FormUrlEncodedContent(formValues);
            var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            var body = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<Dictionary<string, string?>>(body);
        }

        IOctoResponseProvider BadRequest(string message)
        {
            log.Error(message);
            return LoginFailed.Response(message);
        }

        IResultFromExtension<IUser> GetOrCreateUser(UserResource userResource, string[] groups, CancellationToken cancellationToken)
        {
            var identityToMatch = NewIdentity(userResource);

            var matchingUsers = userStore.GetByIdentity(identityToMatch);
            if (matchingUsers.Count() > 1)
                throw new Exception("There are multiple users with this identity. OpenID Connect identity providers do not support users with duplicate email addresses. Please remove any duplicate users, or make the email addresses unique.");
            var user = matchingUsers.SingleOrDefault();

            if (user != null)
            {
                userStore.SetSecurityGroupIds(ProviderName, user.Id, groups, clock.GetUtcTime());

                var identity = user.Identities.FirstOrDefault(x => MatchesProviderAndExternalId(userResource, x));
                if (identity != null)
                {
                    return ResultFromExtension<IUser>.Success(user);
                }

                identity = user.Identities.FirstOrDefault(x => x.IdentityProviderName == ProviderName && x.Claims[ClaimDescriptor.EmailClaimType].Value == userResource.EmailAddress);
                if (identity != null)
                {
                    return ResultFromExtension<IUser>.Success(userStore.UpdateIdentity(user.Id, identityToMatch, cancellationToken));
                }

                return ResultFromExtension<IUser>.Success(userStore.AddIdentity(user.Id, identityToMatch, cancellationToken));
            }

            if (!ConfigurationStore.GetAllowAutoUserCreation())
                return ResultFromExtension<IUser>.Failed("User could not be located and auto user creation is not enabled.");

            var userResult = userStore.Create(
                userResource.Username ?? string.Empty,
                userResource.DisplayName ?? string.Empty,
                userResource.EmailAddress ?? string.Empty,
                cancellationToken,
                new ProviderUserGroups { IdentityProviderName = ProviderName, GroupIds = groups },
                new[] { identityToMatch });
            if (userResult is IFailureResult failureResult)
                return ResultFromExtension<IUser>.Failed(failureResult.Errors);
            return ResultFromExtension<IUser>.Success(((ISuccessResult<IUser>)userResult).Value);
        }

        bool MatchesProviderAndExternalId(UserResource userResource, Identity x)
        {
            return x.IdentityProviderName == ProviderName && x.Claims.ContainsKey(IdentityCreator.ExternalIdClaimType) && x.Claims[IdentityCreator.ExternalIdClaimType].Value == userResource.ExternalId;
        }

        Identity NewIdentity(UserResource userResource)
        {
            return identityCreator.Create(userResource);
        }
    }
}
