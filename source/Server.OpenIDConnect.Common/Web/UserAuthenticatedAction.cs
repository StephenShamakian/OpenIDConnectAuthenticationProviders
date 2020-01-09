using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Octopus.Data.Model.User;
using Octopus.Data.Storage.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;
using Octopus.Server.Extensibility.Authentication.Storage.User;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticatedAction<TStore, TAuthTokenHandler, TIdentityCreator> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthTokenHandler : IAuthTokenHandler
        where TIdentityCreator : IIdentityCreator
    {
        readonly ISystemLog log;
        readonly TAuthTokenHandler authTokenHandler;
        readonly IPrincipalToUserResourceMapper principalToUserResourceMapper;
        readonly IUpdateableUserStore userStore;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly TIdentityCreator identityCreator;
        readonly IClock clock;
        readonly IUrlEncoder encoder;

        protected readonly TStore ConfigurationStore;

        protected UserAuthenticatedAction(
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
            IUrlEncoder encoder)
        {
            this.log = log;
            this.authTokenHandler = authTokenHandler;
            this.principalToUserResourceMapper = principalToUserResourceMapper;
            this.userStore = userStore;
            ConfigurationStore = configurationStore;
            this.authCookieCreator = authCookieCreator;
            this.loginTracker = loginTracker;
            this.sleep = sleep;
            this.identityCreator = identityCreator;
            this.clock = clock;
            this.encoder = encoder;
        }

        protected abstract string ProviderName { get; }

        public async Task ExecuteAsync(OctoContext context)
        {
            // Step 1: Try and get all of the details from the request making sure there are no errors passed back from the external identity provider
            var principalContainer = await authTokenHandler.GetPrincipalAsync(context.Request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateStringFromRequest);
            var principal = principalContainer.Principal;
            if (principal == null || !string.IsNullOrEmpty(principalContainer.Error))
            {
                BadRequest(context, $"The response from the external identity provider contained an error: {principalContainer.Error}");
                return;
            }
            
            // Step 2: Validate the state object we passed wasn't tampered with
            const string stateDescription = "As a security precaution, Octopus ensures the state object returned from the external identity provider matches what it expected.";
            var expectedStateHash = string.Empty;
            if (context.Request.Cookies.ContainsKey(UserAuthConstants.OctopusStateCookieName))
                expectedStateHash = encoder.UrlDecode(context.Request.Cookies[UserAuthConstants.OctopusStateCookieName]);
            if (string.IsNullOrWhiteSpace(expectedStateHash))
            {
                BadRequest(context, $"User login failed: Missing State Hash Cookie. {stateDescription} In this case the Cookie containing the SHA256 hash of the state object is missing from the request.");
                return;
            }

            var stateFromRequestHash = State.Protect(stateStringFromRequest);
            if (stateFromRequestHash != expectedStateHash)
            {
                BadRequest(context, $"User login failed: Tampered State. {stateDescription} In this case the state object looks like it has been tampered with. The state object is '{stateStringFromRequest}'. The SHA256 hash of the state was expected to be '{expectedStateHash}' but was '{stateFromRequestHash}'.");
                return;
            }

            var stateFromRequest = JsonConvert.DeserializeObject<LoginState>(stateStringFromRequest);

            // Step 3: Validate the nonce is as we expected to prevent replay attacks
            const string nonceDescription = "As a security precaution to prevent replay attacks, Octopus ensures the nonce returned in the claims from the external identity provider matches what it expected.";

            var expectedNonceHash = string.Empty;
            if (context.Request.Cookies.ContainsKey(UserAuthConstants.OctopusNonceCookieName))
                expectedNonceHash = encoder.UrlDecode(context.Request.Cookies[UserAuthConstants.OctopusNonceCookieName]);

            if (string.IsNullOrWhiteSpace(expectedNonceHash))
            {
                BadRequest(context, $"User login failed: Missing Nonce Hash Cookie. {nonceDescription} In this case the Cookie containing the SHA256 hash of the nonce is missing from the request.");
                return;
            }

            var nonceFromClaims = principal.Claims.FirstOrDefault(c => c.Type == "nonce");
            if (nonceFromClaims == null)
            {
                BadRequest(context, $"User login failed: Missing Nonce Claim. {nonceDescription} In this case the 'nonce' claim is missing from the security token.");
                return;
            }

            var nonceFromClaimsHash = Nonce.Protect(nonceFromClaims.Value);
            if (nonceFromClaimsHash != expectedNonceHash)
            {
                BadRequest(context, $"User login failed: Tampered Nonce. {nonceDescription} In this case the nonce looks like it has been tampered with or reused. The nonce is '{nonceFromClaims}'. The SHA256 hash of the state was expected to be '{expectedNonceHash}' but was '{nonceFromClaimsHash}'.");
                return;
            }

            // Step 4: Now the integrity of the request has been validated we can figure out which Octopus User this represents
            var authenticationCandidate = principalToUserResourceMapper.MapToUserResource(principal);

            // Step 4a: Check if this authentication attempt is already being banned
            var action = loginTracker.BeforeAttempt(authenticationCandidate.Username, context.Request.Host);
            if (action == InvalidLoginAction.Ban)
            {
                BadRequest(context, "You have had too many failed login attempts in a short period of time. Please try again later.");
                return;
            }

            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1)))
            {
                // Step 4b: Try to get or create a the Octopus User this external identity represents
                var userResult = GetOrCreateUser(authenticationCandidate, principalContainer.ExternalGroupIds, cts.Token);
                if (userResult.Succeeded)
                {
                    loginTracker.RecordSucess(authenticationCandidate.Username, context.Request.Host);

                    var authCookies = authCookieCreator.CreateAuthCookies(userResult.User.IdentificationToken, SessionExpiry.TwentyDays, context.Request.IsHttps, stateFromRequest.UsingSecureConnection);

                    foreach (var cookie in authCookies)
                    {
                        context.Response.WithCookie(cookie);
                    }

                    if (!userResult.User.IsActive)
                    {
                        BadRequest(context, 
                            $"The Octopus User Account '{authenticationCandidate.Username}' has been disabled by an Administrator. If you believe this to be a mistake, please contact your Octopus Administrator to have your account re-enabled.");
                        return;
                    }

                    if (userResult.User.IsService)
                    {
                        BadRequest(context, 
                            $"The Octopus User Account '{authenticationCandidate.Username}' is a Service Account, which are prevented from using Octopus interactively. Service Accounts are designed to authorize external systems to access the Octopus API using an API Key.");
                        return;
                    }

                    context.Response.Redirect(stateFromRequest.RedirectAfterLoginTo)
                        .WithHeader("Expires", new string[] { DateTime.UtcNow.AddYears(1).ToString("R", DateTimeFormatInfo.InvariantInfo) })
                        .WithCookie(new OctoCookie {Name = UserAuthConstants.OctopusStateCookieName, Value = Guid.NewGuid().ToString(), HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue})
                        .WithCookie(new OctoCookie {Name = UserAuthConstants.OctopusNonceCookieName, Value = Guid.NewGuid().ToString(), HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue});
                    return;
                }


                // Step 5: Handle other types of failures
                loginTracker.RecordFailure(authenticationCandidate.Username, context.Request.Host);

                // Step 5a: Slow this potential attacker down a bit since they seem to keep failing
                if (action == InvalidLoginAction.Slow)
                {
                    sleep.For(1000);
                }

                BadRequest(context, $"User login failed: {userResult.FailureReason}");
            }
        }

        void BadRequest(OctoContext context, string message)
        {
            log.Error(message);
            context.Response.BadRequest(message);
        }

        UserCreateResult GetOrCreateUser(UserResource userResource, string[] groups, CancellationToken cancellationToken)
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
                    return new UserCreateResult(user);
                }

                identity = user.Identities.FirstOrDefault(x => x.IdentityProviderName == ProviderName && x.Claims[ClaimDescriptor.EmailClaimType].Value == userResource.EmailAddress);
                if (identity != null)
                {
                    return new UserCreateResult(userStore.UpdateIdentity(user.Id, identityToMatch, cancellationToken));
                }

                return new UserCreateResult(userStore.AddIdentity(user.Id, identityToMatch, cancellationToken));
            }

            if (!ConfigurationStore.GetAllowAutoUserCreation())
                return new AuthenticationUserCreateResult("User could not be located and auto user creation is not enabled.");

            var userResult = userStore.Create(
                userResource.Username, 
                userResource.DisplayName, 
                userResource.EmailAddress,
                cancellationToken,
                new ProviderUserGroups { IdentityProviderName = ProviderName, GroupIds = groups },
                new[] { identityToMatch });

            return userResult;
        }

        bool MatchesProviderAndExternalId(UserResource userResource, Identity x)
        {
            return x.IdentityProviderName == ProviderName && x.Claims.ContainsKey(IdentityCreator.ExternalIdClaimType) && x.Claims[IdentityCreator.ExternalIdClaimType].Value == userResource.ExternalId;
        }

        Identity NewIdentity(UserResource userResource)
        {
            return identityCreator.Create(
                userResource.EmailAddress,
                userResource.DisplayName,
                userResource.ExternalId);
        }
    }
}
