using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Octopus.Data;
using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public class AuthServerResponseHandler<TAuthTokenHandler> where TAuthTokenHandler : IAuthTokenHandler
    {
        readonly TAuthTokenHandler authTokenHandler;
        readonly IPrincipalToUserResourceMapper principalToUserResourceMapper;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly IUrlEncoder encoder;

        public AuthServerResponseHandler(
            TAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IUrlEncoder encoder)
        {
            this.authTokenHandler = authTokenHandler;
            this.principalToUserResourceMapper = principalToUserResourceMapper;
            this.authCookieCreator = authCookieCreator;
            this.loginTracker = loginTracker;
            this.sleep = sleep;
            this.encoder = encoder;
        }

        public async Task<ClaimsPrincipalContainer> GetDetailsFromRequestEnsuringNoErrors(IDictionary<string, string?> requestForm)
        {
            var principalContainer = await authTokenHandler.GetPrincipalAsync(requestForm, out _);
            UserAuthenticatedValidator.ValidatePrincipalContainer(principalContainer);

            return principalContainer;
        }

        public void ValidateState(IOctoRequest request, string state)
        {
            var expectedStateHash = request.Cookies.ContainsKey(UserAuthConstants.OctopusStateCookieName)
                ? encoder.UrlDecode(request.Cookies[UserAuthConstants.OctopusStateCookieName])
                : string.Empty;
            UserAuthenticatedValidator.ValidateExpectedStateHashIsNotEmpty(expectedStateHash);
            UserAuthenticatedValidator.ValidateReceivedStateIsEqualToExpectedState(State.Protect(state), expectedStateHash, state);
        }

        public void ValidateNonce(IOctoRequest request, ClaimsPrincipalContainer principalContainer)
        {
            var expectedNonceHash = string.Empty;
            if (request.Cookies.ContainsKey(UserAuthConstants.OctopusNonceCookieName))
                expectedNonceHash = encoder.UrlDecode(request.Cookies[UserAuthConstants.OctopusNonceCookieName]);

            UserAuthenticatedValidator.ValidateExpectedNonceHashIsNotEmpty(expectedNonceHash);

            var nonceFromClaims = principalContainer.Principal!.Claims.FirstOrDefault(c => c.Type == "nonce");
            UserAuthenticatedValidator.ValidateNonceFromClaimsIsNotEmpty(nonceFromClaims);

            var nonceFromClaimsHash = Nonce.Protect(nonceFromClaims!.Value);
            UserAuthenticatedValidator.ValidateNonceFromClaimsHashIsEqualToExpectedNonce(expectedNonceHash, nonceFromClaimsHash, nonceFromClaims);
        }

        public UserResource MapPrincipalToUserResource(ClaimsPrincipalContainer principalContainer)
        {
            var authenticationCandidate = principalToUserResourceMapper.MapToUserResource(principalContainer.Principal!);
            UserAuthenticatedValidator.ValidateUsername(authenticationCandidate.Username);
            return authenticationCandidate;
        }

        public InvalidLoginAction CheckIfAuthenticationAttemptIsBanned(string username, string host)
        {
            var action = loginTracker.BeforeAttempt(username, host);
            UserAuthenticatedValidator.ValidateUserIsNotBanned(action);
            return action;
        }

        public IOctoResponseProvider Success(IOctoRequest request, ISuccessResult<IUser> successResult, string username, LoginState state)
        {
            loginTracker.RecordSucess(username, request.Host);

            UserAuthenticatedValidator.ValidateUserIsActive(successResult.Value.IsActive, username);
            UserAuthenticatedValidator.ValidateUserIsNotServiceAccount(successResult.Value.IsService, username);

            var octoResponse = UserAuthenticatedValidator.Redirect.Response(state.RedirectAfterLoginTo)
                .WithHeader("Expires", new[] { DateTime.UtcNow.AddYears(1).ToString("R", DateTimeFormatInfo.InvariantInfo) })
                .WithCookie(new OctoCookie(UserAuthConstants.OctopusStateCookieName, Guid.NewGuid().ToString()) { HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue })
                .WithCookie(new OctoCookie(UserAuthConstants.OctopusNonceCookieName, Guid.NewGuid().ToString()) {HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue});

            var authCookies = authCookieCreator.CreateAuthCookies(successResult.Value.IdentificationToken, TimeSpan.FromDays(20), request.IsHttps, state.UsingSecureConnection);

            foreach (var cookie in authCookies)
            {
                octoResponse = octoResponse.WithCookie(cookie);
            }

            return octoResponse;
        }

        public void Failure(string username, string host, InvalidLoginAction action)
        {
            loginTracker.RecordFailure(username, host);

            if (action == InvalidLoginAction.Slow)
            {
                sleep.For(1000);
            }
        }
    }
}