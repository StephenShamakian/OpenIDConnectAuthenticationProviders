using System;
using System.Linq;
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
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Authentication.Resources;
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
        readonly TStore configurationStore;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly TIdentityCreator identityCreator;
        readonly IUrlEncoder encoder;
        readonly IUserService userService;

        protected UserAuthenticatedAction(
            ISystemLog log,
            TAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            TStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            TIdentityCreator identityCreator,
            IUrlEncoder encoder,
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
            this.userService = userService;
        }

        protected abstract string ProviderName { get; }

        public async Task<IOctoResponseProvider> ExecuteAsync(IOctoRequest request)
        {
            var authServerResponseHandler = new AuthServerResponseHandler<TAuthTokenHandler>(
                authTokenHandler,
                principalToUserResourceMapper,
                authCookieCreator,
                loginTracker,
                sleep,
                encoder);
            try
            {
                var principalContainer =  await authServerResponseHandler.GetDetailsFromRequestEnsuringNoErrors(request.Form.ToDictionary(pair => pair.Key, pair => (string?)pair.Value));

                var stateStringFromRequest = request.Form.ContainsKey("state") ? request.Form["state"] : string.Empty;
                authServerResponseHandler.ValidateState(request, stateStringFromRequest);
                authServerResponseHandler.ValidateNonce(request, principalContainer);

                var authenticationCandidate = authServerResponseHandler.MapPrincipalToUserResource(principalContainer);
                var action = authServerResponseHandler.CheckIfAuthenticationAttemptIsBanned(authenticationCandidate.Username!, request.Host);

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
                var userResult = userService.GetOrCreateUser(authenticationCandidate, principalContainer.ExternalGroupIds, ProviderName, identityCreator, configurationStore.GetAllowAutoUserCreation(), cts.Token);
                if (userResult is ISuccessResult<IUser> successResult)
                {
                    var stateFromRequest = JsonConvert.DeserializeObject<LoginState>(stateStringFromRequest)!;
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
    }
}
