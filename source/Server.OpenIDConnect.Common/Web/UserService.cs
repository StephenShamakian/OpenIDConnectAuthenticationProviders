using System;
using System.Linq;
using System.Threading;
using Octopus.Data;
using Octopus.Data.Model.User;
using Octopus.Data.Storage.User;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;
using Octopus.Server.Extensibility.Results;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public class UserService : IUserService
    {
        readonly IUpdateableUserStore userStore;
        readonly IClock clock;

        public UserService(IUpdateableUserStore userStore, IClock clock)
        {
            this.userStore = userStore;
            this.clock = clock;
        }

        public IResultFromExtension<IUser> GetOrCreateUser(
            UserResource userResource,
            string[] groups,
            string providerName,
            IIdentityCreator identityCreator,
            bool allowAutoUserCreation,
            CancellationToken cancellationToken)
        {
            var identityToMatch = NewIdentity(userResource, identityCreator);

            var matchingUsers = userStore.GetByIdentity(identityToMatch);
            if (matchingUsers.Length > 1)
                throw new Exception("There are multiple users with this identity. OpenID Connect identity providers do not support users with duplicate email addresses. Please remove any duplicate users, or make the email addresses unique.");
            var user = matchingUsers.SingleOrDefault();

            if (user != null)
            {
                userStore.SetSecurityGroupIds(providerName, user.Id, groups, clock.GetUtcTime());

                var identity = user.Identities.FirstOrDefault(x => MatchesProviderAndExternalId(userResource, x, providerName));
                if (identity != null)
                {
                    return ResultFromExtension<IUser>.Success(user);
                }

                identity = user.Identities.FirstOrDefault(x => x.IdentityProviderName == providerName && x.Claims[ClaimDescriptor.EmailClaimType].Value == userResource.EmailAddress);
                if (identity != null)
                {
                    return ResultFromExtension<IUser>.Success(userStore.UpdateIdentity(user.Id, identityToMatch, cancellationToken));
                }

                return ResultFromExtension<IUser>.Success(userStore.AddIdentity(user.Id, identityToMatch, cancellationToken));
            }

            if (!allowAutoUserCreation)
                return ResultFromExtension<IUser>.Failed("User could not be located and auto user creation is not enabled.");

            var userResult = userStore.Create(
                userResource.Username ?? string.Empty,
                userResource.DisplayName ?? string.Empty,
                userResource.EmailAddress ?? string.Empty,
                cancellationToken,
                new ProviderUserGroups { IdentityProviderName = providerName, GroupIds = groups },
                new[] { identityToMatch });
            if (userResult is IFailureResult failureResult)
                return ResultFromExtension<IUser>.Failed(failureResult.Errors);
            return ResultFromExtension<IUser>.Success(((ISuccessResult<IUser>)userResult).Value);
        }

        bool MatchesProviderAndExternalId(UserResource userResource, Identity identity, string providerName)
        {
            return identity.IdentityProviderName == providerName && identity.Claims.ContainsKey(IdentityCreator.ExternalIdClaimType) && identity.Claims[IdentityCreator.ExternalIdClaimType].Value == userResource.ExternalId;
        }

        Identity NewIdentity(UserResource userResource, IIdentityCreator identityCreator)
        {
            return identityCreator.Create(userResource);
        }
    }
}