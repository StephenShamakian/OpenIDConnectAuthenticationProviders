using System.Threading;
using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Results;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public interface IUserService
    {
        IResultFromExtension<IUser> GetOrCreateUser(UserResource userResource, string[] groups, string providerName, IIdentityCreator identityCreator, bool allowAutoUserCreation, CancellationToken cancellationToken);
    }
}