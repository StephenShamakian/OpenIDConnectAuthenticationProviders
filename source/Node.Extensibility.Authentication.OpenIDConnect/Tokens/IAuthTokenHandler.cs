using System.Collections.Generic;
using System.Threading.Tasks;

namespace Octopus.Node.Extensibility.Authentication.OpenIDConnect.Tokens
{
    public interface IAuthTokenHandler
    {
        Task<ClaimsPrincipleContainer> GetPrincipalAsync(IDictionary<string, object> requestForm, out string state);
    }
}