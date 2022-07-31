using System.Collections.Generic;
using System.Threading.Tasks;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens
{
    public interface IAuthTokenHandler
    {
        Task<ClaimsPrincipalContainer> GetPrincipalAsync(IDictionary<string, string?> requestForm, out string? stateString);
    }
}