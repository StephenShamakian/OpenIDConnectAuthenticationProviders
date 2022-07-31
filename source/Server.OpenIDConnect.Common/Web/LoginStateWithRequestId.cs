using System;
using Octopus.Server.Extensibility.Authentication.Resources;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    internal class LoginStateWithRequestId : LoginState
    {
        public Guid RequestId { get; }

        public LoginStateWithRequestId(string redirectAfterLoginTo, bool usingSecureConnection, Guid requestId)
        {
            RedirectAfterLoginTo = redirectAfterLoginTo;
            UsingSecureConnection = usingSecureConnection;
            RequestId = requestId;
        }
    }
}