using System;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public class FailedAuthenticationException : Exception
    {
        public FailedAuthenticationException(string message) : base(message)
        {
        }
    }
}