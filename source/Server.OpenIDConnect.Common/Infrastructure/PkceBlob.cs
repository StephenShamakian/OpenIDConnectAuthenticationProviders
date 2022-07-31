using System;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public class PkceBlob
    {
        public Guid RequestId { get; }
        public string CodeVerifier { get; }
        public DateTimeOffset TimeStamp { get; }

        public PkceBlob(Guid requestId, string codeVerifier, DateTimeOffset timeStamp)
        {
            RequestId = requestId;
            CodeVerifier = codeVerifier;
            TimeStamp = timeStamp;
        }
    }
}