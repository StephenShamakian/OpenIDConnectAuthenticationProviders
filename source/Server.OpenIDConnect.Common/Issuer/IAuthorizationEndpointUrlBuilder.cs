namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer
{
    public interface IAuthorizationEndpointUrlBuilder
    {
        string Build(string requestDirectoryPath, IssuerConfiguration issuerConfiguration, string? nonce = null, string? state = null, string? codeChallenge = null);
    }
}