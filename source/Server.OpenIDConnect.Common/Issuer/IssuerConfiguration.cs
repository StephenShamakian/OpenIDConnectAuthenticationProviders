using Newtonsoft.Json;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer
{
    public class IssuerConfiguration
    {
        public string Issuer  { get; set; } = string.Empty;

        [JsonProperty("jwks_uri")]
        public string JwksUri { get; set; } = string.Empty;
        
        [JsonProperty("authorization_endpoint")]
        public string AuthorizationEndpoint { get; set; } = string.Empty;

        [JsonProperty("token_endpoint")]
        public string TokenEndpoint { get; set; } = string.Empty;
    }
}