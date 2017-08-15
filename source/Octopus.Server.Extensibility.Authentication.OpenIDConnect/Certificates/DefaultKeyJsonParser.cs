using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates
{
    public class DefaultKeyJsonParser : IKeyJsonParser
    {
        public KeyDetails[] Parse(string content)
        {
            var keyData = JsonConvert.DeserializeObject<IssuerKeys>(content);

            return keyData.Keys
                .Select(ConvertIssuerKeyToDetails)
                .ToArray();
        }

        static KeyDetails ConvertIssuerKeyToDetails(IssuerKey cert)
        {
            if (cert.x509Chain != null && cert.x509Chain.Any())
            {
                return new CertificateDetails
                {
                    Kid = cert.KeyId,
                    Certificate = cert.x509Chain.First()
                };
            }

            return new RsaDetails
            {
                Kid = cert.KeyId,
                Exponent = cert.Exponent,
                Modulus = cert.Modulus
            };
        }

        public class IssuerKeys
        {
            public List<IssuerKey> Keys { get; set; }
        }

        public class IssuerKey
        {
            [JsonProperty("kid")]
            public string KeyId { get; set; }

            [JsonProperty("e")]
            public string Exponent { get; set; }
            [JsonProperty("n")]
            public string Modulus { get; set; }

            [JsonProperty("x5c")]
            public string[] x509Chain { get; set; }
        }
    }
}