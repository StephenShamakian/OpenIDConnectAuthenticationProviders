using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates
{
    public abstract class KeyRetriever<TStore, TCertificateParser> : IKeyRetriever
        where TStore : IOpenIDConnectConfigurationStore
        where TCertificateParser : IKeyJsonParser
    {
        readonly TCertificateParser keyParser;
        readonly object funcLock = new object();
        Task<IDictionary<string, AsymmetricSecurityKey>> certRetrieveTask;

        protected readonly TStore ConfigurationStore;

        protected KeyRetriever(TStore configurationStore,
            TCertificateParser keyParser)
        {
            ConfigurationStore = configurationStore;
            this.keyParser = keyParser;
        }

        public Task<IDictionary<string, AsymmetricSecurityKey>> GetCertificatesAsync(IssuerConfiguration issuerConfiguration, bool forceReload=false)
        {
            lock (funcLock)
            {
                if (certRetrieveTask != null && !forceReload)
                    return certRetrieveTask;

                certRetrieveTask = DoGetKeyAsync(issuerConfiguration);
                return certRetrieveTask;
            }           
        }

        protected virtual string GetDownloadUri(IssuerConfiguration issuerConfiguration)
        {
            return issuerConfiguration.JwksUri;
        }

        public async Task<IDictionary<string, AsymmetricSecurityKey>> DoGetKeyAsync(IssuerConfiguration issuerConfiguration)
        {
            using (var client = new HttpClient())
            {
                var downloadUri = GetDownloadUri(issuerConfiguration);

                var response = await client.GetAsync(downloadUri);
                var content = await response.Content.ReadAsStringAsync();

                var downloadedKeys = keyParser.Parse(content);

                return downloadedKeys.ToDictionary(c => c.Kid, ConvertDetailsToKey);
            }
        }

        AsymmetricSecurityKey ConvertDetailsToKey(KeyDetails keyDetails)
        {
            var rsa = keyDetails as RsaDetails;
            if (rsa != null)
            {
                return new RsaSecurityKey(
                    new RSAParameters
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(rsa.Exponent),
                        Modulus = Base64UrlEncoder.DecodeBytes(rsa.Modulus)
                    });
            }

            var x509 = keyDetails as CertificateDetails;
            if (x509 != null)
            {
                return new X509SecurityKey(FromBase64String(x509.Kid, x509.Certificate));
            }

            throw new InvalidOperationException($"Unknown key details type: {keyDetails.GetType().Name}");
        }

        X509Certificate2 FromBase64String(string kid, string certificateString)
        {
            // Load the certificate via a file, per http://paulstovell.com/blog/x509certificate2
            var raw = Convert.FromBase64String(certificateString);
            var file = Path.Combine(Path.GetTempPath(), kid);

            try
            {
                File.WriteAllBytes(file, raw);

                var certificate = new X509Certificate2(file);

                return certificate;
            }
            finally
            {
                File.Delete(file);
            }
        }
    }
}