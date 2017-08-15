using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Nancy;
using NSubstitute;
using NUnit.Framework;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Issuer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using JWT.Serializers;
using JWT;
using Octopus.Server.Extensibility.Authentication.Tests.Helpers;

namespace Octopus.Server.Extensibility.Authentication.Tests.OpenIdConnect.Tokens
{
    [TestFixture]
    public class OpenIDConnectAuthTokenHandlerFixture
    {
        ILog log;
        IOpenIDConnectConfigurationStore configurationStore;
        IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        IKeyRetriever keyRetriever;
        CustomOpenIDConnectAuthTokenHandler target;

        const string DefaultIssuer = "https://somedomain.com/";
        const string DefaultClientId = "Octopus Deploy";
        const string DefaultSubject = "12345";
        const string DefaultName = "bob";
        const string DefaultEmail = "bob@somedomain.com";

        const string KeyId = "88a8e79fba13856b4159f96e9c9ea6d5";
        const string Nonce = "";

        [SetUp]
        public void SetUp()
        {
            log = Substitute.For<ILog>();
            configurationStore = Substitute.For<IOpenIDConnectConfigurationStore>();
            identityProviderConfigDiscoverer = Substitute.For<IIdentityProviderConfigDiscoverer>();
            keyRetriever = Substitute.For<IKeyRetriever>();

            target = new CustomOpenIDConnectAuthTokenHandler(
                log,
                configurationStore,
                identityProviderConfigDiscoverer,
                keyRetriever);
        }

        [Test]
        public async void ShouldReturnPrincipalWhenValidTokenReceived()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic);
            var issuerConfig = new IssuerConfiguration() {Issuer = DefaultIssuer };
            var key = new Dictionary<string, AsymmetricSecurityKey>() { { KeyId, rsaSecurityKeyPublic } };

            var request = createRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetCertificatesAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            string state;
            var result = await target.GetPrincipalAsync(request, out state);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNullOrEmpty(result.error);
            Assert.IsNotNull(result.principal);
            Assert.AreEqual("/state/", state);

            AssertClaims(result.principal);

            configurationStore.Received().GetIssuer();
            configurationStore.Received().GetClientId();
            Received.InOrder(async () => { await keyRetriever.GetCertificatesAsync(issuerConfig, false); });

        }


        [Test]
        public async void ShouldRetryWhenInvalidKeyDetected()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyStale;
            RsaSecurityKey rsaSecurityKeyCurrent;

            var token = CreateToken("99a8e79fba13856b4159f96e9c9ea6d5", out rsaSecurityKeyStale);
            token = CreateToken(KeyId, out rsaSecurityKeyCurrent);
            var issuerConfig = new IssuerConfiguration() { Issuer = DefaultIssuer };
            var key = new Dictionary<string, AsymmetricSecurityKey>() { { KeyId, rsaSecurityKeyCurrent } };
            var staleKey = new Dictionary<string, AsymmetricSecurityKey>() { { "99a8e79fba13856b4159f96e9c9ea6d5", rsaSecurityKeyStale } };

            var request = createRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            // On first call to keyRetriever return invalid (stale) key
            keyRetriever.GetCertificatesAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(staleKey));

            // On second call return the new valid key
            keyRetriever.GetCertificatesAsync(issuerConfig, true)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            string state;
            var result = await target.GetPrincipalAsync(request, out state);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNullOrEmpty(result.error);
            Assert.IsNotNull(result.principal);
            Assert.AreEqual("/state/", state);

            AssertClaims(result.principal);

            configurationStore.Received().GetIssuer();
            configurationStore.Received().GetClientId();

            Received.InOrder(async () => { await keyRetriever.GetCertificatesAsync(issuerConfig, false); });
            Received.InOrder(async () => { await keyRetriever.GetCertificatesAsync(issuerConfig, true); });
        }


        [Test]
        [ExpectedException(typeof(SecurityTokenInvalidSignatureException), ExpectedMessage = @"IDX10500: Signature validation failed. There are no security keys to use to validate the signature")]
        public async void ShouldThrowWhenInvalidKeyDetectedTwice()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyStale;
            RsaSecurityKey rsaSecurityKeyCurrent;

            var token = CreateToken("99a8e79fba13856b4159f96e9c9ea6d5", out rsaSecurityKeyStale);
            token = CreateToken(KeyId, out rsaSecurityKeyCurrent);
            var issuerConfig = new IssuerConfiguration() { Issuer = DefaultIssuer };
            var staleKey = new Dictionary<string, AsymmetricSecurityKey>() { { "99a8e79fba13856b4159f96e9c9ea6d5", rsaSecurityKeyStale } };

            var request = createRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            // set keyRetriever to always return invalid (stale) key
            keyRetriever.GetCertificatesAsync(issuerConfig)
                .ReturnsForAnyArgs(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(staleKey));

            // Act
            string state;
            var result = await target.GetPrincipalAsync(request, out state);

            // Expect Exception Thrown

        }

        [Test]
        [TestCase("https://someotherdomain.com", DefaultClientId, Description = "Invalid Issuer", ExpectedException = typeof(SecurityTokenInvalidIssuerException))]
        [TestCase(DefaultIssuer, "Another Client", Description = "Invalid ClientId", ExpectedException = typeof(SecurityTokenInvalidAudienceException))]
        public async void ShouldThrowWhenInvalidTokenDetected(string issuer, string clientId)
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic, issuer: issuer, clientId: clientId);
            var issuerConfig = new IssuerConfiguration() { Issuer = DefaultIssuer };
            var key = new Dictionary<string, AsymmetricSecurityKey>() { { KeyId, rsaSecurityKeyPublic } };

            var request = createRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetCertificatesAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            string state;
            var result = await target.GetPrincipalAsync(request, out state);

            // Expect Exception Thrown

        }


        Request createRequest(string token)
        {
            var request = new Request("POST", DefaultIssuer);
            request.Form["access_token"] = null;
            request.Form["id_token"] = token;
            request.Form["state"] = "/state/";
            return request;
        }

        string CreateToken(
            string keyId,
            out RsaSecurityKey key,
            string issuer = DefaultIssuer,
            string clientId = DefaultClientId,
            string nonce = Nonce,
            string subject = DefaultSubject,
            string name = DefaultName,
            string email = DefaultEmail)
        {
            var epoch = new DateTime(1970, 1, 1);
            var now = Math.Round((DateTime.Now - epoch).TotalSeconds);
            var exp = now + 36000;

            var payload = new Dictionary<string, object>
            {
                { "aud", clientId },
                { "iss", issuer },
                { "exp", exp },
                { "iat", now },
                { "nonce", nonce },
                { "sub", subject},
                { "name", name},
                { "email", email}
            };

            var headers = new Dictionary<string, object>
            {
                { "kid",  keyId}
            };

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var rsaParametersPublic = rsa.ExportParameters(includePrivateParameters: false);
                key = new RsaSecurityKey(rsaParametersPublic) {KeyId = keyId};

                var algorithm = new RS256AlgorithmRsaOnly(rsa);
                var serializer = new JsonNetSerializer();
                var urlEncoder = new JwtBase64UrlEncoder();
                var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
                var token = encoder.Encode(headers, payload, string.Empty);

                return token;
            }
        }

        void AssertClaims(
            ClaimsPrincipal principal,
            string issuer = DefaultIssuer,
            string clientid = DefaultClientId,
            string nonce = Nonce,
            string subject = DefaultSubject,
            string name = DefaultName,
            string email = DefaultEmail)
        {
            Assert.IsTrue(principal.HasClaim(x => x.Type == "iss" && x.Value == issuer));
            Assert.IsTrue(principal.HasClaim(x => x.Type == "aud" && x.Value == clientid));
            Assert.IsTrue(principal.HasClaim(x => x.Type == "nonce" && x.Value == nonce));
            Assert.IsTrue(principal.HasClaim(x => x.Type == "name" && x.Value == name));
            Assert.IsTrue(principal.HasClaim(x => x.Type == ClaimTypes.NameIdentifier && x.Value == subject));
            Assert.IsTrue(principal.HasClaim(x => x.Type == ClaimTypes.Email && x.Value == email));
        }

    }
}
