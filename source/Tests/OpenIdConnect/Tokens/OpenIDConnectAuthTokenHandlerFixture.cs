using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using NSubstitute;
using NUnit.Framework;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.Resources;

namespace Tests.OpenIdConnect.Tokens
{
    [TestFixture]
    public class OpenIDConnectAuthTokenHandlerFixture : OpenIDFixtureBase
    {
        ISystemLog log;
        IOpenIDConnectConfigurationStore configurationStore;
        IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        IKeyRetriever keyRetriever;
        CustomOpenIDConnectAuthTokenHandler target;

        [SetUp]
        public void SetUp()
        {
            log = Substitute.For<ISystemLog>();
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
        public async Task ShouldReturnPrincipalWhenValidTokenReceived()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic);
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey> {{KeyId, rsaSecurityKeyPublic}};

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            var result = await target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => (string) pair.Value?.FirstOrDefault()), out var stateString);
            var state = JsonConvert.DeserializeObject<LoginState>(stateString);

            // Assert
            Assert.IsNotNull(result);
            Assert.That(result.Error, Is.Null.Or.Empty);
            Assert.IsNotNull(result.Principal);
            Assert.AreEqual(DefaultRedirect, state.RedirectAfterLoginTo);

            AssertClaims(result.Principal);

            configurationStore.Received().GetIssuer();
            configurationStore.Received().GetClientId();
            Received.InOrder(async () => { await keyRetriever.GetKeysAsync(issuerConfig, false); });

        }

        [Test]
        public async Task ShouldRetryWhenInvalidKeyDetected()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyStale;
            RsaSecurityKey rsaSecurityKeyCurrent;

            var token = CreateToken("99a8e79fba13856b4159f96e9c9ea6d5", out rsaSecurityKeyStale);
            token = CreateToken(KeyId, out rsaSecurityKeyCurrent);
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey>() { { KeyId, rsaSecurityKeyCurrent } };
            var staleKey = new Dictionary<string, AsymmetricSecurityKey>() { { "99a8e79fba13856b4159f96e9c9ea6d5", rsaSecurityKeyStale } };

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            // On first call to keyRetriever return invalid (stale) key
            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(staleKey));

            // On second call return the new valid key
            keyRetriever.GetKeysAsync(issuerConfig, true)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            var result = await target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString);
            var state = JsonConvert.DeserializeObject<LoginState>(stateString);

            // Assert
            Assert.IsNotNull(result);
            Assert.That(result.Error, Is.Null.Or.Empty);
            Assert.IsNotNull(result.Principal);
            Assert.AreEqual(DefaultRedirect, state.RedirectAfterLoginTo);

            AssertClaims(result.Principal);

            configurationStore.Received().GetIssuer();
            configurationStore.Received().GetClientId();

            Received.InOrder(async () => { await keyRetriever.GetKeysAsync(issuerConfig, false); });
            Received.InOrder(async () => { await keyRetriever.GetKeysAsync(issuerConfig, true); });
        }


        [Test]
        public void ShouldThrowWhenInvalidKeyDetectedTwice()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyStale;
            RsaSecurityKey rsaSecurityKeyCurrent;

            var token = CreateToken("99a8e79fba13856b4159f96e9c9ea6d5", out rsaSecurityKeyStale);
            token = CreateToken(KeyId, out rsaSecurityKeyCurrent);
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var staleKey = new Dictionary<string, AsymmetricSecurityKey>() { { "99a8e79fba13856b4159f96e9c9ea6d5", rsaSecurityKeyStale } };

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            // set keyRetriever to always return invalid (stale) key
            keyRetriever.GetKeysAsync(issuerConfig)
                .ReturnsForAnyArgs(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(staleKey));

            // Act
            Assert.ThrowsAsync<SecurityTokenInvalidSignatureException>(() => target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString));

            // Expect Exception Thrown

        }

        [Test]
        [TestCase("https://someotherdomain.com", DefaultClientId, typeof(SecurityTokenInvalidIssuerException), Description = "Invalid Issuer")]
        [TestCase(DefaultIssuer, "Another Client", typeof(SecurityTokenInvalidAudienceException), Description = "Invalid ClientId")]
        public void ShouldThrowWhenInvalidTokenDetected(string issuer, string clientId, Type expectedException)
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic, issuer: issuer, clientId: clientId);
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey>() { { KeyId, rsaSecurityKeyPublic } };

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            Assert.ThrowsAsync(expectedException, () => target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString));

            // Expect Exception Thrown

        }

        static IssuerConfiguration BuildCertificateIssuerConfiguration()
        {
            return new IssuerConfiguration {Issuer = DefaultIssuer, JwksUri = "https://some-jwks-uri/"};
        }
    }
}
