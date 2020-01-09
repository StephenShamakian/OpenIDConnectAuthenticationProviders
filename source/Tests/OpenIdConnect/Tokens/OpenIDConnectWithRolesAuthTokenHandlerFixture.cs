using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using NUnit.Framework;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Tests.OpenIdConnect.Tokens
{
    [TestFixture]
    public class OpenIDConnectWithRolesAuthTokenHandlerFixture : OpenIDFixtureBase
    {
        ISystemLog log;
        IOpenIDConnectConfigurationWithRoleStore configurationStore;
        IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        IKeyRetriever keyRetriever;
        CustomOpenIDConnectWithRoleAuthTokenHandler target;

        [SetUp]
        public void SetUp()
        {
            log = Substitute.For<ISystemLog>();
            configurationStore = Substitute.For<IOpenIDConnectConfigurationWithRoleStore>();
            identityProviderConfigDiscoverer = Substitute.For<IIdentityProviderConfigDiscoverer>();
            keyRetriever = Substitute.For<IKeyRetriever>();

            target = new CustomOpenIDConnectWithRoleAuthTokenHandler(
                log,
                configurationStore,
                identityProviderConfigDiscoverer,
                keyRetriever);
        }

        [Test]
        public async Task ShouldReturnRolesFromToken()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic, roleIds: new[] {"octoTesters"});
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey>() {{KeyId, rsaSecurityKeyPublic}};

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);
            configurationStore.GetRoleClaimType().Returns("roles");

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            var result = await target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString);

            // Assert
            Assert.IsNotNull(result);
            Assert.That(result.Error, Is.Null.Or.Empty);
            Assert.IsNotNull(result.ExternalGroupIds);
            Assert.That(result.ExternalGroupIds.SingleOrDefault(x => x == "octoTesters"), Is.Not.Null.And.Not.Empty);
        }

        [Test]
        public async Task ShouldReturnGroupsFromToken()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic, groupIds: new[] {"octoTesters"});
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey>() {{KeyId, rsaSecurityKeyPublic}};

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);
            configurationStore.GetRoleClaimType().Returns("groups");

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            var result = await target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString);

            // Assert
            Assert.IsNotNull(result);
            Assert.That(result.Error, Is.Null.Or.Empty);
            Assert.IsNotNull(result.ExternalGroupIds);
            Assert.That(result.ExternalGroupIds.SingleOrDefault(x => x == "octoTesters"), Is.Not.Null.And.Not.Empty);
        }

        [Test]
        public async Task ShouldReturnNoRolesWhenOnlyGroupsAreInToken()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic, groupIds: new[] {"octoTesters"});
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey>() {{KeyId, rsaSecurityKeyPublic}};

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);
            configurationStore.GetRoleClaimType().Returns("roles");

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            var result = await target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString);

            // Assert
            Assert.IsNotNull(result);
            Assert.That(result.Error, Is.Null.Or.Empty);

            Assert.IsNotNull(result.ExternalGroupIds);

            Assert.IsEmpty(result.ExternalGroupIds);
        }

        [Test]
        public async Task ShouldReturnRolesAndGroupsWhenBothAreInToken()
        {
            // Arrange
            RsaSecurityKey rsaSecurityKeyPublic;
            var token = CreateToken(KeyId, out rsaSecurityKeyPublic, roleIds: new[] {"octoTestersRole"}, groupIds: new[] {"octoTestersGroup"});
            var issuerConfig = BuildCertificateIssuerConfiguration();
            var key = new Dictionary<string, AsymmetricSecurityKey>() {{KeyId, rsaSecurityKeyPublic}};

            var request = CreateRequest(token);

            configurationStore.GetIssuer().Returns(DefaultIssuer);
            configurationStore.GetClientId().Returns(DefaultClientId);
            configurationStore.GetRoleClaimType().Returns("groups");

            identityProviderConfigDiscoverer.GetConfigurationAsync(DefaultIssuer)
                .Returns(Task.FromResult<IssuerConfiguration>(issuerConfig));

            keyRetriever.GetKeysAsync(issuerConfig, false)
                .Returns(Task.FromResult<IDictionary<string, AsymmetricSecurityKey>>(key));

            // Act
            var result = await target.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => pair.Value?.FirstOrDefault()), out var stateString);

            // Assert
            Assert.IsNotNull(result);
            Assert.That(result.Error, Is.Null.Or.Empty);
            Assert.IsNotNull(result.ExternalGroupIds);
            Assert.That(result.ExternalGroupIds.SingleOrDefault(x => x == "octoTestersRole"), Is.Not.Null.And.Not.Empty);
            Assert.That(result.ExternalGroupIds.SingleOrDefault(x => x == "octoTestersGroup"), Is.Not.Null.And.Not.Empty);
        }

        static IssuerConfiguration BuildCertificateIssuerConfiguration()
        {
            return new IssuerConfiguration {Issuer = DefaultIssuer, JwksUri = "https://some-jwks-uri/"};
        }
    }
}