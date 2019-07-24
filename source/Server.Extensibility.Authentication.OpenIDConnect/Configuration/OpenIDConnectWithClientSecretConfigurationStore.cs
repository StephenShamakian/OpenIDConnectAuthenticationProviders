using Nevermore.Contracts;
using Octopus.Data.Storage.Configuration;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration
{
    public abstract class OpenIDConnectWithClientSecretConfigurationStore<TConfiguration> : OpenIdConnectConfigurationStore<TConfiguration>, IOpenIDConnectWithClientSecretConfigurationStore<TConfiguration>
        where TConfiguration : OpenIDConnectConfigurationWithClientSecret, IId, new()
    {
        protected OpenIDConnectWithClientSecretConfigurationStore(IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public string GetClientSecret()
        {
            return GetProperty(doc => doc.ClientSecret);
        }

        public void SetClientSecret(string clientSecret)
        {
            SetProperty(doc => doc.ClientSecret = clientSecret);
        }
    }
}