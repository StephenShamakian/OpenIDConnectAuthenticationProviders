using Autofac;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Identities;
using Octopus.Server.Extensibility.Authentication.AzureAD.Infrastructure;
using Octopus.Server.Extensibility.Authentication.AzureAD.Issuer;
using Octopus.Server.Extensibility.Authentication.AzureAD.Tokens;
using Octopus.Server.Extensibility.Authentication.AzureAD.Web;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Extensions.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Extensions;
using Octopus.Server.Extensibility.Extensions.Infrastructure;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.Extensions.Mappings;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.AzureAD
{
    [OctopusPlugin("AzureAD - GraphAPI Support", "Octopus Deploy (Modified by: Stephen Shamakian)")]
    public class AzureADExtension : OpenIDConnectExtension, IOctopusExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<IdentityProviderConfigDiscoverer>().As<IIdentityProviderConfigDiscoverer>().SingleInstance();

            builder.RegisterType<AzureADDatabaseInitializer>().As<IExecuteWhenDatabaseInitializes>().InstancePerDependency();
            builder.RegisterType<AzureADPrincipalToUserResourceMapper>().As<IAzureADPrincipalToUserResourceMapper>().InstancePerDependency();
            builder.RegisterType<AzureADConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<AzureADIdentityCreator>().As<IAzureADIdentityCreator>().SingleInstance();

            builder.RegisterType<AzureADConfigurationStore>()
                .As<IAzureADConfigurationStore>()
                .InstancePerDependency();
            builder.RegisterType<AzureADConfigurationSettings>()
                .As<IAzureADConfigurationSettings>()
                .As<IHasConfigurationSettings>()
                .As<IHasConfigurationSettingsResource>()
                .As<IContributeMappings>()
                .InstancePerDependency();
            builder.RegisterType<AzureADConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .InstancePerDependency();

            builder.RegisterType<AzureADAuthorizationEndpointUrlBuilder>().As<IAzureADAuthorizationEndpointUrlBuilder>().InstancePerDependency();
            builder.RegisterType<AzureADAuthTokenHandler>().As<IAzureADAuthTokenHandler>().InstancePerDependency();

            builder.RegisterType<AzureADHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();

            // These are important as Singletons because they cache X509 certificates for performance
            builder.RegisterType<DefaultKeyJsonParser>().As<IKeyJsonParser>().SingleInstance();
            builder.RegisterType<AzureADKeyRetriever>().As<IAzureADKeyRetriever>().SingleInstance();

            builder.RegisterType<AzureADStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            builder.RegisterType<AzureADUserAuthenticationAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<AzureADUserAuthenticatedPkceAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<AzureADUserAuthenticatedAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<AzureADAuthenticationProvider>()
                .As<IAuthenticationProvider>()
                .As<IAuthenticationProviderWithGroupSupport>()
                .As<IContributesCSS>()
                .As<IContributesJavascript>()
                .As<IUseAuthenticationIdentities>()
                .AsSelf()
                .InstancePerDependency();
        }
    }
}