using Autofac;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Extensions.Identities;
using Octopus.Server.Extensibility.Extensions;
using Octopus.Server.Extensibility.Extensions.Infrastructure;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.Extensions.Mappings;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Identities;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Issuer;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Tokens;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps
{
    [OctopusPlugin("GoogleApps", "Octopus Deploy")]
    public class GoogleAppsExtension : OpenIDConnectExtension, IOctopusExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<IdentityProviderConfigDiscoverer>().As<IIdentityProviderConfigDiscoverer>().SingleInstance();

            builder.RegisterType<GoogleAppsDatabaseInitializer>().As<IExecuteWhenDatabaseInitializes>().InstancePerDependency();
            builder.RegisterType<GoogleAppsConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<GoogleAppsIdentityCreator>().As<IGoogleAppsIdentityCreator>().SingleInstance();

            builder.RegisterType<GoogleAppsConfigurationStore>()
                .As<IGoogleAppsConfigurationStore>()
                .InstancePerDependency();
            builder.RegisterType<GoogleAppsConfigurationSettings>()
                .As<IGoogleAppsConfigurationSettings>()
                .As<IHasConfigurationSettings>()
                .As<IHasConfigurationSettingsResource>()
                .As<IContributeMappings>()
                .InstancePerDependency();
            builder.RegisterType<GoogleAppsConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .InstancePerDependency();

            builder.RegisterType<GoogleAppsAuthorizationEndpointUrlBuilder>().As<IGoogleAppsAuthorizationEndpointUrlBuilder>().InstancePerDependency();
            builder.RegisterType<GoogleAuthTokenHandler>().As<IGoogleAuthTokenHandler>().InstancePerDependency();

            builder.RegisterType<GoogleAppsHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();
             
            builder.RegisterType<GoogleAppsStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            // These are important as Singletons because they cache X509 certificates for performance
            builder.RegisterType<DefaultKeyJsonParser>().As<IKeyJsonParser>().SingleInstance();
            builder.RegisterType<GoogleKeyRetriever>().As<IGoogleKeyRetriever>().SingleInstance();

            builder.RegisterType<GoogleAppsUserAuthenticationAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<GoogleAppsUserAuthenticatedPkceAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<GoogleAppsUserAuthenticatedAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<GoogleAppsAuthenticationProvider>()
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