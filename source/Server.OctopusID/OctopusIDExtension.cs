using Autofac;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.Extensions.Identities;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Identities;
using Octopus.Server.Extensibility.Authentication.OctopusID.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OctopusID.Issuer;
using Octopus.Server.Extensibility.Authentication.OctopusID.Tokens;
using Octopus.Server.Extensibility.Authentication.OctopusID.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;
using Octopus.Server.Extensibility.Extensions;
using Octopus.Server.Extensibility.Extensions.Infrastructure;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.Extensions.Mappings;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    [OctopusPlugin("OctopusID", "Octopus Deploy")]
    public class OctopusIDExtension : OpenIDConnectExtension, IOctopusExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<OctopusIdConfigDiscoverer>().As<IOctopusIdentityProviderConfigDiscoverer>().InstancePerDependency();

            builder.RegisterType<OctopusIDDatabaseInitializer>().As<IExecuteWhenDatabaseInitializes>().InstancePerDependency();
            builder.RegisterType<OctopusIDPrincipalToUserResourceMapper>().As<IOctopusIDPrincipalToUserResourceMapper>().InstancePerDependency();
            builder.RegisterType<OctopusIDConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<OctopusIDIdentityCreator>().As<IOctopusIDIdentityCreator>().SingleInstance();

            builder.RegisterType<OctopusIDConfigurationStore>()
                .As<IOctopusIDConfigurationStore>()
                .InstancePerDependency();
            builder.RegisterType<OctopusIDConfigurationSettings>()
                .As<IOctopusIDConfigurationSettings>()
                .As<IHasConfigurationSettings>()
                .As<IHasConfigurationSettingsResource>()
                .As<IContributeMappings>()
                .InstancePerDependency();
            builder.RegisterType<OctopusIDConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .InstancePerDependency();

            builder.RegisterType<OctopusIDAuthorizationEndpointUrlBuilder>().As<IOctopusIDAuthorizationEndpointUrlBuilder>().InstancePerDependency();
            builder.RegisterType<OctopusIDAuthTokenHandler>().As<IOctopusIDAuthTokenHandler>().InstancePerDependency();

            builder.RegisterType<OctopusIDHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();

            builder.RegisterType<OctopusIDLoginParametersHandler>().As<ICanHandleLoginParameters>().InstancePerDependency();

            // These are important as Singletons because they cache X509 certificates for performance
            builder.RegisterType<DefaultKeyJsonParser>().As<IKeyJsonParser>().SingleInstance();
            builder.RegisterType<OctopusIDKeyRetriever>().As<IOctopusIDKeyRetriever>().SingleInstance();

            builder.RegisterType<OctopusIDStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            builder.RegisterType<OctopusIDUserAuthenticationAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<OctopusIDUserAuthenticatedPkceAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<OctopusIDUserAuthenticatedAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<OctopusIDAuthenticationProvider>()
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