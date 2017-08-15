using Autofac;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Infrastructure;
using Octopus.Server.Extensibility.Authentication.Okta.Issuer;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.Okta.Web;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Server.Extensibility.Extensions;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta
{
    [OctopusPlugin("Okta", "Octopus Deploy")]
    public class OktaExtension : OpenIDConnectExtension, IOctopusExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            builder.RegisterType<OktaPrincipalToUserResourceMapper>().As<IOktaPrincipalToUserResourceMapper>().InstancePerDependency();
            builder.RegisterType<OktaConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<OktaConfigurationStore>()
                .As<IOktaConfigurationStore>()
                .As<IHasConfigurationSettings>()
                .InstancePerDependency();
            builder.RegisterType<OktaConfigureCommands>()
                .As<IContributeToConfigureCommand>()
                .As<IHandleLegacyWebAuthenticationModeConfigurationCommand>()
                .InstancePerDependency();

            builder.RegisterType<OktaAuthorizationEndpointUrlBuilder>().As<IOktaAuthorizationEndpointUrlBuilder>().InstancePerDependency();
            builder.RegisterType<OktaAuthTokenHandler>().As<IOktaAuthTokenHandler>().InstancePerDependency();

            builder.RegisterType<OktaHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();

            // These are important as Singletons because they cache X509 certificates for performance
            builder.RegisterType<DefaultKeyJsonParser>().As<IKeyJsonParser>().SingleInstance();
            builder.RegisterType<OktaKeyRetriever>().As<IKeyRetriever>().SingleInstance();

            builder.RegisterType<OktaStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            builder.RegisterType<OktaUserAuthenticationAction>().AsSelf().InstancePerDependency();
            builder.RegisterType<OktaUserAuthenticatedAction>().AsSelf().InstancePerDependency();

            builder.RegisterType<OktaCSSContributor>().As<IContributesCSS>().InstancePerDependency();
            builder.RegisterType<OktaJavascriptContributor>()
                .As<IContributesJavascript>()
                .As<IContributesAngularModules>()
                .InstancePerDependency();

            builder.RegisterType<OktaAuthenticationProvider>()
                .As<IAuthenticationProvider>()
                .As<IAuthenticationProviderWithGroupSupport>()
                .AsSelf()
                .InstancePerDependency();
        }
    }
}