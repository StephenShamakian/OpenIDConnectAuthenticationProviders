﻿using Autofac;
using Octopus.DataCenterManager.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.DataCenterManager.Extensibility.Authentication.AzureAD.Issuer;
using Octopus.DataCenterManager.Extensibility.HostServices.Web;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Node.Extensibility.Extensions;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.HostServices.Web;

namespace Octopus.DataCenterManager.Extensibility.Authentication.AzureAD
{
    [OctopusPlugin("AzureAD", "Octopus Deploy")]
    public class AzureADExtension : OpenIDConnectExtension, IOctopusExtension
    {
        public override void Load(ContainerBuilder builder)
        {
            base.Load(builder);

            //builder.RegisterType<AzureADPrincipalToUserResourceMapper>().As<IAzureADPrincipalToUserResourceMapper>().InstancePerDependency();
            builder.RegisterType<AzureADConfigurationMapping>().As<IConfigurationDocumentMapper>().InstancePerDependency();

            builder.RegisterType<AzureADConfigurationStore>()
                .As<IAzureADConfigurationStore>()
                .As<IHasConfigurationSettings>()
                .InstancePerDependency();

            builder.RegisterType<UrlEncoder>().As<IUrlEncoder>().InstancePerDependency();
            
            //builder.RegisterType<AzureADAuthorizationEndpointUrlBuilder>().As<IAzureADAuthorizationEndpointUrlBuilder>().InstancePerDependency();
            //builder.RegisterType<AzureADAuthTokenHandler>().As<IAzureADAuthTokenHandler>().InstancePerDependency();

            //builder.RegisterType<AzureADHomeLinksContributor>().As<IHomeLinksContributor>().InstancePerDependency();

            // These are important as Singletons because they cache X509 certificates for performance
            builder.RegisterType<DefaultKeyJsonParser>().As<IKeyJsonParser>().SingleInstance();
            builder.RegisterType<AzureADKeyRetriever>().As<IKeyRetriever>().SingleInstance();

            //builder.RegisterType<AzureADStaticContentFolders>().As<IContributesStaticContentFolders>().InstancePerDependency();

            //builder.RegisterType<AzureADUserAuthenticationAction>().AsSelf().InstancePerDependency();
            //builder.RegisterType<AzureADUserAuthenticatedAction>().AsSelf().InstancePerDependency();

            //builder.RegisterType<AzureADAuthenticationProvider>()
                //.As<IAuthenticationProvider>()
                //.As<IAuthenticationProviderWithGroupSupport>()
                //.As<IContributesCSS>()
                //.As<IContributesJavascript>()
                //.AsSelf()
                //.InstancePerDependency();
        }
    }
}