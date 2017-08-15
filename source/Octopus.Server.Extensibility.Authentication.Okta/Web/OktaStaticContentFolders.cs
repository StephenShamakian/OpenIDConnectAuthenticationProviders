using System.Collections.Generic;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.Okta.Web
{
    public class OktaStaticContentFolders : IContributesStaticContentFolders
    {
        public IEnumerable<StaticContentEmbeddedResourcesFolder> GetStaticContentFolders()
        {
            var type = typeof(OktaStaticContentFolders);
            var assembly = type.Assembly;
            return new[] { new StaticContentEmbeddedResourcesFolder("", assembly, type.Namespace + ".Static") };
        }
    }
}