﻿using System.Collections.Generic;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Web
{
    public class GoogleAppsCSSContributor : IContributesCSS
    {
        public IEnumerable<string> GetCSSUris(string requestDirectoryPath)
        {
            yield return "styles/googleApps.css";
        }
    }
}