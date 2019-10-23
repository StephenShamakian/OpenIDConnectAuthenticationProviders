﻿using Octopus.Server.Extensibility.Authentication.Resources;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public class LoginRedirectLinkRequestModel
    {
        public string ApiAbsUrl { get; set; }
        public LoginState State { get; set; }
    }
}