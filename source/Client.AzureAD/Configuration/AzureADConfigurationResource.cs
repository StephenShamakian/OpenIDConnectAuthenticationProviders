using System.ComponentModel;
using Octopus.Client.Extensibility.Attributes;
using Octopus.Client.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Client.Model;

namespace Octopus.Client.Extensibility.Authentication.AzureAD.Configuration
{
    [Description("Sign in to your Octopus Server with Azure Active Directory. [Learn more](https://g.octopushq.com/AuthAzureAD).")]
    public class AzureADConfigurationResource : OpenIDConnectConfigurationResource
    {
        public AzureADConfigurationResource()
        {
            Id = "authentication-aad";
        }

        [DisplayName("Role Claim Type")]
        [Description("Tell Octopus how to find the roles/groups in the security token from Azure Active Directory (usually \"roles\" or \"groups\")")]
        [Writeable]
        public string RoleClaimType { get; set; }

        [DisplayName("Client Access Key")]
        [Description("The Azure app registration secret access key. This is used for authenticating against the Azure GraphAPI for group overage lookups. If left blank it will disable Azure GraphAPI lookups. [Learn more](https://github.com/StephenShamakian/OpenIDConnectAuthenticationProviders#readme)")]
        [Writeable]
        public SensitiveValue ClientKey { get; set; }
    }
}