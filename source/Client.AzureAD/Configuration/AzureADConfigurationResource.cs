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
        [Description("The App Registration secret access key. Used for authenticating against the GraphAPI for group overage lookups.")]
        [Writeable]
        public SensitiveValue ClientKey { get; set; }
    }
}