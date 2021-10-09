using Newtonsoft.Json;
using Octopus.Data.Model;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Tokens
{
    class AzureADAuthTokenHandler : OpenIDConnectAuthTokenWithRolesHandler<IAzureADConfigurationStore, IAzureADKeyRetriever, IIdentityProviderConfigDiscoverer>, IAzureADAuthTokenHandler
    {
        public AzureADAuthTokenHandler(ISystemLog log, IAzureADConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IAzureADKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {}

        protected class MicrosoftGraphResponse
        {
            public string? odata {get; set;}
            public List<String>? value { get; set; }
        }

        protected class MicrosoftGraphTokenResponse
        {
            public string? token_type { get; set; }
            public int expires_in { get; set; }
            public int ext_expires_in { get; set; }
            public string? access_token { get; set; }
        }

        protected async Task<string[]> FollowGroupApiCall(ClaimsPrincipal principal)
        {
            List<string> groupObjectIds = new List<string>();

            string? clientId = ConfigurationStore.GetClientId();

            if (string.IsNullOrWhiteSpace(clientId))
            {
                // Failed to get Access Token
                Log.Error("+++ AzureAD-GraphAPI: ERROR - Failed to get App Registration Client ID from Octopus Configuration Store!");
                return new string[0];
            }

            String? clientKey = ConfigurationStore.GetClientKey()?.Value;

            if (String.IsNullOrWhiteSpace(clientKey))
            {
                // Failed to get Access Token
                Log.Error("+++ AzureAD-GraphAPI: ERROR - Failed to get App Registration Client Key from Octopus Configuration Store!");
                return new string[0];
            }

            string tenantId = principal.Claims.FirstOrDefault(c => string.Equals(c.Type, "http://schemas.microsoft.com/identity/claims/tenantid", StringComparison.OrdinalIgnoreCase)).Value;

            HttpClient client = new HttpClient();

            // Get Access Token for GraphAPI
            HttpRequestMessage requestToken = new HttpRequestMessage(HttpMethod.Post, "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token");

            var body = new List<KeyValuePair<string, string>>();
            body.Add(new KeyValuePair<string, string>("client_id", clientId));
            body.Add(new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default"));
            body.Add(new KeyValuePair<string, string>("client_secret", clientKey));
            body.Add(new KeyValuePair<string, string>("grant_type", "client_credentials"));

            requestToken.Content = new FormUrlEncodedContent(body);
            HttpResponseMessage responseToken = await client.SendAsync(requestToken);

            // Endpoint returns JSON with an array of Group ObjectIDs
            if (responseToken.IsSuccessStatusCode)
            {

                string responseTokenContent = await responseToken.Content.ReadAsStringAsync();
                MicrosoftGraphTokenResponse tokenResult = JsonConvert.DeserializeObject<MicrosoftGraphTokenResponse>(responseTokenContent);

                string accessToken;

                if ((tokenResult.access_token) != null)
                {
                    accessToken = tokenResult.access_token;
                }
                else
                {
                    // Failed to get Access Token
                    Log.Error("+++ AzureAD-GraphAPI: ERROR - Failed to get user's Access Token!");
                    return new string[0];
                }

                string userObjectId = principal.Claims.FirstOrDefault(c => string.Equals(c.Type, "http://schemas.microsoft.com/identity/claims/objectidentifier", StringComparison.OrdinalIgnoreCase)).Value;

                string requestUrl = "https://graph.microsoft.com/v1.0/" + tenantId + "/users/" + userObjectId + "/getMemberObjects";

                // Get Group Membership list from GraphAPI
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                StringContent content = new StringContent("{\"securityEnabledOnly\": \"false\"}");
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                request.Content = content;
                HttpResponseMessage response = await client.SendAsync(request);

                // Endpoint returns JSON with an array of Group ObjectIDs
                if (response.IsSuccessStatusCode)
                {
                    string responseContent = await response.Content.ReadAsStringAsync();
                    MicrosoftGraphResponse groupsResult = JsonConvert.DeserializeObject<MicrosoftGraphResponse>(responseContent);

                    if ((groupsResult.value) != null)
                    {
                        foreach (string groupObjectID in groupsResult.value)
                        {
                            groupObjectIds.Add(groupObjectID);
                        }
                    }
                    else
                    {
                        // Failed to get Group Memberships
                        Log.Error("+++ AzureAD-GraphAPI: ERROR - Failed to get list of groups from the AzureAD Graph API!");
                        return new string[0];
                    }

                    string[] groups = groupObjectIds.ToArray();

                    return groups;
                }
                else
                {
                    // Failed to get Group Memberships
                    Log.Error("+++ AzureAD-GraphAPI: ERROR - Failed to get group membership via the AzureAD Graph API!");
                    return new string[0];
                }
            }
            else
            {
                // Failed to get Auth Token
                Log.Error("+++ AzureAD-GraphAPI: ERROR - Failed to get Auth Token for group membership API!");
                return new string[0];
            }
        }


        protected override string[] GetProviderGroupIds(ClaimsPrincipal principal)
        {
            var roleClaimType = ConfigurationStore.GetRoleClaimType();

            if (string.IsNullOrWhiteSpace(roleClaimType))
            {
                return new string[0];
            }

            String? clientKey = ConfigurationStore.GetClientKey()?.Value;

            // Lets get some additional claim data for better logging
            string claimNames = principal.Claims.FirstOrDefault(c => string.Equals(c.Type, "_claim_names", StringComparison.OrdinalIgnoreCase)).Value;
            string claimUsersEmail = principal.Claims.FirstOrDefault(c => string.Equals(c.Type, ClaimTypes.Email, StringComparison.OrdinalIgnoreCase)).Value;
            string claimUsersOid = principal.Claims.FirstOrDefault(c => string.Equals(c.Type, "http://schemas.microsoft.com/identity/claims/objectidentifier", StringComparison.OrdinalIgnoreCase)).Value;


            if ((principal.FindFirst("_claim_names") != null) && (!String.IsNullOrWhiteSpace(clientKey)) && (claimNames == "{\"groups\":\"src1\"}"))
            {

                // If this claim has the "_claim_names" present this means this user is over the 150/200 group limit in the token. We need to follow the Microsoft Azure Graph API. But only if the Client Key is set in the AzureAD Octopus configuration.
                Log.Info("+++ AzureAD-GraphAPI: UserAuth - Using Azure GraphAPI group lookup endpoint - ("+ claimUsersEmail + " - "+ claimUsersOid + ")");
                
                return FollowGroupApiCall(principal).Result;

            }
            else
            {

                // the groups Ids consist of external Role and Group identifiers. We always load ClaimTypes.Role claims
                // as external identifiers, and then also based on a custom claim specified by the provider.
                Log.Info("+++ AzureAD-GraphAPI: UserAuth - Using JWT token groups - (" + claimUsersEmail + " - " + claimUsersOid + ")");
                
                var groups = principal.FindAll(ClaimTypes.Role)
                    .Concat(principal.FindAll(roleClaimType))
                    .Select(c => c.Value).ToArray();

                return groups;

            }

        }
    }
}