# Octopus Deploy - Microsoft AzureAD GraphAPI support for Group Membership Overages in Auth Token

## AzureAD Group Role Token Limitations
There are two primary ways to interface with AzureAD, SAML or OpenID (Octopus uses OpenID). Both of these formats present a token that's sent back with various information that describes an authenticated user. This information is called claims. If implementing group based role claims in Octopus, AzureAD will add to the JWT OpenID token a listing of the AzureAD group IDs the user is a member of. This is great, as Octopus uses this information to cross check which Octopus Teams a user belongs to. But there are limitations with both SAML and OpenID tokens. SAML limits the amount of groups returned to 150. OpenID JWT tokens are lmited to 200 groups. In large organizations and Enterprises users often exceed these limitations by SAML and OpenID.

There are ways to wildcard limit how many groups are returned in AzureAD tokens based on a prefix. For example "devops_[groupNameHere]". But this feature in AzureAD does not work for OpenID. And Octopus only implements OpenID with its AzureAD implementation. Plus it's still (as of the writing of this) a preview feature in AzureAD for SAML.

## Microsoft/AzureAD's "Solution" to this Limitation
If there are two many groups returned in a token sent by AzureAD. Microsoft includes a custom claim "_claims_name" & "_claims_sources" that has a link to the Azure GraphAPI (an old deprecated one - more on that below) that has the group membership list for the user. They (Microsoft) expect applications to implement this in their code when developing AzureAD integrations.

See more [here](https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/tree/master/5-WebApp-AuthZ/5-2-Groups#processing-groups-claim-in-tokens-including-handling-overage). They also include an example ASP.NET Core application code that implements this [here](https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/blob/master/5-WebApp-AuthZ/5-2-Groups/Services/MicrosoftGraph-Rest/GraphHelper.cs).

## The Reason for this Octopus OpenID Auth Extension Fork
The primary reason for this fork is to implement this "solution" from Microsoft. The code in this fork is (except where otherwise stated) exactly the same as the [official repo from Octopus Deploy](https://github.com/OctopusDeploy/OpenIDConnectAuthenticationProviders). But it now has the ability to follow the Microsoft GraphAPI if it detects group membership overages. I will try my best to keep this fork in lock step with Octopus Deploy's. **But the overall goal of this fork is to eventually have Octopus Deploy merge it back into the primary OpenID Auth Provider repo provided by Octopus Deploy. That or at the very least provide a template on how to implement this.**

## Microsoft GraphAPI vs. Windows GraphAPI
I mentioned above that I am not following the exact Azure GraphAPI endpoint that is provided in the token. This is because (for whatever reason) Microsoft hasn't updated the backend to provide the new GraphAPI endpoint. Microsoft is slowly deprecating https://graph.windows.net in favor of https://graph.microsoft.com. This decision (to use graph.microsoft.com) is to future proof this implementation. This also affects the permissions the App Registration will need that you use for your AzureAD Octopus logins (more on that below).

## Installation, Configuration and Usage
### Installation:
I had all kinds of problems getting this extension to work. Sadly it wasn't as easy as stated on the [Octopus Documentation page](https://octopus.com/docs/administration/server-extensibility/installing-a-custom-server-extension). I had to write a custom PowerShell script that copied the .dll's it needed to function from the Octopus install path.

1. At the root of this repo there is a PowerShell script named "Update-OctopusReferences.ps1". Place this in the CustomExtensions folder located here "_%ProgramData%\Octopus\CustomExtensions_" on your Octopus Server. Also make sure the file paths listed in this PowerShell script at the top are correct. This Powershell script will basically copy a few .dll dependencies from the root Octopus Server install folder to this "_CustomExtensions_" folder to allow the modified AzureAD extension to run without erroring out.
2. Build the code in this fork using the documentation listed [here](https://octopus.com/docs/administration/server-extensibility/customizing-an-octopus-deploy-server-extension).
3. Copy the newly built dll file named "_Octopus.Server.Extensibility.Authentication.AzureAD.dll_" to the "_%ProgramData%\Octopus\CustomExtensions_" location on the Octopus Server. Along side the above PowerShell script.
4. Stop the Octopus Server service.
5. Run the PowerShell script with admin privileges. Make sure the Octopus Server Windows Service is not running, or you will run into file lock issues.
6. Start the Octopus Server service back up.
7. Keep in mind that whenever you upgrade your Octopus Server you will need to run this PowerShell script to verify you are running with the latest .dll dependencies from the root Octopus Server install folder. My recommendation is to run it right after the installer completes the file copy but before you click "_Finish_" on the installer.

### Configuration: 
This modified plugin will work exactly like it has before by default. In order to enable the new functionality, you will need to browse to "_Octopus Web UI > Configuration > Settings > AzureAD_" and specified a "_Client Access Key_". This is a secret key that is generated on the Azure App Registration that you use for AzureAD integration.

To generate a Client Access Key go to the Azure Portal, open up the Azure App Registration for Octopus and click the menu item called "_Certificates & Secrets_". Click the "_New Client Secret_" link towards the bottom to generate a new key. This key needs to be entered into the "_Client Access Key_" field in Octopus AzureAD Settings.

**Note:** Keep in mind that you may also have to add additional API Permissions to your Octopus App Registration to allow it to access the Microsoft Graph API. In my testing I made sure the following API Permission was present: "Directory.Read.All" (Delegated).

### Usage:
Once you add this secret key to the Octopus AzureAD configuration section this plugin will now enable the ability to follow the Azure Microsoft GraphAPI if it detects a token that has a group membership overage. If the token does not have an overage, it will not hit the GraphAPI endpoint and will continue to function like it always has.

========================================================

# Original Octopus Deploy OpenID Provider Readme Notes
This repository contains the [Octopus Deploy][1] OpenID Connect authentication providers.

## Documentation
- [Authentication Providers][2]
- [Azure AD authentication][3]
- [GoogleApps authentication][4]

## Issues
Please see [Contributing](CONTRIBUTING.md)

[1]: https://octopus.com
[2]: http://g.octopushq.com/AuthenticationProviders
[3]: http://g.octopushq.com/AuthAzureAD
[4]: http://g.octopushq.com/AuthGoogleApps
