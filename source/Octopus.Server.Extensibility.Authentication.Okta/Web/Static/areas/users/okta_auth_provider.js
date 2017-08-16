var providerName = "Okta";

function oktaAuthProvider(octopusClient, provider, redirectAfterLoginToLink, onError) {

    this.linkHtml = '<a><div class="okta-button"><img src="' + octopusClient.resolve("~/images/okta/aura_solid_blue.png") + '" /><div>Sign in with Okta</div></div></a>';

    this.signIn = function () {
        console.log("Signing in using " + providerName + " provider");

        var authUri = provider.Links.Authenticate;
        var redirectToLink = function (externalProviderLink) {
            window.location.href = externalProviderLink.ExternalAuthenticationUrl;
        };
        var postData = {
            ApiAbsUrl: octopusClient.resolve("~/"),
            RedirectAfterLoginTo: redirectAfterLoginToLink
        };

        octopusClient.post(authUri, postData)
            .then(redirectToLink, onError);
    };

    return {
        Name: providerName,
        LinkHtml: this.linkHtml,
        SignIn: this.signIn
    };
}

console.log("Registering " + providerName + " auth provider");
window.Octopus.registerExtension(providerName, "auth_provider", oktaAuthProvider);