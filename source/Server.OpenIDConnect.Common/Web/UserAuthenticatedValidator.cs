using System.Security.Claims;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public static class UserAuthenticatedValidator
    {
        public static readonly BadRequestRegistration LoginFailed = new("User login failed");
        public static readonly RedirectRegistration Redirect = new("Redirects back to the Octopus portal");

        const string StateDescription = "As a security precaution, Octopus ensures the state object returned from the external identity provider matches what it expected.";
        const string NonceDescription = "As a security precaution to prevent replay attacks, Octopus ensures the nonce returned in the claims from the external identity provider matches what it expected.";

        public static void ValidatePrincipalContainer(ClaimsPrincipalContainer principalContainer)
        {
            if (principalContainer.Principal == null || !string.IsNullOrEmpty(principalContainer.Error))
            {
                throw new FailedAuthenticationException($"The response from the external identity provider contained an error: {principalContainer.Error}");
            }
        }

        public static void ValidateExpectedStateHashIsNotEmpty(string? expectedStateHash)
        {
            if (string.IsNullOrWhiteSpace(expectedStateHash))
            {
                throw new FailedAuthenticationException($"User login failed: Missing State Hash Cookie. {StateDescription} In this case the Cookie containing the SHA256 hash of the state object is missing from the request.");
            }
        }

        public static void ValidateReceivedStateIsEqualToExpectedState(string stateFromRequestHash, string expectedStateHash, string? stateStringFromRequest)
        {
            if (stateFromRequestHash != expectedStateHash)
            {
                throw new FailedAuthenticationException($"User login failed: Tampered State. {StateDescription} In this case the state object looks like it has been tampered with. The state object is '{stateStringFromRequest}'. The SHA256 hash of the state was expected to be '{expectedStateHash}' but was '{stateFromRequestHash}'.");
            }
        }

        public static void ValidateUsername(string? username)
        {
            if (username == null)
            {
                throw new FailedAuthenticationException("Unable to determine username.");
            }
        }

        public static void ValidateUserIsNotBanned(InvalidLoginAction action)
        {
            if (action == InvalidLoginAction.Ban)
            {
                throw new FailedAuthenticationException("You have had too many failed login attempts in a short period of time. Please try again later.");
            }
        }

        public static void ValidateUserIsActive(bool isActive, string username)
        {
            if (!isActive)
            {
                throw new FailedAuthenticationException($"The Octopus User Account '{username}' has been disabled by an Administrator. If you believe this to be a mistake, please contact your Octopus Administrator to have your account re-enabled.");
            }
        }

        public static void ValidateUserIsNotServiceAccount(bool isService, string username)
        {
            if (isService)
            {
                throw new FailedAuthenticationException($"The Octopus User Account '{username}' is a Service Account, which are prevented from using Octopus interactively. Service Accounts are designed to authorize external systems to access the Octopus API using an API Key.");
            }
        }

        public static void ValidateExpectedNonceHashIsNotEmpty(string? expectedNonceHash)
        {
            if (string.IsNullOrWhiteSpace(expectedNonceHash))
            {
                throw new FailedAuthenticationException($"User login failed: Missing Nonce Hash Cookie. {NonceDescription} In this case the Cookie containing the SHA256 hash of the nonce is missing from the request.");
            }
        }

        public static void ValidateNonceFromClaimsIsNotEmpty(Claim? nonceFromClaims)
        {
            if (nonceFromClaims == null)
            {
                throw new FailedAuthenticationException($"User login failed: Missing Nonce Claim. {NonceDescription} In this case the 'nonce' claim is missing from the security token.");
            }
        }

        public static void ValidateNonceFromClaimsHashIsEqualToExpectedNonce(string nonceFromClaimsHash, string expectedNonceHash, Claim nonceFromClaims)
        {
            if (nonceFromClaimsHash != expectedNonceHash)
            {
                throw new FailedAuthenticationException($"User login failed: Tampered Nonce. {NonceDescription} In this case the nonce looks like it has been tampered with or reused. The nonce is '{nonceFromClaims}'. The SHA256 hash of the state was expected to be '{expectedNonceHash}' but was '{nonceFromClaimsHash}'.");
            }
        }

        public static IOctoResponseProvider BadRequest(ILog log, string message)
        {
            log.Error(message);
            return LoginFailed.Response(message);
        }
    }
}