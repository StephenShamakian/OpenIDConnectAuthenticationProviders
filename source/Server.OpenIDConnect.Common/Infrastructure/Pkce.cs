using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class Pkce
    {
        /*
         * https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
         * code_verifier = high-entropy cryptographic random STRING using the
         * unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
         * from Section 2.3 of [RFC3986], with a minimum length of 43 characters
         * and a maximum length of 128 characters.
         *
         * ABNF for "code_verifier" is as follows.
         *
         * code-verifier = 43*128unreserved
         * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
         * ALPHA = %x41-5A / %x61-7A
         * DIGIT = %x30-39
         *
         * NOTE: The code verifier SHOULD have enough entropy to make it
         * impractical to guess the value.  It is RECOMMENDED that the output of
         * a suitable random number generator be used to create a 32-octet
         * sequence.  The octet sequence is then base64url-encoded to produce a
         * 43-octet URL safe string to use as the code verifier.
         */
        public static string GenerateCodeVerifier()
        {
            var data = new byte[32];
            RandomNumberGenerator.Fill(data);
            return Base64UrlEncoder.Encode(data);
        }

        /*
         * https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
         * code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
         */
        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha = SHA256.Create();
            var challengeBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncoder.Encode(challengeBytes);
        }
    }
}