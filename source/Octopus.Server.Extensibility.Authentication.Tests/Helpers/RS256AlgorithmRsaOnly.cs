using JWT;
using JWT.Algorithms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Octopus.Server.Extensibility.Authentication.Tests.Helpers
{
    public class RS256AlgorithmRsaOnly : IJwtAlgorithm
    {
        readonly RSACryptoServiceProvider rsa;
        public RS256AlgorithmRsaOnly(RSACryptoServiceProvider rsa)
        {
            this.rsa = rsa;
        }

        public string Name => JwtHashAlgorithm.RS256.ToString();

        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            return rsa.SignData(bytesToSign, CryptoConfig.MapNameToOID("SHA256"));
        }
    }
}
