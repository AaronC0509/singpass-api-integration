﻿using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

public class DpopGenerator
{
    // If for Person API call, use this method below
    // public static string GenerateDpopProof(string url, string method, string privateKey, string accessToken)
    public static string GenerateDpopProof(string url, string method, string privateKey)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = JwtGenerator.GenerateRandomString(40);

        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            X = "BXUWq0Z2RRFqrlWbW2muIybNnj_YBxflNQTEOg-QmCQ",
            Y = "vXO4G4yDo0iOVJAzmEWyIZwXwnSnGxPIrZe7SX0PKu4",
            Use = "sig",
            Alg = "ES256",
            Kid = "aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ"
        };

        // Convert the private key from PEM format to an ECDsa object
        Console.WriteLine("privateKey: " + privateKey);
        var ecdsa = KeyGenerator.ConvertPemToECDsa(privateKey);

        // Create a security key from the ECDsa object
        var securityKey = new ECDsaSecurityKey(ecdsa);

        // Use the ECDsa security key to create the signing credentials with the ES256 algorithm
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

        var jwtHeader = new JwtHeader(signingCredentials);

        // Remove the existing "typ" key
        if (jwtHeader.ContainsKey("typ"))
        {
            jwtHeader.Remove("typ");
        }

        // Now add it again with the new value
        jwtHeader.Add("typ", "dpop+jwt");
        jwtHeader.Add("jwk", jwk);

        var jwtPayload = new JwtPayload
    {
        { "jti", jti },
        { "htu", url },
        { "htm", method },
        { "iat", now },
        { "exp", now + 120 }
    };

        var jwtSecurityToken = new JwtSecurityToken(jwtHeader, jwtPayload);
        var jwtHandler = new JwtSecurityTokenHandler();

        return jwtHandler.WriteToken(jwtSecurityToken);
    }

    private static string GenerateAth(string accessToken)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(accessToken));
            return Base64UrlEncoder.Encode(hash);
        }
    }
}
