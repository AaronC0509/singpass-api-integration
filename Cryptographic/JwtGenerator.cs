using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;

public class JwtGenerator
{
    public static string GenerateRandomString(int length)
    {
        const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder res = new StringBuilder();
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            byte[] uintBuffer = new byte[4];

            while (length-- > 0)
            {
                rng.GetBytes(uintBuffer);
                uint num = BitConverter.ToUInt32(uintBuffer, 0);
                res.Append(valid[(int)(num % (uint)valid.Length)]);
            }
        }

        return res.ToString();
    }

    public static string GenerateClientAssertion(string url, string clientId, string privateSigningKey, string jwkThumbprint)
    {
        var now = DateTime.UtcNow;
        var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

        var payload = new JwtPayload
        {
            { "sub", clientId },
            { "jti", GenerateRandomString(40) },
            { "aud", url },
            { "iss", clientId },
            { "iat", unixTimeSeconds },
            { "exp", unixTimeSeconds + 300 },
            { "cnf", new { jkt = jwkThumbprint } }
        };

        var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(privateSigningKey)), SecurityAlgorithms.HmacSha256);
        var jwtHeader = new JwtHeader(signingCredentials);
        jwtHeader["typ"] = "JWT";

        var jwt = new JwtSecurityToken(jwtHeader, payload);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.WriteToken(jwt);

        return jwtToken;
    }
}
