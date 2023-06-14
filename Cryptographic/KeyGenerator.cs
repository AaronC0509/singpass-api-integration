using System;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.IO;

public class KeyGenerator
{
    public static (string PublicKey, string PrivateKey) GenerateEphemeralKey()
    {
        var generator = new ECKeyPairGenerator("ECDSA");
        var secureRandom = new SecureRandom();
        var keyGenParam = new KeyGenerationParameters(secureRandom, 256);
        generator.Init(keyGenParam);

        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        TextWriter textWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(keyPair.Public);
        string publicKey = textWriter.ToString();

        textWriter = new StringWriter();
        pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(keyPair.Private);
        string privateKey = textWriter.ToString();

        return (PublicKey: publicKey, PrivateKey: privateKey);
    }

    public static string GenerateJwkThumbprint(string publicKey)
    {
        var jwk = new { kty = "EC", crv = "P-256", x = "", y = "", use = "sig", alg = "ES256" };
        var jwkJson = JsonConvert.SerializeObject(jwk);
        using (SHA256 sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(jwkJson));
            return Base64UrlEncoder.Encode(hash);
        }
    }
}
