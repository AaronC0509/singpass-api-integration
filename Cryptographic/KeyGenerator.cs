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
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

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
    public static ECDsaCng ConvertPemToECDsa(string pem)
    {
        Console.WriteLine("pem: " + pem);
        TextReader textReader = new StringReader(pem);
        PemReader pemReader = new PemReader(textReader);
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        var privateKeyParameters = (ECPrivateKeyParameters)keyPair.Private;
        var d = privateKeyParameters.D.ToByteArrayUnsigned();
        var q = privateKeyParameters.Parameters.G.Multiply(privateKeyParameters.D);
        var x = q.Normalize().AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
        var y = q.Normalize().AffineYCoord.ToBigInteger().ToByteArrayUnsigned();

        // Ensure the key parameters are the correct length, padding with zeros if necessary
        if (x.Length < 32)
        {
            var temp = new byte[32];
            Buffer.BlockCopy(x, 0, temp, 32 - x.Length, x.Length);
            x = temp;
        }
        if (y.Length < 32)
        {
            var temp = new byte[32];
            Buffer.BlockCopy(y, 0, temp, 32 - y.Length, y.Length);
            y = temp;
        }
        if (d.Length < 32)
        {
            var temp = new byte[32];
            Buffer.BlockCopy(d, 0, temp, 32 - d.Length, d.Length);
            d = temp;
        }

        // Construct the BLOB
        var blob = new byte[104];
        blob[0] = 0x20; // Magic number for ECC private key
        blob[1] = 0x20; // Key length
        Buffer.BlockCopy(d, 0, blob, 8, 32); // Start copying at index 8 to leave space for cbKey
        Buffer.BlockCopy(x, 0, blob, 40, 32);
        Buffer.BlockCopy(y, 0, blob, 72, 32);


        Console.WriteLine("d: " + d.Length);
        Console.WriteLine("x: " + x.Length);
        Console.WriteLine("y: " + y.Length);
        Console.WriteLine("blob: " + blob.Length);

        // Import the BLOB into a CngKey
        var ecdsa = new ECDsaCng(CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob));

        return ecdsa;
    }

    private static byte[] FromHex(string hex)
    {
        byte[] raw = new byte[hex.Length / 2];
        for (int i = 0; i < raw.Length; i++)
        {
            raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return raw;
    }
}
