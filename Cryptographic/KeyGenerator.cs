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
        TextReader textReader = new StringReader(pem);
        PemReader pemReader = new PemReader(textReader);
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters)keyPair.Private;

        var x9 = new X9ECParameters(
            privateKeyParameters.Parameters.Curve,
            new X9ECPoint(privateKeyParameters.Parameters.Curve, privateKeyParameters.Parameters.G.GetEncoded()),
            privateKeyParameters.Parameters.N,
            privateKeyParameters.Parameters.H,
            privateKeyParameters.Parameters.GetSeed());

        var privateKeyInfo = new PrivateKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, x9.ToAsn1Object()),
            new Org.BouncyCastle.Asn1.Sec.ECPrivateKeyStructure((int)privateKeyParameters.Parameters.N.BitLength, privateKeyParameters.D, x9).ToAsn1Object());

        var serializedPrivateBytes = privateKeyInfo.GetDerEncoded();

        ECDsaCng ecdsa = new ECDsaCng(CngKey.Import(serializedPrivateBytes, CngKeyBlobFormat.Pkcs8PrivateBlob));
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
