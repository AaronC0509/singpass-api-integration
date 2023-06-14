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
    public static ECDsa ConvertPemToECDsa(string pem)
    {
        TextReader textReader = new StringReader(pem);
        PemReader pemReader = new PemReader(textReader);
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters)keyPair.Private;

        var q = privateKeyParameters.Parameters.G.Multiply(privateKeyParameters.D);
        var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByOid(privateKeyParameters.PublicKeyParamSet);
        var spec = new ECDomainParameters(ps.Curve, ps.G, ps.N, ps.H);
        var publicKeyParameters = new ECPublicKeyParameters(q, spec);

        var x = publicKeyParameters.Q.AffineXCoord.GetEncoded();
        var y = publicKeyParameters.Q.AffineYCoord.GetEncoded();

        var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);
        bw.Write((byte)0x30);
        bw.Write((byte)0x81);
        bw.Write((byte)0x8f);
        bw.Write((byte)0x30);
        bw.Write((byte)0x1d);
        bw.Write((byte)0x06);
        bw.Write((byte)0x07);
        bw.Write(new byte[] { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01 });
        bw.Write((byte)0x02);
        bw.Write((byte)0x12);
        bw.Write(new byte[] { 0x00, 0x78, 0x00, 0xa6, 0x9d, 0xe6, 0x4a, 0x63, 0x98, 0x6b, 0xc6, 0x51, 0xd3, 0x2c, 0x2c, 0x81, 0x0f, 0x0d });
        bw.Write((byte)0x04);
        bw.Write((byte)0x6e);
        bw.Write((byte)0x30);
        bw.Write((byte)0x6c);
        bw.Write((byte)0x02);
        bw.Write((byte)0x01);
        bw.Write((byte)0x01);
        bw.Write((byte)0x04);
        bw.Write((byte)0x20);
        bw.Write(privateKeyParameters.D.ToByteArrayUnsigned());
        bw.Write((byte)0xa1);
        bw.Write((byte)0x44);
        bw.Write((byte)0x03);
        bw.Write((byte)0x42);
        bw.Write((byte)0x00);
        bw.Write(x);
        bw.Write(y);

        var ecdsa = new ECDsaCng(CngKey.Import(ms.ToArray(), CngKeyBlobFormat.EccPrivateBlob));
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
