using System;

public class ApiClient
{
    public void GenerateTokens(string url, string clientId, string privateKey)
    {
        var (publicKey, ephemeralPrivateKey) = KeyGenerator.GenerateEphemeralKey();
        var jwkThumbprint = KeyGenerator.GenerateJwkThumbprint(publicKey);
        Console.WriteLine("DPoP Thumbprint: " + jwkThumbprint);
        var clientAssertion = JwtGenerator.GenerateClientAssertion(url, clientId, privateKey, jwkThumbprint);
        var dpopToken = DpopGenerator.GenerateDpopProof(url, "POST", ephemeralPrivateKey);

        Console.WriteLine("Client Assertion: " + clientAssertion);
        Console.WriteLine("DPoP Token: " + dpopToken);
    }
}
