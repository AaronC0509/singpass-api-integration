using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptographic
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var apiClient = new ApiClient();
            apiClient.GenerateTokens("https://test.api.myinfo.gov.sg/com/v4/token", "STG2-MYINFO-SELF-TEST", "-----BEGIN EC PRIVATE KEY-----MHcCAQEEIGcOBk0/8HtXAR8XkSinGpVE4GTmbPQnjkhGO+A+QrPaoAoGCCqGSM49AwEHoUQDQgAEBXUWq0Z2RRFqrlWbW2muIybNnj/YBxflNQTEOg+QmCS9c7gbjIOjSI5UkDOYRbIhnBfCdKcbE8itl7tJfQ8q7g==-----END EC PRIVATE KEY-----");
            Console.Read();
        }
    }
}
