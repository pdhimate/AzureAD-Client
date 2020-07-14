using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureADClient
{
    class Program
    {
        // Config params
        static string TenantId = "Your Tenant Id";
        static string Authority = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token";
        static string ClientId = "Azure AD App's Client Id";
        static string PfxCertFilePath = @"c:\blah.pfx"; // The Public Key Certificate (.cer) should be uploaded in the Azure AD App.
        static string PfxCertFilePassword = "Password for blah.pfx";

        // Azure AD Secured API endpoints
        static string FunctionAppAPIBaseUrl = "https://blahblah.azurewebsites.net";
        static string GETEndpoint1 = "/HttpTrigger1";

        static void Main(string[] args)
        {
            try
            {
                RunAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error" + ex.Message);
                Console.ResetColor();
            }
        }

        private static async Task RunAsync()
        {
            IConfidentialClientApplication clientApp = BuildClientUsingClientAssertion();

            // Request Access Token 
            string[] scopes = new string[] {
                $"{FunctionAppAPIBaseUrl}/.default",
              };
            var result = await clientApp.AcquireTokenForClient(scopes)
              .ExecuteAsync();
            Console.WriteLine("Access token: " + result.AccessToken);

            // Call Secured API using the Access Token
            var response = await CallEndpoint1(result);
            Console.WriteLine("Obtained response from secured endpoint: " + JsonConvert.SerializeObject(response));
        }

        #region Local helpers
       
        /// <summary>
        /// Generates Client Assertion and builds ClientApp
        /// </summary>
        /// <returns></returns>
        private static IConfidentialClientApplication BuildClientUsingClientAssertion()
        {
            string signedClientAssertion = GetSignedClientAssertion(TenantId, ClientId,
                PfxCertFilePath, PfxCertFilePassword);

            IConfidentialClientApplication clientApp = ConfidentialClientApplicationBuilder
                 .Create(ClientId)
                 .WithAuthority(new Uri(Authority))
                 .WithClientAssertion(signedClientAssertion)
                 .Build();

            return clientApp;
        }

        private static async Task<JObject> CallEndpoint1(AuthenticationResult result)
        {
            using (var httpClient = new HttpClient())
            {
                var defaultRequestHeaders = httpClient.DefaultRequestHeaders;
                if (defaultRequestHeaders.Accept == null || !defaultRequestHeaders.Accept.Any(m => m.MediaType == "application/json"))
                {
                    httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                }
                defaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", result.AccessToken);

                var response = await httpClient.GetAsync($"{FunctionAppAPIBaseUrl}/{GETEndpoint1}");
                if (response.IsSuccessStatusCode)
                {
                    string json = await response.Content.ReadAsStringAsync();
                    JObject responseObj = JsonConvert.DeserializeObject(json) as JObject;
                    Console.ForegroundColor = ConsoleColor.Gray;
                    return responseObj;
                }
                throw new Exception($"Failed to call the Web Api: {response.StatusCode}");
            }
        }

        private static string GetSignedClientAssertion(string tenantId, string confidentialClientID,
          string certificatePath, string certPass)
        {
            var cert = new X509Certificate2(certificatePath, certPass, X509KeyStorageFlags.EphemeralKeySet);

            // JsonWebTokenHandler will add defaults
            var claims = new Dictionary<string, object>()
            {
                { "aud", $"https://login.microsoftonline.com/{tenantId}/oauth2/token" },
                { "iss", confidentialClientID },
                { "jti", Guid.NewGuid().ToString() },
                { "sub", confidentialClientID }
            };

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = claims,
                SigningCredentials = new X509SigningCredentials(cert)
            };

            var handler = new JsonWebTokenHandler();
            var signedClientAssertion = handler.CreateToken(securityTokenDescriptor);
            return signedClientAssertion;
        } 

        #endregion
    }
}

