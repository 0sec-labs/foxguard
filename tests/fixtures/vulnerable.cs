using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.DirectoryServices;
using System.Xml;

namespace VulnerableApp
{
    public class Vulnerabilities
    {
        // Rule 1: SQL injection via string concatenation
        public void SqlInjection(string userId)
        {
            var conn = new SqlConnection("Server=localhost;Database=test;");
            var cmd = new SqlCommand();
            cmd.Connection = conn;
            var reader = cmd.ExecuteReader("SELECT * FROM users WHERE id = " + userId);
        }

        // Rule 2: Command injection via Process.Start
        public void CommandInjection(string userInput)
        {
            Process.Start(userInput);
        }

        // Rule 3: Unsafe deserialization
        public void UnsafeDeserialization(Stream stream)
        {
            var formatter = new BinaryFormatter();
            var obj = formatter.Deserialize(stream);
        }

        // Rule 4: SSRF via HttpClient
        public async void Ssrf(string url)
        {
            var client = new HttpClient();
            var response = await client.GetAsync(url);
        }

        // Rule 5: Path traversal via File operations
        public void PathTraversal(string userPath)
        {
            var content = File.ReadAllText(userPath);
            var reader = new StreamReader(userPath);
            var exists = File.Exists(userPath);
            var stream = new FileStream(userPath, FileMode.Open);
        }

        // Rule 6: Weak cryptography
        public void WeakCrypto()
        {
            var md5 = MD5.Create();
            var sha1 = SHA1.Create();
            var des = DES.Create();
        }

        // Rule 7: Hardcoded secrets
        public void HardcodedSecrets()
        {
            string password = "SuperSecret123";
            string apiKey = "sk-1234567890abcdef";
            string connectionString = "Server=prod;Password=hunter2;";
        }

        // Rule 8: XXE vulnerability
        public void XxeVulnerability(string xmlInput)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xmlInput);
        }

        // Rule 9: LDAP injection
        public void LdapInjection(string username)
        {
            var searcher = new DirectorySearcher();
            searcher.Filter = "(uid=" + username + ")";
        }

        // Rule 10: Overly permissive CORS
        public void ConfigureCors(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    builder.AllowAnyOrigin();
                });
            });
        }
    }
}
