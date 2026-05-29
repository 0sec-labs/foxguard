using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Xml;

namespace SafeApp
{
    public class SafeExamples
    {
        private const string KnownUid = "service-account";

        public void ParameterizedSql(SqlConnection conn, string userId)
        {
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", userId);
            cmd.ExecuteReader();
        }

        public void StaticCommand()
        {
            Process.Start("dotnet", "--info");
        }

        // Command argument traced to a string-literal local — safe.
        public void CommandFromConstLocal()
        {
            string cmd = "dotnet";
            Process.Start(cmd);
        }

        public async void StaticHttp()
        {
            var client = new HttpClient();
            await client.GetAsync("https://api.example.com/health");
        }

        // URL produced by a Validate* sanitizer — safe.
        public async void ValidatedHttp(HttpClient client, string raw)
        {
            var url = Validate(raw);
            await client.GetAsync(url);
        }

        private string Validate(string input) => input;

        public void StaticFile()
        {
            File.ReadAllText("config/appsettings.json");
        }

        // Path built from a safe base via Path.Combine — safe.
        public void CombinedPath(string baseDir, string x)
        {
            var path = Path.Combine(baseDir, x);
            File.ReadAllText(path);
        }

        public void StrongCrypto()
        {
            using var sha256 = SHA256.Create();
        }

        public void ConfiguredSecret()
        {
            string apiKey = Environment.GetEnvironmentVariable("API_KEY");
        }

        // All-literal SQL concatenation — no tainted operand, safe.
        public void LiteralSqlConcat(SqlConnection conn)
        {
            var cmd = new SqlCommand();
            cmd.Connection = conn;
            cmd.ExecuteReader("SELECT * FROM users " + "WHERE active = 1");
        }

        // LDAP filter concatenated only with a known constant — safe.
        public void LdapWithConstant()
        {
            var searcher = new DirectorySearcher();
            searcher.Filter = "(uid=" + KnownUid + ")";
        }

        public void SafeXml(string xmlInput)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
            using var reader = XmlReader.Create(new StringReader(xmlInput), settings);
        }
    }
}
