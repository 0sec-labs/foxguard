using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Xml;

namespace SafeApp
{
    public class SafeExamples
    {
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

        public async void StaticHttp()
        {
            var client = new HttpClient();
            await client.GetAsync("https://api.example.com/health");
        }

        public void StaticFile()
        {
            File.ReadAllText("config/appsettings.json");
        }

        public void StrongCrypto()
        {
            using var sha256 = SHA256.Create();
        }

        public void ConfiguredSecret()
        {
            string apiKey = Environment.GetEnvironmentVariable("API_KEY");
        }

        public void SafeXml(string xmlInput)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
            using var reader = XmlReader.Create(new StringReader(xmlInput), settings);
        }
    }
}
