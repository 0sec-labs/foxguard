# Ruby test fixture — safe code that should NOT trigger foxguard rules

# Safe: string literal URLs (no SSRF)
URI.open("https://example.com/api")
Net::HTTP.get("https://api.example.com/data")
HTTParty.get("https://api.example.com/data")
Faraday.get("https://api.example.com/data")
RestClient.get("https://api.example.com/data")
open "https://example.com"

# Safe: string literal file paths (no path traversal)
File.read("config/settings.yml")
File.open("log/app.log")
IO.read("data/seed.json")
File.write("tmp/cache.txt", data)
FileUtils.cp("src/file.rb", "dst/file.rb")
send_file "public/downloads/report.pdf"
