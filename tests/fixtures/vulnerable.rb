# Ruby test fixture — intentionally vulnerable code for foxguard detection tests

# rb/no-eval
eval(user_input)
instance_eval(params[:code])

# rb/no-command-injection
system(user_input)
exec(user_input)
`#{user_input}`

# rb/no-sql-injection
User.where("name = '#{params[:name]}'")
ActiveRecord::Base.connection.execute("DELETE FROM users WHERE id = #{params[:id]}")

# rb/no-mass-assignment
params.permit!

# rb/no-unsafe-deserialization
Marshal.load(data)
YAML.load(data)

# rb/no-open-redirect
redirect_to params[:url]

# rb/no-csrf-skip
skip_before_action :verify_authenticity_token

# rb/no-html-safe
params[:name].html_safe
raw(user_input)

# rb/no-hardcoded-secret
secret_key = "super-secret-key-12345"
api_token = "sk-live-abcdef123456789"

# rb/no-weak-crypto
Digest::MD5.hexdigest("data")
Digest::SHA1.hexdigest("data")

# rb/no-ssrf
URI.open(user_input)
Net::HTTP.get(user_url)
HTTParty.get(url)
Faraday.get(url)
RestClient.get(url)
open url

# rb/no-path-traversal
File.read(user_input)
File.open(user_input)
IO.read(user_input)
File.write(path, data)
FileUtils.cp(src, dst)
send_file path
