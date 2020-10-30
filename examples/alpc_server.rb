require 'turborex'

endpoint = ARGV[0]

unless endpoint.start_with?("\\RPC Control")
  endpoint = "\\RPC Control\\#{endpoint}"
end

server = TurboRex::Windows::ALPC::Server.new endpoint
server.run do |client|
  m = client.gets
  print "Enter the response message: "
  client.puts STDIN.gets.chomp, m.message_id
end