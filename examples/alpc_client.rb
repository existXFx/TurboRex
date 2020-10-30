require 'turborex'

endpoint = ARGV[0]
message = ARGV[1]

unless endpoint.start_with?("\\RPC Control")
  endpoint = "\\RPC Control\\#{endpoint}"
end

client = TurboRex::Windows::ALPC::Client.new endpoint
server, msg = client.connect do |server|
  a = server.send_recv ARGV[1], recv_attr: TurboRex::Windows::ALPC::MessageAttribute.new.struct
  puts a.message_id
  puts a.payload
end