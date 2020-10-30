require 'turborex'

include TurboRex::MSRPC::RPCFinder::StaticRPCBacktracer

dasm = _disassemble_executable_sections(Metasm::PE.decode_file(ARGV[0]))
res = bt_security_callback(dasm, true)
res.each do |r|
  puts "Interface id: #{r[:interface_id]}"
  puts "Callback address: 0x#{r[:callback].to_s(16)}"
  puts "Flags: #{r[:flags]}"
  puts
end