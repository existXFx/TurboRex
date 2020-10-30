require 'turborex'
require 'turborex/windows/com'

clsid = ARGV[0]
ctx = ARGV[1]
client = TurboRex::Windows::COM::Client.new(clsid)
interface = TurboRex::Windows::COM::Interface::IUnknown.new
client.create_instance cls_context: ctx, interface: interface

objref = TurboRex::Windows::Win32API.decode_c_struct('OBJREF', interface.marshal_to_string)
pid = objref.u_standard.std.ipid.Data2

puts "Create COM object in process #{pid}."
interface.Release

