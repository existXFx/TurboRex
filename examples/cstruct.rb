# My syntactic sugar for simply defining the structure. 
# Does not support enum, union, the first letter of member variables must be lowercase
# This is a very crude DSL，I strongly recommend you to use Metasm's cparser instead of this

require 'turborex'

include TurboRex::CStruct

StructMgr = define_structs(arch: 'x64') do
  struct MyStruct {
    PVOID member1;
    ULONG length;
  };
end

s1 = StructMgr['MyStruct'].from_str "\x00\x00\x00\x00\x00\x00\x00\x01\xA\x00\x00\x00"
puts s1['length'].to_s.unpack('L')


