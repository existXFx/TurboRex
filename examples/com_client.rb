require 'turborex'

client = TurboRex::Windows::COM::Client.new('E60687F7-01A1-40AA-86AC-DB1CBF673334')
interface = TurboRex::Windows::COM::Interface.define_interface('5B311480-E5CE-4325-90CD-586C1A123FD3', {
  Proc5: 'HRESULT Proc5(void *this, GUID* p0, wchar_t* p1,  void* p2);',
  Proc6: 'HRESULT Proc6(void *this, GUID* p0);',
  Proc7: 'HRESULT Proc7(void *this, void* p0, int p1,  wchar_t* p2);'
}, TurboRex::Windows::COM::Interface::IClassFactory)
client.create_instance cls_context: TurboRex::Windows::COM::CLSCTX_LOCAL_SERVER, interface: interface


_iid = "{5B311480-E5CE-4325-90CD-586C1A123FD3}"
pstr_iid = TurboRex::Windows::Win32API.alloc_c_ary('OLECHAR', _iid.chars.push(0).map{|c|c.ord})
piid = TurboRex::Windows::Win32API.alloc_c_struct('CLSID')
TurboRex::Windows::Win32API.clsidfromstring(pstr_iid, piid)

interface.Proc6(piid)
interface.Release()

