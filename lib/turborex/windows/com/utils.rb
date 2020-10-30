module TurboRex
  class Windows < Metasm::WinOS
    module COM
      module Utils
        def self.marshal_interface(object, mshctx=MSHCTX_DIFFERENTMACHINE, mshlflags=MSHLFLAGS_NORMAL)
          iid = object.iid
          _iid = "{#{iid}}"
          pstr_iid = Win32API.alloc_c_ary('OLECHAR', _iid.chars.push(0).map{|c|c.ord})
          iid = Win32API.alloc_c_struct('CLSID')
          Win32API.clsidfromstring(pstr_iid, iid)

          istream = create_istream
          hr = Win32API.comarshalinterface(istream.this, iid, object.this, mshctx, 0, mshlflags)
          return false unless TinySDK.nt_success?(hr)
          istream
        end

        def self.marshal_interface_to_string(object, mshctx=MSHCTX_DIFFERENTMACHINE, mshlflags=MSHLFLAGS_NORMAL)
          # https://thrysoee.dk/InsideCOM+/ch15c.htm
          istream = marshal_interface(object, mshctx, mshlflags)
          return false unless istream
          phglobal = Win32API.alloc_c_ptr('HGLOBAL') 
          size = Win32API.alloc_c_ptr('ULONG')

          iid = object.iid
          _iid = "{#{iid}}"
          pstr_iid = Win32API.alloc_c_ary('OLECHAR', _iid.chars.push(0).map{|c|c.ord})
          iid = Win32API.alloc_c_struct('CLSID')
          Win32API.clsidfromstring(pstr_iid, iid) 

          hr = Win32API.cogetmarshalsizemax(size, iid, object.this, mshctx, 0, mshlflags)
          return false unless TinySDK.nt_success?(hr)

          Win32API.gethglobalfromstream(istream.this, phglobal)
          addr = Win32API.globallock(phglobal[0])

          objref = Win32API.memory_read(addr, size[0])
          Win32API.globalunlock(phglobal[0])
          istream.Release

          objref
        end
        
        def self.unmarshal_interface(stream, riid, interface=nil)
          riid =~ /\{.+\}/ ? _iid = riid : _iid = "{#{riid}}"

          pstr_iid = Win32API.alloc_c_ary('OLECHAR', _iid.chars.push(0).map{|c|c.ord})
          iid = Win32API.alloc_c_struct('CLSID')
          ppv = Win32API.alloc_c_ptr('PVOID')
          Win32API.clsidfromstring(pstr_iid, iid)

          hr = Win32API.counmarshalinterface(stream.this, iid, ppv)
          raise hr.to_s unless TinySDK.nt_success?(hr)

          pthis = ppv[0]
          return pthis unless interface

          interface.this = pthis
          interface
        end

        def self.unmarshal_interface_from_string(objref, riid, interface=nil)
          istream = create_istream
          return false unless istream

          buf = Win32API.alloc_c_ary('BYTE', objref.bytesize)
          buf.str = objref
          hr = istream.Write(buf, objref.bytesize, 0)
          return false unless TinySDK.nt_success?(hr)

          # WTF? Why dlibMove won't work?
          # dlibMove = Win32API.alloc_c_struct('LARGE_INTEGER')
          # dlibMove.QuadPart = 0
          # istream.Seek(dlibMove, 0, 0)

          istream.Seek(0, 0, 0)

          phglobal = Win32API.alloc_c_ptr('HGLOBAL') 
          Win32API.gethglobalfromstream(istream.this, phglobal)
          addr = Win32API.globallock(phglobal[0])
          objref = Win32API.memory_read(addr, 292)

          unmarshal_interface(istream, riid, interface)
        end

        def self.create_istream
          ppstm = Win32API.alloc_c_ptr('LPSTREAM')
          hr = Win32API.createstreamonhglobal(0, 1, ppstm)
          return false unless TinySDK.nt_success?(hr)
          istream = Interface::IStream.new
          istream.this = ppstm[0]
          istream
        end

        def self.create_istorage(name, mode=STGM_SHARE_EXCLUSIVE|STGM_CREATE|STGM_READWRITE)
          wname = Win32API.alloc_c_ary('WCHAR', name.chars.map{|c|c.unpack('C').first}.push(0))
          ppstgOpen = Win32API.alloc_c_ptr('LPSTORAGE')
          hr = Win32API.stgcreatedocfile(wname, mode, 0, ppstgOpen)
          return false unless TinySDK.nt_success?(hr)
          istorage = Interface::IStorage.new
          istorage.this = ppstgOpen[0]
          istorage
        end

        def self.clsid_to_raw(clsid)
          pstr_clsid = INTERNAL_APIPROXY.alloc_c_ary('OLECHAR', "{#{clsid}}".chars.push(0).map{|c|c.ord})
          pclsid = INTERNAL_APIPROXY.alloc_c_ptr('CLSID')
          return unless INTERNAL_APIPROXY.clsidfromstring(pstr_clsid, pclsid).nil?
          pclsid
        end

        def self.dll_get_class_object(rclsid, dll, interface=Interface::IClassFactory.new)
          _api_proxy = TurboRex::Windows::COM::INTERNAL_APIPROXY.dup
          _api_proxy.new_api_c <<-EOS, dll
            HRESULT DllGetClassObject(
              REFCLSID rclsid,
              REFIID   riid,
              LPVOID   *ppv
            );
          EOS

          rclsid = clsid_to_raw(rclsid)    
          riid = clsid_to_raw(interface.iid)
          ppv = _api_proxy.alloc_c_ptr('PVOID')
          
          unless hr = _api_proxy.dllgetclassobject(rclsid, riid, ppv)
            interface.this = ppv[0]
            return interface
          end

          raise "Failed to call DllGetClassObject(): #{TinySDK.format_hex_ntstatus(hr, hex_str: true)}"
        end

        def get_disptbl_count(proxy_file_info)
          pcif_stub_vtbl_list = to_ptr(@memory.get_page(proxy_file_info.pStubVtblList, @ptr_len))
          if_stub_vtbl = TurboRex::Windows::COM::INTERNAL_APIPROXY.alloc_c_struct('CInterfaceStubVtbl')
          if_stub_vtbl.str = @memory.get_page(pcif_stub_vtbl_list, if_stub_vtbl.sizeof)
          return if_stub_vtbl.header.DispatchTableCount
        end

        def get_proxy_file_info(iid)
          # TODO: Replace to call CoGetPSClsid()
          require 'win32/registry'
          Win32::Registry::HKEY_CLASSES_ROOT.open("Interface\\{#{iid}}") do |reg|
            psclsid32_key = reg.open('ProxyStubClsid32')
            ps_clsid = psclsid32_key.read('').last
            psclsid32_key.close

            Win32::Registry::HKEY_CLASSES_ROOT.open("CLSID\\#{ps_clsid}") do |reg_clsid|
              inproc32_key = reg_clsid.open('InprocServer32') 
              dll_path = inproc32_key.read_s_expand('')
              inproc32_key.close
              return internal_get_proxyfile(dll_path, ps_clsid.delete('{}'))
            end
          end
        end

        # Note: The interface stub should be standard.
        def get_pid_by_std_objref(interface)
          objref = TurboRex::Windows::Win32API.decode_c_struct('OBJREF', interface.marshal_to_string)
          objref.u_standard.std.ipid.Data2
        end

        def internal_get_proxyfile(path, clsid)
          _api_proxy = TurboRex::Windows::COM::INTERNAL_APIPROXY.dup
          _api_proxy.new_api_c <<-EOS, path
            void RPC_ENTRY GetProxyDllInfo( const ProxyFileInfo*** pInfo, const CLSID ** pId );
            HRESULT DllGetClassObject(
              REFCLSID rclsid,
              REFIID   riid,
              LPVOID   *ppv
            );
          EOS

          begin
            ppproxy_fileinfo = _api_proxy.alloc_c_ptr('PVOID')
            proxy_file_info = _api_proxy.alloc_c_struct('ProxyFileInfo')
            ppclsid = _api_proxy.alloc_c_ptr('PVOID')
            _api_proxy.getproxydllinfo(ppproxy_fileinfo, ppclsid)
            pproxy_file_info = to_ptr(@memory.get_page(to_ptr(ppproxy_fileinfo.str), @ptr_len))
            proxy_file_info.str = @memory.get_page(pproxy_file_info, proxy_file_info.sizeof)
          rescue NoMethodError # GetProxyDllInfo() is not exported
            ipsfactory = Interface::IPSFactoryBuffer.new
            Utils.dll_get_class_object(clsid, path, ipsfactory)
            cstd_psfactory = _api_proxy.alloc_c_struct('CStdPSFactoryBuffer')
            cstd_psfactory.str =  @memory.get_page(ipsfactory.this, cstd_psfactory.sizeof)

            pproxy_file_info = to_ptr(@memory.get_page(cstd_psfactory.pProxyFileList, @ptr_len))
            proxy_file_info = _api_proxy.alloc_c_struct('ProxyFileInfo')
            proxy_file_info.str = @memory.get_page(pproxy_file_info, proxy_file_info.sizeof)
            ipsfactory.Release
          end

          proxy_file_info
        end

        def to_ptr(raw)
          format = case @ptr_len
          when 8
            'Q'
          when 4
            'L'
          end

          raw.unpack(format).first
        end
      end
    end
  end
end