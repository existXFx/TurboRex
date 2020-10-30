# frozen_string_literal: true
require 'turborex/pefile/scanner'

module TurboRex
  class Windows < Metasm::WinOS
    module COM
      class Finder
        include TurboRex::Utils::DisassemblerHelper
        include TurboRex::PEFile::Scanner

        def initialize(clsid)
          @clsid = clsid
        end
      end

      class InProcFinder < Finder
        attr_reader :clsid
        attr_reader :server_path

        include Utils

        def initialize(clsid)
          @clsid = clsid
          @process = TurboRex::Windows::Process.new(nil, -1)
          @memory = @process.memory
          @ptr_len = @process.cpusz / 8
        end

        def locate_interface_methods(iid)
          Win32::Registry::HKEY_CLASSES_ROOT.open("CLSID\\{#{@clsid}}") do |reg_clsid|
            reg_clsid.open('InprocServer32') do |reg_inproc32|
              @server_path = reg_inproc32.read_s_expand('')
            end
          end

          class_factory = Utils.dll_get_class_object(@clsid, @server_path)
          ppv = INTERNAL_APIPROXY.alloc_c_ptr('PVOID')
          unless class_factory.CreateInstance(0, Utils.clsid_to_raw(iid), ppv)
            # class_factory.Release
            pvtbl = to_ptr(@memory.get_page(ppv[0], @ptr_len))
            proxy_file_info = get_proxy_file_info(iid)
            return false unless proxy_file_info

            count = get_disptbl_count(proxy_file_info)

            if count
              methods = []
              @memory.get_page(pvtbl, count * @ptr_len).split('').each_slice(@ptr_len) { |m| methods << to_ptr(m.join) }

              first_method = methods.first
              _module = @process.modules.find { |m| first_method > m.addr && first_method < m.addr + m.size }
              if relative
                return {
                  module: _module.path,
                  methods: methods.map.with_index { |method, i| { index: i, rva: method - _module.addr } }
                }
              else
                return {
                  module: _module.path,
                  methods: methods.map.with_index { |method, i| { index: i, va: method } }
                }
              end
             
            end
          end
        end
      end

      class OutOfProcFinder < Finder
        attr_reader :clsid
        attr_reader :client
        attr_reader :process
        attr_reader :pid
        attr_reader :handle

        include Utils

        def initialize(clsid, opts = {})
          pid = opts[:pid]
          context = opts[:context] || CLSCTX_ALL
          @clsid = clsid
          @client = Client.new(clsid)
          @iunknown = @client.create_instance(cls_context: context, interface: Interface::IUnknown.new)
          @pid = get_pid_by_std_objref(@iunknown) || pid

          process = TurboRex::Windows::Process.new(@pid)
          raise "Unable to open process #{pid}" unless process.handle
          unless process.addrsz == (sz = Metasm::WinOS::Process.new(nil, -1).addrsz)
            raise "The architecture of Ruby interpreter process(#{sz}-bit) is not same as target process"
          end

          @process = process
          @handle = @process.handle
          @ptr_len = @process.cpusz / 8
          @memory = @process.memory

          unless @process.load_symbol_table('combase.dll')
            raise "Unable to load combase.dll's symbol"
          end

          @combase_base_addr = (@process.modules.find { |m| m.path =~ Regexp.new('combase.dll', true) }).addr
        end

        def locate_multiple_interfaces(iids, relative = true)
          iids.map {|iid| locate_interface_methods(iid, relative)}.compact
        end

        def locate_interface_methods(iid, relative = true)
          # Let the object exporter create IPID entry for target interface
          tmp_interface = TurboRex::Windows::COM::Interface.define_interface(iid, {}, Interface::IUnknown)
          ppv = INTERNAL_APIPROXY.alloc_c_ptr('PVOID')
          raise "No such interface: #{iid}" unless @iunknown.QueryInterface(Utils.clsid_to_raw(iid), ppv).nil?
          tmp_interface.this = ppv[0]
          tmp_interface.marshal_to_string # For In-Proc server
          return nil unless buckets_addr = find_oid_buckets_addr

          headers = read_bucket_headers(buckets_addr)
          walk_buckets(headers) do |_cid_obj, ipid_entry|
            raw_iid = ipid_entry.str[ipid_entry.iid.stroff, ipid_entry.iid.sizeof]
            _iid = TurboRex::MSRPC::Utils.raw_to_guid_str(raw_iid)

            if _iid == iid
              methods_count = iface_vtbl_count(ipid_entry)
              return nil unless methods_count

              if ipid_entry.pv
                pvtbl = to_ptr(@memory.get_page(ipid_entry.pv, @ptr_len))
              end

              methods = []
              @memory.get_page(pvtbl, methods_count * @ptr_len).split('').each_slice(@ptr_len) { |m| methods << to_ptr(m.join) }
              # dasm = Metasm::Shellcode.decode(@memory, Metasm::X86_64.new).disassembler
              # dasm.disassemble_fast_deep(methods.last)

              first_method = methods.first
              _module = @process.modules.find { |m| first_method > m.addr && first_method < m.addr + m.size }
              if relative
                tmp_interface.Release
                return {
                  module: _module.path,
                  methods: methods.map.with_index { |method, i| { index: i, rva: method - _module.addr } }
                }

                # return methods.map.with_index do |method, i|
                #   _module = @process.modules.find { |m| method > m.addr && method < m.addr + m.size }
                #   _module ? {index: i, module: _module.path, rva: method - _module.addr} : nil
                # end
              else
                tmp_interface.Release
                return {
                  module: _module.path,
                  methods: methods.map.with_index { |method, i| { index: i, va: method } }
                }
              end
            end
          end

          # Should decrease reference count
          tmp_interface.Release
          nil
        end

        def walk_buckets(buckets, &block)
          buckets.each do |bucket, base_addr|
            pNext = bucket.pNext
            until pNext == base_addr
              obj_addr = pNext - bucket.sizeof - @ptr_len
              cid_obj = INTERNAL_APIPROXY.alloc_c_struct('CIDObject')
              cid_obj.str = @memory.get_page(obj_addr, cid_obj.sizeof)
              pNext = cid_obj._oidChain.pNext

              std_ident = INTERNAL_APIPROXY.alloc_c_struct('CStdIdentity')
              std_ident.str = @memory.get_page(cid_obj._pStdID, std_ident.sizeof)
              walk_ipid_entries(std_ident._pFirstIPID) do |ipid_entry|
                yield(cid_obj, ipid_entry) if block_given?
              end
            end
          end
        end


        def walk_ipid_entries(pfirst_entry)
          ipid_entries = []
          pNext = pfirst_entry

          # TODO: stdid.cIPIDs
          until pNext.nil?
            ipid_entry = INTERNAL_APIPROXY.alloc_c_struct('tagIPIDEntry')
            ipid_entry.str = @memory.get_page(pNext, ipid_entry.sizeof)
            yield(ipid_entry) if block_given?
            ipid_entries << ipid_entry
            pNext = ipid_entry.pNextIPID
          end

          ipid_entries
        end

        def find_oid_buckets_addr
          buffer = INTERNAL_APIPROXY.alloc_c_ary('BYTE', 300)
          sym_info = INTERNAL_APIPROXY.alloc_c_struct('SYMBOL_INFO')
          sym_info.SizeOfStruct = sym_info.sizeof
          sym_info.MaxNameLen = 150
          buffer[0, sym_info.sizeof] = sym_info.str

          if INTERNAL_APIPROXY.symfromname(@handle, 'COIDTable::s_OIDBuckets', buffer) == 1
            sym_info.str = buffer[0, sym_info.sizeof]
            sym_info.Address
          end
        end

        def read_bucket_headers(address)
          headers = []

          TurboRex::Windows::Constants::MAX_BUCKETS_NUM.times do |i|
            header = INTERNAL_APIPROXY.alloc_c_struct('SHashChain')
            header_addr = address + i * header.sizeof
            header.str = @memory.get_page(header_addr, header.sizeof)
            next if header.pNext == header_addr

            headers << [header, header_addr]
          end

          headers
        end

        def close
          # TODO: Unload symbols
          if @process
            @process.close_handle
            @handle = nil
          end
        end

        private

        def iface_vtbl_count(ipid_entry)
          if ipid_entry.pStub # Standard interface stub
            pstub_vtbl = @memory.get_page(ipid_entry.pStub, @ptr_len)
            if_stub_vtbl = INTERNAL_APIPROXY.alloc_c_struct('CInterfaceStubVtbl')
            if_stub_vtbl.str = @memory.get_page(to_ptr(pstub_vtbl) - if_stub_vtbl.Vtbl.stroff, if_stub_vtbl.sizeof)
            if_stub_vtbl.header.DispatchTableCount
          else
            # Get ProxyFileInfo->pStubVtblList->header->DispatchTableCount
            raw_iid = ipid_entry.str[ipid_entry.iid.stroff, ipid_entry.iid.sizeof]
            iid = TurboRex::MSRPC::Utils.raw_to_guid_str(raw_iid)
            proxy_file_info = get_proxy_file_info(iid)
            raise unless proxy_file_info

            # pcif_stub_vtbl_list = to_ptr(@memory.get_page(proxy_file_info.pStubVtblList, @ptr_len))
            # if_stub_vtbl = TurboRex::Windows::COM::INTERNAL_APIPROXY.alloc_c_struct('CInterfaceStubVtbl')
            # if_stub_vtbl.str = @memory.get_page(pcif_stub_vtbl_list, if_stub_vtbl.sizeof)
            # return if_stub_vtbl.header.DispatchTableCount
            get_disptbl_count(proxy_file_info)
          end
        end
      end

      class ClientFinder
        include TurboRex::Utils::COMApiBacktraceHelper

        BACKTRACE_PROC = {
          'CoCreateInstance' => :bt_cocreateinstance
        }

        def initialize(fname_or_dasm)
          if fname_or_dasm.is_a?(String)
            pe = Metasm::PE.decode_file(fname_or_dasm)
            @dasm = _disassemble_executable_sections(pe)
          elsif fname_or_dasm.is_a?(::Metasm::Disassembler)
            @dasm = dasm
          end
        end

        def find_client_call(dis=nil)
          res = []

          BACKTRACE_PROC.each do |k, v|
            @dasm.call_sites(::Metasm::Expression[k]).each do |c|
              bt_result = v.to_proc.call(self, @dasm, c)
              pv = bt_result[:pv]
              clsid = bt_result[:rclsid]
              iid = bt_result[:riid]
              context = bt_result[:context]

              unless pv == :unknown
                func_start = @dasm.find_function_start(c)
                func_end = @dasm.function_including(c).return_address
                return unless func_end
                func_end = func_end.first
                dis ||= @dasm.decoded.values.select  {|di| di.address >= func_start && di.address <= func_end}
                dis.select {|di| di.opcode.props[:saveip]}.each do |di_call|
                  if (obj, vtbl, index = solve_cppobj_call(@dasm, di_call))
                    if obj.reduce_rec.to_s == pv.to_s
                      res << {
                        clsid: clsid,
                        iid: iid,
                        context: context,
                        method_index: index,
                        call_site: di_call.address
                      }
                    end
                  elsif fptr = solve_guard_icall(@dasm, di_call) # TODO: check Guard Flags to detect whether cfg is enabled
                    if fptr.is_a?(::Metasm::Indirection)
                      if fptr.pointer.op == :+ && 
                          fptr.pointer.rexpr.is_a?(Integer) &&
                          fptr.pointer.lexpr.is_a?(::Metasm::Indirection)

                        if fptr.pointer.lexpr.pointer.reduce_rec.to_s == pv.to_s
                          res << {
                            clsid: clsid,
                            iid: iid,
                            context: context,
                            method_index: fptr.pointer.rexpr / (@dasm.cpu.size / 8),
                            call_site: di_call.address
                          }
                        end
                      end
                    end
                  end                  
                end
              end
            end
          end

          res
        end
      end
    end
  end
end
