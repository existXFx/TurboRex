# frozen_string_literal: true

module TurboRex
  module MSRPC
    module RPCFinder

      # This module provides a set of helper functions 
      # that backtracking RPC runtime routines parameters to determine information 
      # such as address of security callback function and rpc flags.
      module StaticRPCBacktracer
        include TurboRex::Utils::DisassemblerHelper

        # RpcServerRegisterIf2/RpcServerRegisterIf3/RpcServerRegisterIfEx
        def bt_security_callback(dasm, trace_flags=false, uuid=nil)
          res = []

          case dasm.cpu.size
          when 64
            expr_if_handle = 'rcx'
            expr_sec_cb = '[rsp+30h]'
            expr_flag = 'r9' if trace_flags
            mk_struct_proc = Proc.new {
              TurboRex::MSRPC::RPCBase::RPC_SERVER_INTERFACE64.make(pack: 8, align: true)
            }
          when 32
            expr_if_handle = '[esp]'
            expr_sec_cb = '[esp+14h]'
            expr_flag = '[esp+Ch]' if trace_flags
            mk_struct_proc = Proc.new {
              TurboRex::MSRPC::RPCBase::RPC_SERVER_INTERFACE32.make(pack: 4, align: true)
            }
          end

          fn = ['RpcServerRegisterIf2', 'RpcServerRegisterIf3', 'RpcServerRegisterIfEx']
          fn.each do |f|
            callers = dasm.call_sites(Metasm::Expression[f])
            callers.each do |addr|
              server_if = mk_struct_proc.call
              if_handle = backtrace(addr, dasm, expr_if_handle).first.first

              next unless raw = dasm.read_raw_data(if_handle, server_if.slength)
              server_if.from_s(raw) 
              interface_id = TurboRex::MSRPC::Utils.raw_to_guid_str(server_if['interfaceId'].to_s)

              found, _ = backtrace(addr, dasm, expr_sec_cb)
              found_flags, _ = backtrace(addr, dasm, expr_flag) if trace_flags
              if dasm.get_section_at(found.first)
                r = {interface_id: interface_id, callback: found.first}
                r[:flags] = found_flags.first.to_i if trace_flags
                res << r
              end
            end
          end

          res.uniq!

          case uuid
          when String
            return res.select {|r| r[:interface_id] == uuid}
          when Array
            return res.select { |r| uuid.include?(r[:interface_id])}
          else
            return res
          end
        end
      end

      class Collection
        attr_reader :server_interfaces
        attr_reader :client_interfaces

        def initialize
          @server_interfaces = []
          @client_interfaces = []
        end

        def push_server(i)
          @server_interfaces << i
        end

        def push_client(i)
          @client_interfaces << i
        end

        def draw_xrefs
          @server_interfaces.each do |si|
            ci = find_client_by_server(si)
            next if ci.empty?

            si.xrefs_to << ci
            ci.xrefs_from << si

            si.uniq!
            ci.uniq!
          end

          true
        end

        def find_server_by_client(client)
          @server_interfaces.select { |i| i.interface_id == client.interface_id }
        end

        def find_client_by_server(server)
          @client_interfaces.select { |i| i.interface_id == server.interface_id }
        end

        def find_by_interface_id(id, filter = nil)
          case filter
          when nil
            @server_interfaces.select { |i| i.interface_id == id } + \
              @client_interfaces.select { |i| i.interface_id == id }
          when :server
            @server_interfaces.select { |i| i.interface_id == id }
          when :client
            @client_interfaces.select { |i| i.interface_id == id }
          end
        end

        def find_by_routine(routine)
          @server_interfaces.select { |i| i.routines.include?(routine) } + \
            @client_interfaces.select { |i| i.routines.include?(routine) }
        end

        def find_by_midl_switches(*switches)
          @server_interfaces.select { |i| i.midl_switches.has_one_of_switches?(switches) } + \
            @client_interfaces.select { |i| i.midl_switches.has_one_of_switches?(switches) }
        end
      end

      class ImageFinder
        include TurboRex::Utils::DisassemblerHelper

        class AutoFindConf
          def initialize
            @options = {
              include_client: true,
              find_client_routines: false
            }
          end

          def build
            @options
          end

          def exclude_client
            @options[:include_client] = false
          end

          def only_client
            @options[:only_client] = true
          end

          def find_client_routines
            @options[:find_client_routines] = true if @options[:include_client]
          end

          alias only_server exclude_client
        end

        include Rex::PeParsey
        include TurboRex::MSRPC::RPCBase
        include TurboRex::PEFile
        include TurboRex::PEFile::Scanner
        include TurboRex::MSRPC::RPCFinder::StaticRPCBacktracer

        class InterfaceModel
          attr_accessor :dasm
          attr_reader :struct
          attr_accessor :protocol
          attr_reader :interface_id
          attr_reader :uuid
          attr_reader :interface_ver
          attr_reader :midl_switches
          attr_reader :finder

          attr_accessor :decompiler
          attr_accessor :routines
          attr_accessor :xrefs_to
          attr_accessor :xrefs_from
          attr_accessor :endpoints

          attr_accessor :pproc_fs
          attr_accessor :offset_table
          attr_accessor :ptype_fs


          def initialize(struct, finder, dasm = nil)
            @struct = struct # RPC_SERVER_INTERFACE_Klass
            @protocol = get_protocol
            @interface_id = @uuid = TurboRex::MSRPC::Utils.raw_to_guid_str(struct.InterfaceId_Value)
            @interface_ver = get_interface_ver
            @transfer_syntax = TurboRex::MSRPC::Utils.raw_to_guid_str(struct.TransferSyntax_Value)
            @transfer_syntax_ver = get_trans_syntax_ver
            @midl_switches = RPCBase::MIDL_SWITCHES.new
            @dasm = dasm || finder.dasm
            @endpoints = []
            @finder = finder
            @routines = []
            @xrefs_to = []
            @xrefs_from = []
          end

          def server?
            !@struct.dispatch_table_nullptr?
          end

          def client?
            !server?
          end

          def set_fs
            return false if client?
            analysis_midl_switches

            pe = finder.pe
            @poffset_table = pe.vma_to_file_offset(self.InterpreterInfo.FormatStringOffset_Value)
            @pproc_fs = pe.vma_to_file_offset(self.InterpreterInfo.ProcFormatString_Value)

            if @midl_switches.has_switch?('Oi')
              @ptype_fs = pe.vma_to_file_offset(self.InterpreterInfo.pStubDesc.pFormatTypes_Value)
              mode = :Oi
            elsif @midl_switches.has_switch?('all') && @midl_switches.arch_64?
              return false # TODO: Implement
            elsif @midl_switches.has_switch?('Oicf')
              @ptype_fs = pe.vma_to_file_offset(self.InterpreterInfo.pStubDesc.pFormatTypes_Value)
            end

            true
          end

          def decompile
            return false unless set_fs

            @finder.ndr_decompiler.decompile(self)
          end

          def func_in_server_routines?(addr)
            func_in_server_routines(addr).empty? ? false : true
          end

          def func_in_server_routines(addr)
            return false unless server?

            @finder.disassemble_executable_sections
            res = []

            routines = @routines
            routines.each do |r|
              res << r if @finder.has_path?(dasm, r.addr, addr)
            end

            res
          end

          def analysis_midl_switches
            # Don't analyze the client interfaces. It is performed when parsing the client dispatch functions.
            if server?
              dispatch_funcs = @struct.DispatchTable.DispatchTable

              # TODO: Refine the parse methods with format string
              # Oi/Oicf/ndr64
              unless dispatch_funcs.empty?
                begin
                  @dasm.disassemble dispatch_funcs[0]
                rescue StandardError
                  return false
                end

                label = @dasm.get_label_at dispatch_funcs[0]
                case label
                when /NdrServerCall2/i
                  @midl_switches << %w[Oif Oicf]
                when /NdrServerCall/i
                  @midl_switches << %w[Oi Oic]
                when /NdrServerCallNdr64/i
                  if @struct.ndr64?
                    @midl_switches << 'ndr64'
                    @midl_switches << %w[win64 amd64 ia64]
                  end
                end
              end

              if (@struct.Flags & 0x6000000) == 0x6000000 # test /Oicf /protocol all /win64(amd64/ia64)
                interpreter_info = @struct.InterpreterInfo
                unless interpreter_info == 0
                  if interpreter_info.nCount >= 2 && interpreter_info.ProcString != 0
                    begin
                      interpreter_info.pSyntaxInfo.each do |syntax_info|
                        disp_funcs = syntax_info.DispatchTable.DispatchFunctions
                        @dasm.disassemble disp_funcs.first
                        label = @dasm.get_label_at disp_funcs.first

                        next unless label =~ /NdrServerCallAll/

                        @midl_switches << 'all'
                        @midl_switches << %w[win64 amd64 ia64]
                        @protocol = :all
                      end
                    rescue StandardError
                      # TODO: exception handle
                    end
                  end
                end
              end

              # Os is contradictory with '/protocol ndr64/all'
              unless @midl_switches.has_one_of_switches?(%w[Oi Oic Oif Oicf ndr64 all])
                if @struct.interpreter_info_nullptr? && @struct.Flags == 0
                  @midl_switches << 'Os'
                end
              end
            end
          end

          def method_missing(m, *args)
            if m.to_s.start_with?('raw_')
              camelcase_name = camelcase(m.to_s.sub('raw_', ''))
              if @struct.respond_to? camelcase_name
                @struct.public_send camelcase_name, *args
              end
            elsif @struct.respond_to? m
              @struct.public_send m, *args
            else
              begin
                @struct.public_send m, *args
              rescue StandardError
                super(m, *args)
              end
            end
          end

          private

          def get_protocol
            @protocol = if @struct.ndr64?
                          :ndr64
                        elsif @struct.dce?
                          :dce
                        else
                          :unknown
                        end
          end

          def get_interface_ver
            major = @struct.InterfaceId.SyntaxVersion.MajorVersion
            minor = @struct.InterfaceId.SyntaxVersion.MinorVersion
            get_syntax_version(major, minor)
          end

          def get_trans_syntax_ver
            major = @struct.TransferSyntax.SyntaxVersion.MajorVersion
            minor = @struct.TransferSyntax.SyntaxVersion.MinorVersion
            get_syntax_version(major, minor)
          end

          def get_syntax_version(_major, _minor)
            major = _major.to_s.unpack('S')[0]
            minor = _minor.to_s.unpack('S')[0]
            "#{major}.#{minor}"
          end

          def camelcase(str)
            str.split('_').collect(&:capitalize).join
          end
        end

        attr_reader :pe
        attr_reader :dasm
        attr_reader :ndr_decompiler
        attr_reader :server_interfaces
        attr_reader :midl_server_infos
        attr_reader :midl_syntax_infos
        attr_reader :midl_stubless_proxy_infos
        attr_reader :dispatch_funcs
        attr_reader :server_routines

        attr_reader :client_interfaces
        attr_reader :client_routines

        def initialize(pe, _opts = {})
          open_file(pe)

          @server_interfaces = []
          @midl_server_infos = []
          @midl_stub_descs = []
          @midl_syntax_infos = []
          @midl_stubless_proxy_infos = []
          @server_routines = []
          @dispatch_funcs = []
          @client_interfaces = []
          @dasm = new_dasm
          @collection_proxy = _opts[:collection_proxy]

          arch = @pe.ptr_32? ? 'x86' : 'x64'
          @ndr_decompiler = TurboRex::MSRPC::Decompiler.new(arch: arch)
        end

        def self.glob_all(root)
          Dir.glob(root + '/**/*')
        end

        def self.glob(path, suffixes = nil)
          pattern = []
          suffixes&.each { |suffix| pattern << File.join(path, '*') + suffix }

          if block_given?
            Dir.glob(pattern) do |filename|
              yield(filename)
            end
          else
            Dir.glob(pattern)
          end
        end

        def open_file(filename)
          begin
            @pe = TurboRex::PEFile::PE.new_from_file(filename)
            @pe.image_path = Pathname.new(filename)
          rescue FileHeaderError
            return false
          end

          pe
        end

        def close
          unless @pe.nil?
            @pe.close
            @pe = nil
          end

          true
        end

        def auto_find(&block)
          default = TurboRex::MSRPC::RPCFinder::ImageFinder::AutoFindConf.new
          config = if block_given?
                     Docile.dsl_eval(default, &block).build
                   else
                     default.build
                   end

          internal_auto_find(config)
        end

        def make_rpc_server_interface(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::RPC_SERVER_INTERFACE32.make(pack: 4, align: true)
          else
            TurboRex::MSRPC::RPCBase::RPC_SERVER_INTERFACE64.make(pack: 8, align: true)
          end
        end

        def make_midl_server_info(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::MIDL_SERVER_INFO32.make
          else
            TurboRex::MSRPC::RPCBase::MIDL_SERVER_INFO64.make
          end
        end

        def make_midl_stubless_proxy_info(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::MIDL_STUBLESS_PROXY_INFO32.make(pack: 4, align: true)
          else
            TurboRex::MSRPC::RPCBase::MIDL_STUBLESS_PROXY_INFO64.make(pack: 8, align: true)
          end
        end

        def make_midl_syntax_info(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::MIDL_SYNTAX_INFO32.make(pack: 4, align: true)
          else
            TurboRex::MSRPC::RPCBase::MIDL_SYNTAX_INFO64.make(pack: 8, align: true)
          end
        end

        def make_rpc_dispatch_table_t(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::RPC_DISPATCH_TABLE_T.make(pack: 4, align: true)
          else
            TurboRex::MSRPC::RPCBase::RPC_DISPATCH_TABLE_T64.make(pack: 8, align: true)
          end
        end

        def make_rpc_protseq_endpoint(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::RPC_PROTSEQ_ENDPOINT32.make(pack: 4, align: true)
          else
            TurboRex::MSRPC::RPCBase::RPC_PROTSEQ_ENDPOINT64.make(pack: 8, align: true)
          end
        end

        def make_midl_stub_desc(pe)
          if pe.ptr_32?
            TurboRex::MSRPC::RPCBase::MIDL_STUB_DESC.make(pack: 4, align: true)
          else
            TurboRex::MSRPC::RPCBase::MIDL_STUB_DESC64.make(pack: 8, align: true)
          end
        end

        def get_midl_server_info(rpc_server_if)
          reconstruct_midl_server_info(@pe, rpc_server_if)
        end

        def get_midl_stub_desc(midl_server_info)
          reconstruct_midl_stub_desc(@pe, midl_server_info)
        end

        def get_stubless_pinfo_from_client_if(rpc_client_if)
          reconstruct_stubless_pinfo(@pe, rpc_client_if)
        end

        def get_midl_syntax_info(midl_server_info)
          reconstruct_midl_syntax_info(@pe, midl_server_info)
        end

        def get_dispatch_table(rpc_server_if)
          reconstruct_disptbl_for_server_interface(@pe, rpc_server_if)
        end

        def get_offset_table(rpc_server_if)
          reconstruct_offset_table(@pe, rpc_server_if)
        end

        def get_offset_table2(disptbl, midl_server_info)
          reconstruct_offset_table2(@pe, disptbl, midl_server_info)
        end

        def get_endpoint_info(rpc_server_if)
          reconstruct_endpoint_info(@pe, rpc_server_if)
        end

        def get_disp_functions(rpc_dispatch_table)
          reconstruct_disp_functions(@pe, rpc_dispatch_table)
        end

        def get_rpc_server_routines(midl_server_info, count)
          reconstruct_disptbl_for_midl_server_info(@pe, midl_server_info, count)
        end

        def get_routines_from_server_interface(rpc_server_interface)
          if has_interpreter_info?(rpc_server_interface)
            disptbl = get_dispatch_table(rpc_server_interface)
            midl_server_info = get_midl_server_info(rpc_server_interface)
            count = disptbl['dispatchTableCount'].value

            get_rpc_server_routines(midl_server_info, count) if count > 0
          end
        end

        def find_rpc_server_interface(opts = {})
          rpc_server_interface = make_rpc_server_interface(@pe)
          regexp = Regexp.new [rpc_server_interface.slength].pack('V')
          res = []
          opts[:only_data_section] ||= true

          if opts[:only_data_section]
            @pe.data_sections.each do |s|
              TurboRex::PEFile::Scanner.scan_section(s, regexp).each do |r|
                rpc_server_interface = make_rpc_server_interface(@pe)
                next unless reconstruct_struct_from_pe(@pe, r[0], rpc_server_interface) > 0
                
                if validate_rpc_server_interface(@pe, rpc_server_interface)
                  yield(rpc_server_interface, r[0]) if block_given?
                  res << rpc_server_interface
                end
              end
            end
          else
            addr_info = TurboRex::PEFile::Scanner.scan_all_sections(@pe, regexp)
            unless addr_info.empty?
              addr_info.each do |addr|
                rpc_server_interface = make_rpc_server_interface(@pe)
                if reconstruct_struct_from_pe(@pe, addr[0], rpc_server_interface) > 0
                  yield(rpc_server_interface, addr[0]) if block_given?
                  res << rpc_server_interface
                end
              end
            end
          end

          res
        end

        def find_client_disp_functions(va, dasm, expr, *funcs)
          disassemble_executable_sections(dasm)
          # addrtolabel(dasm)
          dispatch_funcs = []

          if expr.nil?
            case dasm.cpu.size
            when 64
              expr = 'rcx'
            when 32
              expr = '[esp]'
            end
          end

          funcs.each do |func|
            callers = dasm.call_sites(Metasm::Expression[func])
            callers.each do |addr|
              found, log = backtrace(addr, dasm, expr)
              next unless found.include?(va)

              # Finding proc number
              proc_num = nil
              case func
              when 'NdrClientCall' # Oi, conflict with 64-bit platform
                expr_procnum = '[esp+4]'
                switch = :Oi
              when 'NdrClientCall2' # Oicf
                expr_procnum = dasm.cpu.size == 64 ? 'rdx' : '[esp+4]'
                switch = :Oicf
              when 'NdrClientCall3'
                expr_procnum = 'rdx'
              when 'NdrClientCall4' # ?
                expr_procnum = dasm.cpu.size == 64 ? 'rdx' : '[esp+4]'
              end

              _found, _log = backtrace(addr, dasm, expr_procnum)

              unless _found.empty?
                if func == 'NdrClientCall3'
                  proc_num = _found.first
                else
                  _dasm = dasm.dup
                  _dasm.c_parser = @ndr_decompiler.parser
                  fs_header, header_len = @ndr_decompiler.parse_proc_fs_header_dasm(_dasm, _found[0])
                  proc_num = fs_header.oi_header.common.ProcNum
                end
              end

              yield(addr, dasm) if block_given?
              func_start = dasm.find_function_start(addr)
              dispatch_funcs << {
                dispatch_func: func_start,
                backtrace: [func, va, log],
                proc_num: proc_num
              }
            end
          end

          dispatch_funcs
        end

        def find_client_routines(client_if, client_if_addr, dasm = nil)
          dasm = @dasm || (@dasm = new_dasm)
          disp_funcs = []

          if has_proxy_info?(client_if) # stubless proxy, no dispatch table and thunk table
            if proxy_info = get_stubless_pinfo_from_client_if(client_if)
              pi_obj = TurboRex::MSRPC::RPCBase::MIDL_STUBLESS_PROXY_INFO_Klass.new(proxy_info)
              pinterpreter_info = client_if.InterpreterInfo_Value
              @midl_stubless_proxy_infos << pi_obj
              client_if.midl_switches << %w[all win64 amd64 ia64]
              client_if.link_to pi_obj
              disp_funcs = find_client_disp_functions(pinterpreter_info, dasm, nil, 'NdrClientCall3')
            end
          else
            xrefs = scan_xrefs_immediate(client_if_addr, dasm)
            xrefs.each do |xref|
              midl_stub_desc = make_midl_stub_desc(@pe)
              reconstruct_struct_from_pe(@pe, @pe.vma_to_rva(xref), midl_stub_desc)
              next unless validate_midl_stub_desc(@pe, midl_stub_desc)

              stub_desc_obj = MIDL_STUB_DESC_Klass.new(midl_stub_desc)
              stub_desc_obj.link_to client_if
              @midl_stub_descs << stub_desc_obj

              disp_funcs = find_client_disp_functions(xref, dasm, nil, 'NdrClientCall', 'NdrClientCall2', 'NdrClientCall4')

              # TODO: detect switches when using NdrClientCall4
              next unless b = disp_funcs[0]&.fetch(:backtrace) { }

              client_if.midl_switches << %w[Oi Oic] if b[0] == 'NdrClientCall'
              if b[0] == 'NdrClientCall2'
                client_if.midl_switches << %w[Oif Oicf]
              end
            end
          end

          disp_funcs.map do |m|
            r = TurboRex::MSRPC::RPCBase::CLIENT_ROUTINE_Klass.new(m[:dispatch_func])
            r.proc_num = m[:proc_num]
            r
          end.uniq(&:addr)
        end

        def validate_transfer_syntax(transfer_syntax)
          transfer_syntax.to_s == DCE_TransferSyntax.to_s || transfer_syntax.to_s == NDR64_TransferSyntax.to_s
        end

        def validate_rpc_server_interface(pe, rpc_server_interface)
          length = rpc_server_interface.slength
          return false unless rpc_server_interface['length'].value == length
          unless validate_transfer_syntax(rpc_server_interface['transferSyntax'])
            return false
          end

          itpInfo = rpc_server_interface['interpreterInfo'].value # vma
          if itpInfo == 0
            # TODO: Inline stub check
          else
            section = pe._find_section_by_rva(pe.vma_to_rva(itpInfo))
            return false if section.nil?
            return false unless TurboRex::PEFile::Scanner.data_section?(section)
          end

          dispTable = rpc_server_interface['dispatchTable'].value
          unless dispTable == 0
            section = pe._find_section_by_rva(pe.vma_to_rva(dispTable))
            return false if section.nil?
            return false unless TurboRex::PEFile::Scanner.data_section?(section)
          end

          true
        end

        def validate_server_interface_from_pe(pe, address)
          make_rpc_server_interface(pe)
          reconstruct_struct_from_pe(pe, address, rpc_server_interface)
          validate_rpc_server_interface(pe, rpc_server_interface)
        end

        def validate_midl_stub_desc(pe, struct)
          pfnAllocate = struct['pfnAllocate'].value
          pfnFree = struct['pfnFree'].value
          phandle = struct['implicit_handle_info'].value
          bounds_flag = struct['fCheckBounds'].value

          # TODO: more check(version)
          pointer_check = pe.valid_vma?(pfnAllocate) && pe.valid_vma?(pfnFree)
          # && pe.valid_vma?(phandle)
          # Rex library valid_vma? method make a mistake here.
          bounds_flag_check = (bounds_flag == 1 || bounds_flag == 0)

          pointer_check && bounds_flag
        end

        # The "strict_check" option will use the algorithm of NdrClientCall3
        def validate_stubless_proxy_info(pe, stubless_proxy_info, strict_check = true)
          pTransferSyntax = stubless_proxy_info['pTransferSyntax'].value
          pSyntaxInfo = stubless_proxy_info['pSyntaxInfo'].value
          nCount = stubless_proxy_info['nCount'].value
          dce_transfer = DCE_TransferSyntax.to_s
          ndr64_transfer = NDR64_TransferSyntax.to_s
          len = make_midl_syntax_info(pe).slength

          return false if pTransferSyntax == 0

          transfer_syntax = pe._isource.read(pe.vma_to_file_offset(pTransferSyntax), DCE_TransferSyntax.slength)
          unless transfer_syntax == dce_transfer || transfer_syntax == ndr64_transfer
            return false
          end

          if strict_check
            nCount.times do |i|
              syntaxinfo_trans = pe._isource.read(pe.vma_to_file_offset(pSyntaxInfo + i * len), DCE_TransferSyntax.slength)
              break if syntaxinfo_trans == transfer_syntax
              return false if i + 1 == nCount
            end
          end

          true
        end

        def reconstruct_struct_from_pe(pe, rva, cstruct)
          length = cstruct.slength
          data = pe._isource.read(pe.rva_to_file_offset(rva), length)
          cstruct.from_s data
        end

        def reconstruct_offset_table(pe, server_if)   
          if server_if['interpreterInfo'].value != 0
            server_info = reconstruct_midl_server_info(pe, server_if)

            unless server_info.nil?
              pdisptbl = pe.vma_to_rva(server_if['dispatchTable'].value)
              disptbl = reconstruct_disptbl_from_addr(pe, pdisptbl)

              reconstruct_offset_table2(pe, disptbl, server_info)
            end
          end
        end

        def reconstruct_offset_table2(pe, disptbl, midl_server_info)
          poffset_table = pe.vma_to_file_offset(midl_server_info['fmtStringOffset'].value)
          count = disptbl['dispatchTableCount'].value
          pe._isource.read(poffset_table, count).unpack('C'*count)
        end

        def reconstruct_endpoint_info(pe, server_if)
          endpoints = []

          if (count = server_if['rpcProtseqEndpointCount'].value) > 0
            rva = pe.vma_to_rva(server_if['rpcProtseqEndpoint'].value)

            count.times do |i|
              ep = make_rpc_protseq_endpoint(pe)
              reconstruct_struct_from_pe(pe, rva+i*ep.slength, ep)
              pprotseq = pe.vma_to_file_offset(ep['rpcProtocolSequence'].value)
              pendpoint = pe.vma_to_file_offset(ep['endpoint'].value)

              protseq = TurboRex::MSRPC::Utils.read_cstring(pe._isource, pprotseq)[0]
              ep_name = TurboRex::MSRPC::Utils.read_cstring(pe._isource, pendpoint)[0]
              endpoints << {protseq: protseq, ep_name: ep_name}
              i+=ep.slength
            end

          end

          endpoints
        end

        def reconstruct_stubless_pinfo(pe, client_if)
          proxy_info = make_midl_stubless_proxy_info(pe)
          pinterpreter_info = client_if.InterpreterInfo_Value
          rva = pe.vma_to_rva(pinterpreter_info)
          reconstruct_struct_from_pe(pe, rva, proxy_info)
          proxy_info if validate_stubless_proxy_info(pe, proxy_info)
        end

        def reconstruct_midl_syntax_info(pe, midl_server_info)
          pSyntaxInfo = midl_server_info['pSyntaxInfo'].value
          count = midl_server_info['nCount'].value
          return nil if count < 0

          syntax_infos = []

          if pe.ptr_32?
            len = TurboRex::MSRPC::RPCBase::MIDL_SYNTAX_INFO32.make(pack: 4, align: true).slength
          else
            len = TurboRex::MSRPC::RPCBase::MIDL_SYNTAX_INFO64.make(pack: 8, align: true).slength
          end

          unless pSyntaxInfo == 0
            count.times do |i|
              rva = pe.vma_to_rva(pSyntaxInfo + i * len)
              midl_syntax_info = make_midl_syntax_info(pe)
              reconstruct_struct_from_pe(pe, rva, midl_syntax_info)

              syntax_infos << midl_syntax_info
            end
          end

          syntax_infos
        end

        def reconstruct_midl_server_info(pe, rpc_server_interface)
          if validate_rpc_server_interface(pe, rpc_server_interface) && has_interpreter_info?(rpc_server_interface)
            rva = pe.vma_to_rva(rpc_server_interface['interpreterInfo'].value)
            midl_server_info = make_midl_server_info(pe)
            reconstruct_struct_from_pe(pe, rva, midl_server_info)

            midl_server_info
          end
        end

        def reconstruct_midl_stub_desc(pe, midl_server_info)
          unless midl_server_info['pStubDesc'].value == 0
            rva = pe.vma_to_rva(midl_server_info['pStubDesc'].value)
            midl_stub_desc = make_midl_stub_desc(@pe)
            reconstruct_struct_from_pe(pe, rva, midl_stub_desc)
            midl_stub_desc if validate_midl_stub_desc(pe, midl_stub_desc)
          end
        end

        def reconstruct_disptbl_for_server_interface(pe, rpc_server_interface)
          rva = pe.vma_to_rva(rpc_server_interface['dispatchTable'].value)
          reconstruct_disptbl_from_addr(pe, rva)
        end

        def reconstruct_disptbl_from_addr(pe, addr)
          rpc_dispatch_table = make_rpc_dispatch_table_t(pe)
          reconstruct_struct_from_pe(pe, addr, rpc_dispatch_table)

          rpc_dispatch_table
        end

        def reconstruct_disp_functions(pe, rpc_dispatch_table)
          count = rpc_dispatch_table['dispatchTableCount'].value
          pdispatch_table = pe.vma_to_rva(rpc_dispatch_table['dispatchTable'].value)
          dispatch_funcs = []

          if pe.ptr_32?
            ptr_len = 4
            format = 'V'
            func_name = 'read_dword'
          else
            ptr_len = 8
            format = 'Q<'
            func_name = 'read_qword'
          end

          unless pdispatch_table == 0
            count.times do |i|
              code = "#{func_name}(pe._isource, pe.rva_to_file_offset(pdispatch_table + #{i * ptr_len})).unpack('#{format}')[0]"
              begin
                dispatch_funcs << eval(code)
              rescue StandardError
                next
              end
            end
          end

          dispatch_funcs
        end

        def reconstruct_disptbl_for_midl_server_info(pe, midl_server_info, count)
          rva = pe.vma_to_rva(midl_server_info['dispatchTable'].value)
          server_routines = []

          if pe.ptr_32?
            count.times do
              server_routines << read_dword(pe._isource, pe.rva_to_file_offset(rva)).unpack('V')[0]
              rva += 4
            end
          else
            count.times do
              server_routines << read_qword(pe._isource, pe.rva_to_file_offset(rva)).unpack('Q<')[0]
              rva += 8
            end
          end

          server_routines
        end

        def new_dasm
          exe = Metasm::PE.decode_file @pe.image_path.to_s

          exe.disassembler
        end

        def scan_xrefs_immediate(addr, dasm = nil)
          dasm ||= (@dasm || new_dasm)
          cpu_size = dasm.cpu.size
          mask = (1 << cpu_size) - 1
          format = (cpu_size == 64 ? 'q' : 'V')
          res = []

          dasm.sections.sort.each do |start_addr, encoded_data|
            raw = encoded_data.data.to_str
            (0..raw.length - cpu_size / 8).each do |offset|
              data = raw[offset, cpu_size / 8].unpack(format).first
              res << (start_addr + offset) if data == addr
            end
          end

          res
        end


        # Xrefs in the same binary file
        def draw_ifs_xrefs
          @server_interfaces.each do |si|
            @client_interfaces.each do |ci|
              calls = []
              ci.routines.each do |cr|
                unless (res = si.func_in_server_routines(cr.addr)).empty?
                  calls << { caller: res, called: cr }
                end
              end

              next if calls.empty?

              si.xrefs_from << [ci, calls]
              ci.xrefs_to << [si, calls]

              si.xrefs_from.uniq!
              si.xrefs_to.uniq!
            end
          end
        end



        def disassemble(addr, dasm = nil)
          dasm ||= (@dasm || new_dasm)
          res = dasm.disassemble addr
          [dasm, res]
        end

        def disassemble_fast_deep(addr, dasm = nil)
          dasm ||= (@dasm || new_dasm)
          res = dasm.disassemble_fast_deep(addr)
          [dasm, res]
        end

        def disassemble_fast(addr, dasm = nil)
          dasm ||= (@dasm || new_dasm)
          res = dasm.disassemble_fast(addr)
          [dasm, res]
        end

        def decompile_func(addr)
          dasm = disassemble_fast(addr)[0]
          dasm.decompiler.decompile(addr) # Metasm::C::Parser
        end

        def disassemble_executable_sections(dasm = nil)
          exe_sections = @pe.executable_sections
          unless exe_sections.empty?
            dasm ||= (@dasm || new_dasm)
            add_dasm_all_method(dasm)

            exe_sections.each do |s|
              dasm.dasm_all(@pe.rva_to_vma(s.base_rva), s.raw_size)
            end

            addrtolabel(dasm)
            dasm
          end
        end

        private

        def read_dword(isource, address)
          isource.read(address, 4)
        end

        def read_qword(isource, address)
          isource.read(address, 8)
        end

        def has_interpreter_info?(rpc_server_interface)
          # Don't assume when flag is set. Must check if InterpreterInfo is a null pointer.
          (rpc_server_interface['flags'].value & 0x4000000) == 0x4000000 && \
            rpc_server_interface['interpreterInfo'].value != 0
        end

        def has_proxy_info?(rpc_server_interface)
          flags = (begin
                     rpc_server_interface['flags'].value
                   rescue StandardError
                     rpc_server_interface.Flags
                   end)
          interpreter_info = (begin
                                rpc_server_interface['interpreterInfo'].value
                              rescue StandardError
                                rpc_server_interface.InterpreterInfo
                              end)
          (flags & 0x2000000) == 0x2000000 && \
            interpreter_info != 0
        end

        def internal_auto_find(config = {})
          @server_interfaces = []
          @dispatch_funcs = []
          @server_routines = []
          @client_routines = []
          @client_interfaces = []
          @midl_stub_descs = []

          find_rpc_server_interface do |r, s_addr|
            next if r.nil?
            si_obj = TurboRex::MSRPC::RPCBase::RPC_SERVER_INTERFACE_Klass.new(r)
            interface = InterfaceModel.new si_obj, self
            interface.endpoints = get_endpoint_info(r)

            if interface.dispatch_table_nullptr? # maybe client
              next unless config[:include_client]

              @client_interfaces << interface
              @collection_proxy&.push_client(interface)

              if config[:find_client_routines]
                cr = find_client_routines(interface, @pe.rva_to_vma(s_addr))
                @client_routines |= cr
                interface.routines = cr
              end

            else # server
              next if config[:only_client]

              @server_interfaces << interface
              @collection_proxy&.push_server(interface)

              disp_table = get_dispatch_table(r)
              disp_func = get_disp_functions(disp_table)
              @dispatch_funcs |= disp_func

              disp_table_obj = TurboRex::MSRPC::RPCBase::RPC_DISPATCH_TABLE_Klass.new(disp_table)
              disp_table_obj.link_to disp_func
              interface.link_to disp_table_obj

              msi = get_midl_server_info(r)
              if msi.nil? # Inline stub(-Os mode)
                @dispatch_funcs |= disp_func
              else
                msi_obj = TurboRex::MSRPC::RPCBase::MIDL_SERVER_INFO_Klass.new(msi)
                @midl_server_infos << msi_obj
                interface.link_to msi_obj

                # find all server routines
                routines = get_routines_from_server_interface(r)
                unless routines.nil?
                  r_objs = routines.map { |r| TurboRex::MSRPC::RPCBase::SERVER_ROUTINE_Klass.new(r) }
                  @server_routines |= r_objs
                  interface.routines = r_objs
                  msi_obj.link_to r_objs
                end

                # reconstruct MIDL_SYNTAX_INFO
                midl_syntax_info = get_midl_syntax_info(msi)
                unless midl_syntax_info.nil? || midl_syntax_info.empty?
                  objs = []
                  midl_syntax_info.each do |m|
                    syntax_info_obj = TurboRex::MSRPC::RPCBase::MIDL_SYNTAX_INFO_Klass.new(m)
                    pdisp_tbl = syntax_info_obj.DispatchTable
                    unless pdisp_tbl == 0
                      disptbl = reconstruct_disptbl_from_addr(@pe, @pe.vma_to_rva(pdisp_tbl))
                      disp_funcs =  reconstruct_disp_functions(@pe, disptbl)
                      disptbl_obj = RPC_DISPATCH_TABLE_Klass.new(disptbl)
                      disptbl_obj.link_to disp_funcs
                      syntax_info_obj.link_to disptbl_obj
                    end

                    @midl_syntax_infos << syntax_info_obj
                    objs << syntax_info_obj
                  end

                  msi_obj.link_to objs
                end

                # reconstruct MIDL_STUB_DESC
                midl_stub_desc = get_midl_stub_desc(msi)
                unless midl_stub_desc.nil?
                  stub_desc_obj = TurboRex::MSRPC::RPCBase::MIDL_STUB_DESC_Klass.new(midl_stub_desc)
                  msi_obj.link_to stub_desc_obj
                end

                # reconstruct offset_table
                interface.offset_table = get_offset_table2(disp_table, msi)
              end
            end

            interface.analysis_midl_switches if config[:analysis_switches]
          end
        end
      end

      class MemoryFinder
        attr_reader :process
        attr_reader :header

        include TurboRex::Windows::Utils
        include TurboRex::MSRPC::Utils

        using ::RefineAllocCStruct

        ## Abstract data model for some key rpc structures
        class RPC_Interface
          attr_accessor :flags
          attr_accessor :interface_type
          attr_accessor :interface_id
          attr_accessor :name
          attr_accessor :syntax
        end

        class RPC_Endpoint
        end

        class RPC_AuthInfo
        end

        def initialize(pid, opts = {})
          raise 'Not work on non-Windows os.' unless ::OS.windows?

          if opts[:debug_priv]
            unless Metasm::WinOS.get_debug_privilege
              raise 'Unable to get SeDebugPrivilege.'
            end
          end

          @process = open_process(pid)
          @mem = @process.memory
          opts[:force_load] ||= {}

          unless load_headers(opts[:force_load])
            raise 'Unable to load RPC structure definitions.'
          end

          @header.prepare_visualstudio

          @gRpcServer = nil
          @rpc_interfaces = []
          @server_interfaces = []
          @endpoints = []
        end

        def self.list_process_pid
          TurboRex::Windows.list_all_process_pid
        end

        def close
          @process.close
        end

        def process_handle
          @process.handle
        end

        def find_rpc_server
          @gRpcServer = find_global_rpc_server
        end

        def enum_rpc_interfaces(rpc_server_t)
          num_entries = rpc_server_t.InterfaceDict.NumberOfEntries
          dictsize = num_entries * ptr_len

          rpc_interface_t = @header['RPC_INTERFACE_T'] # read data as RPC_INTERFACE_T
          begin
            data = @mem.get_page(rpc_server_t.InterfaceDict.pArray, dictsize)
            return false if data.nil?

            (0..dictsize).step(ptr_len) do |p|
              prpc_interface_t = if pe.ptr_32?
                                   data[p, ptr_len].unpack('V')[0]
                                 else
                                   data[p, ptr_len].unpack('Q<')[0]
                                 end

              interface_t = rpc_interface_t.from_str(@mem.get_page(prpc_interface_t, rpc_interface_t.size))
              get_rpc_interfaces_info(interface_t)
            end
          rescue StandardError
            false
          end
        end

        def get_rpc_interfaces_info(rpc_interface)
          info = TurboRex::MSRPC::RPCFinder::MemoryFinder::RPC_Interface.new
          info.flags = rpc_interface.Flags
          info.interface_type = get_interface_type(rpc_interface)
          info.interface_id = TurboRex::MSRPC::Utils.raw_to_guid_str(rpc_interface.RpcServerInterface.InterfaceId.to_string)
          if info.interface_type == TurboRex::MSRPC::RPCBase::InterfaceType::DCOM
            info.name = get_com_interface_name(info.interface_id)
          end
          info.syntax = TurboRex::MSRPC::Utils.raw_to_guid_str(rpc_interface.RpcServerInterface.TransferSyntax.to_string)

          case info.interface_type
          when TurboRex::MSRPC::RPCBase::InterfaceType::RPC
            get_location(rpc_interface.RpcServerInterface.DispatchTable)
          end
        end

        def get_interface_type(rpc_interface)
          if rpc_interface.Flags == @header.numeric_constants.assoc('RPC_IF_OLE')[1]
            return TurboRex::MSRPC::RPCBase::InterfaceType::OLE
          end

          uuid = TurboRex::MSRPC::Utils.raw_to_guid_str(rpc_interface.RpcServerInterface.InterfaceId.to_string)
          if get_com_interface_name(uuid)
            return TurboRex::MSRPC::RPCBase::InterfaceType::DCOM
          end

          TurboRex::MSRPC::RPCBase::InterfaceType::RPC
        end

        def get_com_interface_name(interface_id)
          require 'win32/registry'
          case @arch
          when 'x86'
            prefix = ''
          when 'x64'
            prefix = 'Wow6432Node\\'
          end
          begin
            Win32::Registry::HKEY_CLASSES_ROOT.open(prefix + "Interface\\{#{interface_id}}") do |reg|
              return reg.read('')[1] # default value
            end
          rescue StandardError
            false
          end
        end

        def get_location(_addr)
          raise NotImplementedError
        end

        def scan_marker(marker, range, size = marker.size, step = 1)
          mem = @mem
          res = []

          range.step(step) do |va|
            data = mem.get_page(va, size)
            yield(data, va) if block_given?

            unless data.nil?
              res << va if data == marker
            end
          end

          res
        end

        def find_global_rpc_server
          rpcrt4 = @process.modules.select { |m| m.path =~ /rpcrt4.dll/i }[0]

          pe = TurboRex::PEFile::PE.new_from_file(rpcrt4.path)
          data_section = pe.sections.select { |s| s.name == '.data' }[0]
          startaddr = rpcrt4.addr + data_section.vma
          endaddr = startaddr + data_section._section_header.v['Misc']
          ptr_len = pe.ptr_32? ? 4 : 8 && @header.llp64
          max_entries = @header.numeric_constants.assoc('MAX_SIMPLE_DICT_ENTRIES')[1]
          pe.close

          scan_marker(nil, startaddr..endaddr, ptr_len) do |data|
            pointer = if pe.ptr_32?
                        data.unpack('V')[0]
                      else
                        data.unpack('Q<')[0]
                      end

            rpc_server_t = @header['RPC_SERVER_T'] # read data as RPC_SERVER_T
            begin
              data = @mem.get_page(pointer, rpc_server_t.size)
            rescue StandardError
              next
            end
            rpc_server_t.from_str data

            num_entries = rpc_server_t.InterfaceDict.NumberOfEntries
            dictsize = num_entries * ptr_len
            next if num_entries > max_entries || num_entries <= 0

            rpc_interface_t = @header['RPC_INTERFACE_T'] # read data as RPC_INTERFACE_T
            begin
              data = @mem.get_page(rpc_server_t.InterfaceDict.pArray, dictsize)
              next if data.nil?

              (0..dictsize).step(ptr_len) do |p|
                prpc_interface_t = if pe.ptr_32?
                                     data[p, ptr_len].unpack('V')[0]
                                   else
                                     data[p, ptr_len].unpack('Q<')[0]
                                   end

                interface_t = rpc_interface_t.from_str(@mem.get_page(prpc_interface_t, rpc_interface_t.size))
                if interface_t.pRpcServer == pointer
                  if interface_t.RpcServerInterface.TransferSyntax.to_string == TurboRex::MSRPC::RPCBase::DCE_TransferSyntax.to_s
                    return rpc_server_t
                  end
                end
              end
            rescue StandardError
              next
            end
          end
        end

        private

        def open_process(pid)
          p = TurboRex::Windows.open_process(pid, Metasm::WinAPI::PROCESS_VM_READ)
          raise "Unable to open process #{pid}" if p.nil?

          case p.addrsz
          when 32
            @arch = 'x86'
          when 64
            @arch = 'x64'
          end

          p
        end

        def load_headers(force_load = {})
          headers_path = TurboRex.root + '/resources/headers/rpc'
          include_path = TurboRex::Utils.get_all_subdir(headers_path)
          version_hl = get_version('rpcrt4.dll')
          version = ((version_hl[0] << 32) + version_hl[1])
          opts = {}
          distance = 0
          approximation = nil

          opts[:include_path] = include_path
          if force_load[:file] && force_load[:cpu]
            return force_load_file(force_load)
          end

          if @process.addrsz == 32
            opts[:cpu] = Metasm::Ia32
            pattern = '/v*_x86/rpcinternals.h'
          elsif @process.addrsz == 64
            opts[:cpu] = Metasm::X86_64
            pattern = '/v*_x64/rpcinternals.h'
          end

          Dir.glob(headers_path + pattern).each do |f|
            opts[:file] = f
            native_parser = TurboRex::CStruct::NativeParser.new(nil, opts)
            initializer = native_parser.parser.toplevel.symbol['RPC_CORE_RUNTIME_VERSION'].initializer
            initializer.each do |i|
              if i.rexpr == version
                @header = native_parser
                return true
              else
                d = (version - i.rexpr).abs
                distance = d if distance == 0

                if d < distance
                  approximation = [i.rexpr, native_parser]
                  distance = d
                end
              end
            end
          end

          if force_load[:approximation]
            @header = approximation[1]
            @approximation = approximation
          end

          true
        end

        def force_load_file(opts)
          @header = TurboRex::CStruct::NativeParser.new(nil, opts)
        end
      end
    end
  end
end
