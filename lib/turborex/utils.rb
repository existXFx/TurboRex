# frozen_string_literal: true

module TurboRex
  module Utils
    def self.get_all_subdir(root_path)
      require 'find'
      paths = []
      Find.find(root_path) do |path|
        if FileTest.directory?(path)
          if File.basename(path)[0] == '.'
            Find.prune
          else
            paths << path
          end
        end
      end

      paths
    end

    module DisassemblerHelper
      # https://github.com/jjyg/metasm/blob/master/samples/dasm-plugins/imm2off.rb
      def addrtolabel(dasm)
        bp = dasm.prog_binding.invert
        dasm.decoded.each_value do |di|
          next unless di.is_a?(Metasm::DecodedInstruction)

          di.each_expr do |e|
            next unless e.is_a?(Metasm::Expression)

            if l = bp[e.lexpr]
              dasm.add_xref(e.lexpr, Metasm::Xref.new(:addr, di.address))
              e.lexpr = Metasm::Expression[l]
            end
            if l = bp[e.rexpr]
              dasm.add_xref(e.rexpr, Metasm::Xref.new(:addr, di.address))
              e.rexpr = (e.lexpr ? Metasm::Expression[l] : l)
            end
          end
        end
        nil
      end

      def add_dasm_all_method(dasm)
        dasm.instance_eval %(
          def dasm_all(addrstart, length, method=:disassemble_fast_deep)
            s = get_section_at(addrstart)
            return if not s
            s = s[0]
            boff = s.ptr
            off = 0
            while off < length
              if di = di_at(addrstart + off)
                off += di.bin_length
              elsif @decoded[addrstart+off]
                off += 1
              else
                s.ptr = boff+off
                maydi = cpu.decode_instruction(s, 0)
                if not maydi
                  off += 1
                elsif maydi.instruction.to_s =~ /nop|lea (.*), \[\1(?:\+0)?\]|mov (.*), \2|int 3/
                  off += maydi.bin_length
                else
                  send(method, addrstart+off)
                end
              end
            end

            count = 0
            off = 0
            while off < length
              addr = addrstart+off
              if di = di_at(addr)
                if di.block_head?
                  b = di.block
                  if not @function[addr] and b.from_subfuncret.to_a.empty? and b.from_normal.to_a.empty?
                    l = auto_label_at(addr, 'sub_orph')
                    @function[addrstart+off] = Metasm::DecodedFunction.new
                    @function[addrstart+off].finalized = true
                    detect_function_thunk(addr)
                    count += 1
                  end
                end
                off += di.bin_length
              else
                off += 1
              end
            end

          end
        )

        dasm
      end

      def _disassemble_executable_sections(pe, method=:disassemble_fast_deep)
        dasm = pe.disassembler
        executable_sections = pe.section_info.select {|s| s.last.to_s.split(',').include?('MEM_EXECUTE')}
        unless executable_sections.empty?
          add_dasm_all_method(dasm)
          executable_sections.each do |name, address, len|
            dasm.dasm_all(address, len, method)
          end

          addrtolabel(dasm)
          dasm
        end
      end

      # https://github.com/jjyg/metasm/blob/2a088ff85e5b873570bc284a97ddd9f8b3b0a03a/metasm/gui/dasm_main.rb#L413
      def backtrace(addr, dasm, e, narg={})
        bd = {}
        expr = Metasm::IndExpression.parse_string(e)
        registers = (begin
                        dasm.cpu.dbg_register_list.map(&:to_s)
                      rescue StandardError
                        []
                      end)
        expr.externals.grep(String).each do |w|
          bd[w] = w.downcase.to_sym if registers.include? w.downcase
        end

        expr = expr.bind(bd).reduce do |e_|
          e_.len ||= dasm.cpu.size / 8 if e_.is_a? Metasm::Indirection; nil
        end

        log = []
        found = []
        bt_opts = { log: log }
        bt_opts.merge!(narg)
        dasm.backtrace(expr, addr, bt_opts)
        if found_log = log.assoc(:found)
          found_log[1].each do |expr|
            found << dasm.resolve(expr)
          end
        end

        [found, log]
      end

      def solve_cppobj_call(dasm, di)
        return unless di.opcode.props[:saveip]	
        fptr = dasm.get_xrefs_x(di)
        return if fptr.to_a.length != 1
        fptr = ::Metasm::Expression[fptr.first].reduce_rec
        return unless fptr.kind_of? ::Metasm::Indirection
        return unless fptr.pointer.lexpr.kind_of? Symbol  
        return unless fptr.pointer.rexpr.kind_of? Integer
        log = []
        vtbl = dasm.backtrace(fptr.pointer.lexpr, di.address, log: log)
        vtbl.delete ::Metasm::Expression::Unknown

        if vtbl.empty?
          r = log.reverse_each.detect {|l| l[0] != :found && l[2] != ::Metasm::Expression[:unknown]}
          vtbl =  r[2].reduce_rec
        else
          vtbl = vtbl.first
        end

        vtbl = ::Metasm::Expression[vtbl].reduce_rec
        return unless vtbl.kind_of? ::Metasm::Indirection
        obj = vtbl.pointer
        ptr_size = @dasm.program.cpu.size / 8
        [obj, vtbl, fptr.pointer.rexpr / ptr_size]
      end

      def solve_guard_icall(dasm, di)
        return unless di.opcode.props[:saveip]	
        fptr = dasm.get_xrefs_x(di)
        return if fptr.to_a.length != 1
        fptr = ::Metasm::Expression[fptr.first].reduce_rec
        return unless fptr.kind_of? ::Metasm::Indirection

        v = case dasm.cpu.size
        when 32
           dasm.program.decode_loadconfig.guard_check_icall
        when 64
           dasm.program.decode_loadconfig.guard_dispatch_icall
        end

        #f = dasm.decode_dword(dasm.normalize(dasm.prog_binding[v.to_s])).to_s
        if v == fptr.pointer
          case dasm.cpu.size
          when 32
            expr = :ecx
          when 64
            expr = :rax
          end

          log = []
          res = dasm.backtrace(expr, di.address, log: log)
          res.delete ::Metasm::Expression::Unknown
          if res.empty?
            r = log.reverse_each.detect {|l| l[0] != :found && l[2] != ::Metasm::Expression[:unknown]}
            return r[2].reduce_rec
          end

          return res.first
        end
      end
    end

    module COMApiBacktraceHelper
      include DisassemblerHelper
      
      def bt_cocreateinstance(dasm, addr, filter={})
        case dasm.cpu.size
        when 32
          expr_rclsid = '[esp]'
          expr_context = '[esp+8]'
          expr_riid = '[esp+12]'
          expr_pv = '[[esp+16]]'
        when 64
          expr_rclsid = 'rcx'
          expr_context = 'r8'
          expr_riid = 'r9'
          expr_pv = '[[rsp+32]]'
        end

        rclsid, context, riid, pv = [:unknown]*4
        # rclsid
        found, _ = backtrace(addr, dasm, expr_rclsid)
        unless found.empty?
          raw_rclsid = dasm.read_raw_data(found.first, 16)
          rclsid = TurboRex::MSRPC::Utils.raw_to_guid_str(raw_rclsid)
          if filter[:rclsid]
            return unless rclsid == filter[:rclsid]
          end
        end

        #context
        found, _ = backtrace(addr, dasm, expr_context)
        unless found.empty?
          context = found.first
          if filter[:context]
            return unless context == filter[:context]
          end
        end

        # riid
        found, _ = backtrace(addr, dasm, expr_riid)
        unless found.empty?
          raw_riid = dasm.read_raw_data(found.first, 16)
          riid = TurboRex::MSRPC::Utils.raw_to_guid_str(raw_riid)
          if filter[:riid]
            return unless riid == filter[:riid]
          end
        end

        # pv
        log = []
        found, _ = backtrace(addr, dasm, expr_pv, log: log)
        found.delete ::Metasm::Expression::Unknown
        if found.empty?
          r = log.reverse_each.detect {|l| l[0] != :found && l[2] != ::Metasm::Expression[:unknown]}
          pv = r[2].reduce_rec
        else
          pv = found.first
        end


        {rclsid: rclsid, context: context, riid: riid, pv: pv}
      end

      # TODO: Backtrace ServerInfo
      def bt_cocreateinstanceex(dasm, addr, filter={})
        case dasm.cpu.size
        when 32
          expr_rclsid = '[esp]'
          expr_context = '[esp+8]'
          expr_count = '[esp+16]'
          expr_results = '[esp+20]'
        when 64
          expr_rclsid = 'rcx'
          expr_context = 'r8'
          expr_count = 'dword ptr [rsp+32]'
          expr_results = '[rsp+40]'
        end

        rclsid, context, iids = [:unknown]*3

        # rclsid
        found, _ = backtrace(addr, dasm, expr_rclsid)
        unless found.empty?
          raw_rclsid = dasm.read_raw_data(found.first, 16)
          rclsid = TurboRex::MSRPC::Utils.raw_to_guid_str(raw_rclsid)
          if filter[:rclsid]
            return unless rclsid == filter[:rclsid]
          end
        end

        #context
        found, _ = backtrace(addr, dasm, expr_context)
        unless found.empty?
          context = found.first
          if filter[:context]
            return unless context == filter[:context]
          end
        end

        # results and count
        found, _ = backtrace(addr, dasm, expr_count)
        unless found.empty?
          count = found.first
          iids = []
          size = dasm.alloc_c_struct('MULTI_QI').sizeof
          count.times do |i|
            expr_iid = "[#{expr_results}+#{i*size}]"
            found, _ = backtrace(addr, dasm, expr_iid)
            unless found.empty?
              iids << found.first
            end
          end
        end

        {rclsid: rclsid, context: context, iids: iids}
      end
    end
  end
end
