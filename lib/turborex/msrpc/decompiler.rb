# frozen_string_literal: true

module TurboRex
  module MSRPC
    class IStream
      attr_reader :base
      
      def initialize(isource, base)
        @isource = isource
        @base = @init_base = base
      end

      def read(len, offset=0)
        @isource.read(@base+offset, len)
      end

      def set_base(base)
        @base = base
      end
      
      def base_drift(drift)
        @base += drift
      end

      def reset
        @base = @init_base
        true
      end
    end

    class Decompiler
      include TurboRex::MSRPC::RPCBase
      include TurboRex::MSRPC::MIDL      

      attr_reader :parser

      def initialize(opts = {})
        arch = opts[:arch] || 'x86'
        header_file = TurboRex.root + '/resources/headers/rpc/internal_ndrtypes.h'
        case arch
        when 'x86'
          cpu = Metasm::Ia32
        when 'x64'
          cpu = Metasm::X86_64
        else
          raise 'Unknown architecture'
        end

        @parser = TurboRex::CStruct::NativeParser.new(nil, file: header_file, cpu: cpu, predefined: true)
      end

      def decompile(iface)
        return false if iface.client?
        switches = iface.midl_switches
        return false if switches.has_one_of_switches?(%w[Os])

        mode = :oif
        if switches.has_switch?('Oi')
          mode = :oi
        elsif switches.has_switch?('all') && switches.arch_64?
          return false # TODO: Implement
        end

        public_send "decompile_#{mode}", iface
      end

      def decompile_oif(iface)
        OifDecompiler.new(iface, @parser).decompile
      end

      def parse_proc_fs_header(raw_header, mode = :Oif)
        offset = 0
        header_s = Struct.new(:oi_header, :oif_header, :win2k_ext).new
        oi_header_s = Struct.new(:common, :explicit_handle_desc).new

        oi_header_p1 = @parser.decode_c_struct('Oi_Header_HType_Flags_t', raw_header)
        oi_header = if (oi_header_p1.OiFlags & Oi_HAS_RPCFLAGS) == Oi_HAS_RPCFLAGS
                      @parser.decode_c_struct('Oi_Header_t', raw_header)
                    else
                      @parser.decode_c_struct('Oi_Header_Without_RPCFlags_t', raw_header)
                    end

        oi_header_s.common = oi_header
        offset += oi_header.sizeof
        if oi_header_p1.HandleType == FC_EXPLICIT_HANDLE
          explicit_hdesc = @parser.decode_c_struct('Handle_Desc_Common_t', raw_header, offset)
          case explicit_hdesc.HandleType
          when FC_BIND_PRIMITIVE
            explicit_handle_desc = @parser.decode_c_struct('ExplicitHandlePrimitive_t', raw_header, offset)
          when FC_BIND_GENERIC
            explicit_handle_desc = @parser.decode_c_struct('ExplicitHandleGeneric_t', raw_header, offset)
          when FC_BIND_CONTEXT
            explicit_handle_desc = @parser.decode_c_struct('ExplicitHandleContext_t', raw_header, offset)
          end

          offset += explicit_handle_desc.sizeof
          oi_header_s.explicit_handle_desc = explicit_handle_desc
        end

        header_s.oi_header = oi_header_s

        case mode
        when :Oi
          return oi_header_s, offset
        when :Oif
          oif_header = @parser.decode_c_struct('Oif_Header_t', raw_header, offset)
          offset += oif_header.sizeof
          header_s.oif_header = oif_header

          if (oif_header.InterpreterOptFlags.HasExtensions) == 1 # Has win2k extension part
            size = @parser.decode_c_struct('WIN2K_EXT', raw_header, offset).ExtensionVersion
            case size
            when WIN2K_EXT_SIZE
              win2k_ext = @parser.decode_c_struct('WIN2K_EXT', raw_header, offset)
            when WIN2K_EXT64_SIZE
              win2k_ext = @parser.decode_c_struct('WIN2K_EXT64', raw_header, offset)
            end
            offset += win2k_ext.sizeof
            header_s.win2k_ext = win2k_ext
          end
        when :Os
          raise NotImplementedError
        end

        [header_s, offset]
      end

      def parse_proc_fs_header_dasm(dasm, addr, mode = :Oif)
        offset = 0
        header_s = Struct.new(:oi_header, :oif_header, :win2k_ext).new
        oi_header_s = Struct.new(:common, :explicit_handle_desc).new

        oi_header_p1 = dasm.decode_c_struct('Oi_Header_HType_Flags_t', addr + offset)
        oi_header = if (oi_header_p1.OiFlags & Oi_HAS_RPCFLAGS) == Oi_HAS_RPCFLAGS
                      dasm.decode_c_struct('Oi_Header_t', addr + offset)
                    else
                      dasm.decode_c_struct('Oi_Header_Without_RPCFlags_t', addr + offset)
                    end

        oi_header_s.common = oi_header
        offset += oi_header.sizeof
        if oi_header_p1.HandleType == FC_EXPLICIT_HANDLE
          explicit_hdesc = dasm.decode_c_struct('Handle_Desc_Common_t', addr + offset)
          case explicit_hdesc.HandleType
          when FC_BIND_PRIMITIVE
            explicit_handle_desc = dasm.decode_c_struct('ExplicitHandlePrimitive_t', addr + offset)
          when FC_BIND_GENERIC
            explicit_handle_desc = dasm.decode_c_struct('ExplicitHandleGeneric_t', addr + offset)
          when FC_BIND_CONTEXT
            explicit_handle_desc = dasm.decode_c_struct('ExplicitHandleContext_t', addr + offset)
          end

          offset += explicit_handle_desc.sizeof
          oi_header_s.explicit_handle_desc = explicit_handle_desc
        end

        header_s.oi_header = oi_header_s

        case mode
        when :Oi
          raise NotImplementedError
        when :Oif
          oif_header = dasm.decode_c_struct('Oif_Header_t', addr + offset)
          offset += oif_header.sizeof
          header_s.oif_header = oif_header

          if oif_header.InterpreterOptFlags.HasExtensions == 1 # Has win2k extension part
            size = dasm.decode_c_struct('WIN2K_EXT', addr + offset).ExtensionVersion
            case size
            when WIN2K_EXT_SIZE
              win2k_ext = dasm.decode_c_struct('WIN2K_EXT', addr + offset)
            when WIN2K_EXT64_SIZE
              win2k_ext = dasm.decode_c_struct('WIN2K_EXT64', addr + offset)
            end
            offset += win2k_ext.sizeof
            header_s.win2k_ext = win2k_ext
          end
        when :Os
          raise NotImplementedError
        end

        [header_s, offset]
      end
    end

    class OifDecompiler < Decompiler
      FORMAT_STRING_STYLE = {
        proc_fs: OifProcFormatString,
        param_desc: OifParamDesc
      }

      def initialize(interface, cparser)
        @interface = interface
        @interface.decompiler = self
        @cparser = cparser

        @procfs_stream = nil
        @typefs_stream = nil
        @offset_table = interface.offset_table

        make_istream
      end

      def decompile(interface=nil)
        interface ||= @interface
        midl_interface = Interface.new(interface)

        @offset_table.each do |offset|
          _procfs = @procfs_stream.dup
          _procfs.base_drift(offset)
          proc_fs = FORMAT_STRING_STYLE[:proc_fs].new(_procfs, @typefs_stream, @cparser)
          procedure = proc_fs.decompile
          midl_interface.push_procedure(procedure)
          midl_interface.push_typedef(procedure.typedefs)
        end

        midl_interface
      end

      def parse_proc_fs_header(raw_header, mode = :Oif)
        mode = :Oif
        super(raw_header, mode)
      end

      def parse_proc_fs_header_dasm(dasm, addr, mode = :Oif)
        mode = :Oif
        super(dasm, addr ,mode)
      end

      private

      def make_istream
        unless (@interface.pproc_fs && @interface.ptype_fs && @interface.offset_table)
          raise "The format string is not initialized."
        end

        isource = @interface.finder.pe._isource
        @procfs_stream = IStream.new(isource, @interface.pproc_fs)
        @typefs_stream = IStream.new(isource, @interface.ptype_fs)
        true
      end
    end
  end
end
