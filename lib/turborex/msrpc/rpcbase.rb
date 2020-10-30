# frozen_string_literal: true

module TurboRex
  module MSRPC
    module RPCBase
      extend TurboRex::CStruct

      RPC_Struct_Mgr32 = define_structs do
        struct GENERIC_BINDING_ROUTINE_PAIR {
          PVOID pfnBind
          PVOID pfnUnbind
        }

        struct GUID {
          UINT data1
          USHORT data2
          USHORT data3
          BYTE data4[8]
        }

        struct RPC_VERSION {
          USHORT majorVersion
          USHORT minorVersion
        }

        struct RPC_SYNTAX_IDENTIFIER {
          GUID syntaxGUID
          RPC_VERSION syntaxVersion
        }

        struct RPC_SERVER_INTERFACE {
          UINT length
          RPC_SYNTAX_IDENTIFIER interfaceId
          RPC_SYNTAX_IDENTIFIER transferSyntax
          PVOID dispatchTable
          UINT rpcProtseqEndpointCount
          PVOID rpcProtseqEndpoint
          PVOID defaultManagerEpv
          PVOID interpreterInfo
          UINT flags
        }

        struct RPC_PROTSEQ_ENDPOINT {
          PVOID rpcProtocolSequence
          PVOID endpoint
        }

        struct RPC_DISPATCH_TABLE_T {
          UINT dispatchTableCount
          PVOID dispatchTable
          ULONG_PTR_T reserved
        }

        struct MIDL_SERVER_INFO {
          PVOID pStubDesc
          PVOID dispatchTable
          PVOID procString
          PVOID fmtStringOffset
          PVOID thunkTable
          PVOID pTransferSyntax
          PVOID nCount
          PVOID pSyntaxInfo
        }

        struct MIDL_STUB_DESC {
          PVOID rpcInterfaceInformation
          PVOID pfnAllocate
          PVOID pfnFree
          PVOID implicit_handle_info
          PVOID apfnNdrRundownRoutines
          PVOID aGenericBindingRoutinePairs
          PVOID apfnExprEval
          PVOID aXmitQuintuple
          PVOID pFormatTypes
          INT fCheckBounds
          ULONG version
          PVOID pMallocFreeStruct
          LONG midlVersion
          PVOID commFaultOffsets
          PVOID aUserMarshalQuadruple
          PVOID notifyRoutineTable
          ULONG_PTR mFlags
          PVOID csRoutineTables
          PVOID proxyServerInfo
          PVOID pExprInfo
        }

        struct MIDL_STUBLESS_PROXY_INFO {
          PVOID pStubDesc
          PVOID procFormatString
          PVOID formatStringOffset
          PVOID pTransferSyntax
          ULONG_PTR nCount
          PVOID pSyntaxInfo
        }

        struct MIDL_SYNTAX_INFO {
          RPC_SYNTAX_IDENTIFIER transferSyntax
          PVOID dispatchTable
          PVOID procString
          PVOID fmtStringOffset
          PVOID typeString
          PVOID aUserMarshalQuadruple
          PVOID pMethodProperties
          ULONG_PTR pReserved2
        }
      end

      RPC_Struct_Mgr64 = define_structs(arch: 'x64') do
        struct GUID {
          uint data1
          ushort data2
          ushort data3
          BYTE data4[8]
        }

        struct RPC_VERSION {
          ushort majorVersion
          ushort minorVersion
        }

        struct RPC_SYNTAX_IDENTIFIER {
          GUID syntaxGUID
          RPC_VERSION syntaxVersion
        }

        struct RPC_SERVER_INTERFACE {
          UINT length
          RPC_SYNTAX_IDENTIFIER interfaceId
          RPC_SYNTAX_IDENTIFIER transferSyntax
          PVOID dispatchTable
          UINT rpcProtseqEndpointCount
          PVOID rpcProtseqEndpoint
          PVOID defaultManagerEpv
          PVOID interpreterInfo
          UINT flags
        }

        struct RPC_PROTSEQ_ENDPOINT {
          PVOID rpcProtocolSequence
          PVOID endpoint
        }

        struct RPC_DISPATCH_TABLE_T {
          UINT dispatchTableCount
          PVOID dispatchTable
          ULONG_PTR_T reserved
        }

        struct MIDL_STUB_DESC {
          PVOID rpcInterfaceInformation
          PVOID pfnAllocate
          PVOID pfnFree
          PVOID implicit_handle_info
          PVOID apfnNdrRundownRoutines
          PVOID aGenericBindingRoutinePairs
          PVOID apfnExprEval
          PVOID aXmitQuintuple
          PVOID pFormatTypes
          INT fCheckBounds
          ULONG version
          PVOID pMallocFreeStruct
          LONG midlVersion
          PVOID commFaultOffsets
          PVOID aUserMarshalQuadruple
          PVOID notifyRoutineTable
          ULONG_PTR mFlags
          PVOID csRoutineTables
          PVOID proxyServerInfo
          PVOID pExprInfo
        }

        struct MIDL_SERVER_INFO {
          PVOID pStubDesc
          PVOID dispatchTable
          PVOID procString
          PVOID fmtStringOffset
          PVOID thunkTable
          PVOID pTransferSyntax
          PVOID nCount
          PVOID pSyntaxInfo
        }

        struct MIDL_SYNTAX_INFO {
          RPC_SYNTAX_IDENTIFIER transferSyntax
          PVOID dispatchTable
          PVOID procString
          PVOID fmtStringOffset
          PVOID typeString
          PVOID aUserMarshalQuadruple
          PVOID pMethodProperties
          ULONG_PTR pReserved2
        }

        struct MIDL_STUBLESS_PROXY_INFO {
          PVOID pStubDesc
          PVOID procFormatString
          PVOID formatStringOffset
          PVOID pTransferSyntax
          ULONG_PTR nCount
          PVOID pSyntaxInfo
        }
      end

      RPC_SERVER_INTERFACE = RPC_Struct_Mgr32['RPC_SERVER_INTERFACE']
      RPC_SERVER_INTERFACE32 = RPC_Struct_Mgr32['RPC_SERVER_INTERFACE']
      RPC_SERVER_INTERFACE64 = RPC_Struct_Mgr64['RPC_SERVER_INTERFACE']
      RPC_PROTSEQ_ENDPOINT = RPC_Struct_Mgr32['RPC_PROTSEQ_ENDPOINT']
      RPC_PROTSEQ_ENDPOINT32 = RPC_Struct_Mgr32['RPC_PROTSEQ_ENDPOINT']
      RPC_PROTSEQ_ENDPOINT64 = RPC_Struct_Mgr64['RPC_PROTSEQ_ENDPOINT']
      MIDL_SERVER_INFO = RPC_Struct_Mgr32['MIDL_SERVER_INFO']
      MIDL_SERVER_INFO32 = RPC_Struct_Mgr32['MIDL_SERVER_INFO']
      MIDL_SERVER_INFO64 = RPC_Struct_Mgr64['MIDL_SERVER_INFO']
      MIDL_STUB_DESC = RPC_Struct_Mgr32['MIDL_STUB_DESC']
      MIDL_STUB_DESC32 = RPC_Struct_Mgr32['MIDL_STUB_DESC']
      MIDL_STUB_DESC64 = RPC_Struct_Mgr64['MIDL_STUB_DESC']
      MIDL_SYNTAX_INFO = RPC_Struct_Mgr32['MIDL_SYNTAX_INFO']
      MIDL_SYNTAX_INFO32 = RPC_Struct_Mgr32['MIDL_SYNTAX_INFO']
      MIDL_SYNTAX_INFO64 = RPC_Struct_Mgr64['MIDL_SYNTAX_INFO']
      MIDL_STUBLESS_PROXY_INFO = RPC_Struct_Mgr32['MIDL_STUBLESS_PROXY_INFO']
      MIDL_STUBLESS_PROXY_INFO32 = RPC_Struct_Mgr32['MIDL_STUBLESS_PROXY_INFO']
      MIDL_STUBLESS_PROXY_INFO64 = RPC_Struct_Mgr64['MIDL_STUBLESS_PROXY_INFO']
      RPC_DISPATCH_TABLE_T = RPC_Struct_Mgr32['RPC_DISPATCH_TABLE_T']
      RPC_DISPATCH_TABLE_T32 = RPC_Struct_Mgr32['RPC_DISPATCH_TABLE_T']
      RPC_DISPATCH_TABLE_T64 = RPC_Struct_Mgr64['RPC_DISPATCH_TABLE_T']

      GUID = RPC_Struct_Mgr32['GUID']
      RPC_VERSION = RPC_Struct_Mgr32['RPC_VERSION']
      RPC_SYNTAX_IDENTIFIER = RPC_Struct_Mgr32['RPC_SYNTAX_IDENTIFIER']
      RPC_SYNTAX_IDENTIFIER64 = RPC_Struct_Mgr64['RPC_SYNTAX_IDENTIFIER']
      RPC_IF_ID = RPC_SYNTAX_IDENTIFIER

      def self.from_guid_str(guid_str)
        if guid_str.count('-') == 3
          hexData1, hexData2, hexData3, hexData4 = guid_str.split('-')

          data1 = hexData1.to_i(16)
          data2 = hexData2.to_i(16)
          data3 = hexData3.to_i(16)
          data4 = [hexData4.to_i(16)].pack('Q<').unpack('CCCCCCCC')

          guid_struct = GUID.make
          guid_struct['data1'].value = data1
          guid_struct['data2'].value = data2
          guid_struct['data3'].value = data3

          data4.each_with_index do |c, i|
            guid_struct['data4'][i].value = c
          end

          guid_struct
        elsif guid_str.count('-') == 4
          hexData1, hexData2, hexData3, hexData4Hi, hexData4 = guid_str.split('-')

          data1 = hexData1.to_i(16)
          data2 = hexData2.to_i(16)
          data3 = hexData3.to_i(16)
          data4Hi = hexData4Hi.to_i(16)
          data4 = []

          (0...hexData4.length).step(2) do |i|
            data4 << hexData4[i...i + 2].to_i(16)
          end

          guid_struct = GUID.make
          guid_struct['data1'].value = data1
          guid_struct['data2'].value = data2
          guid_struct['data3'].value = data3
          guid_struct['data4'][0].value = data4Hi >> 8
          guid_struct['data4'][1].value = data4Hi & 0xff

          data4.each_with_index do |c, i|
            guid_struct['data4'][i + 2].value = c
          end

          guid_struct
        end
      end

      def self.make_transferSyntax(guid, majorVersion, minorVersion)
        ident = RPC_SYNTAX_IDENTIFIER.make
        ident['syntaxGUID'].from_s from_guid_str(guid).to_s
        ident['syntaxVersion'][0].value = majorVersion
        ident['syntaxVersion'][1].value = minorVersion

        ident
      end

      DCE_TransferSyntax = make_transferSyntax('8A885D04-1CEB-11C9-9FE8-08002B104860', 2, 0)
      NDR64_TransferSyntax = make_transferSyntax('71710533-BEBA-4937-8319-B5DBEF9CCC36', 1, 0)

      module InterfaceType
        UNKNOWN = 0
        RPC = 1
        DCOM = 2
        OLE = 3
      end

      module InterfaceFlag
        RPC_IF_AUTOLISTEN                   = 0x0001
        RPC_IF_OLE                          = 0x0002
        RPC_IF_ALLOW_UNKNOWN_AUTHORITY      = 0x0004
        RPC_IF_ALLOW_SECURE_ONLY            = 0x0008
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH = 0x0010
        RPC_IF_ALLOW_LOCAL_ONLY             = 0x0020
        RPC_IF_SEC_NO_CACHE                 = 0x0040
        RPC_IF_SEC_CACHE_PER_PROC           = 0x0080
        RPC_IF_ASYNC_CALLBACK               = 0x0100

        MAPPING = {
            rpc_if_autolisten: 0x1,
            rpc_if_ole: 0x2,
            rpc_if_allow_unknown_authority: 0x4,
            rpc_if_allow_secure_only: 0x8,
            rpc_if_allow_callbacks_with_no_auth: 0x10,
            rpc_if_allow_local_only: 0x20,
            rpc_if_sec_no_cache: 0x40,
            rpc_if_sec_cache_per_proc: 0x80,
            rpc_if_async_callback: 0x100
        }
      end

      class MIDL_SWITCHES
        SWITCHES = %w[Oi Oic Oif Oicf Os ndr64 all win64 amd64 ia64]
        attr_reader :value

        def initialize
          @value = 0
        end

        def add(switch)
          return @value if has_switch?(switch)
          @value |= mapping_midl_switch(switch)
        end

        def remove(switch)
          @value &= ~mapping_midl_switch(switch)
        end

        def has_switch?(switch)
          integer = mapping_midl_switch(switch)
          !integer.zero? && (@value & integer) == integer
        end

        def has_one_of_switches?(switch)
          switch.each { |s| return true if has_switch?(s)  }
          false
        end

        def has_all_of_switches?(switch)
          res = true
          switch.map {|s|res = false unless has_switch?(s)}
          res
        end

        def arch_64?
          has_one_of_switches?(%w[win64 amd64 ia64])
        end

        def mapping_midl_switch(switch)
          switch = [switch] if switch.is_a?(String)
          case switch
          when Array
            (switch & SWITCHES).map do |s| 
              2**SWITCHES.index(s) 
            end.inject(0, :+)
          when Integer
            SWITCHES.reject do |s|
              ((switch || 0) & 2**SWITCHES.index(s)).zero?
            end
          end
        end

        def to_array
          mapping_midl_switch(@value)
        end

        def to_s
          mapping_midl_switch(@value).join(', ')
        end

        alias_method :<<, :add
      end

      
      class Structures_Klass
        attr_accessor :xrefs

        def initialize(cstruct)
          @xrefs = []
          @value_table = {}          
          @cstruct = cstruct
          parse_struct(cstruct)
        end

        def to_s
          @cstruct.to_s
        end

        def [](key)
          self.send key
        end

        def method_missing(m, *args)
          if m.to_s.end_with?('_Value')
            key = m.to_s.split('_Value')[0].to_sym
            @value_table[key]
          elsif @value_table.keys.map(&:downcase).include?(m.downcase)
            self.define_singleton_method(m) do
              @value_table[m]
            end
            @value_table[m]
          else
            super(m, *args)
          end
        end

        def link_and_xref(var_name, struct)
          self.instance_variable_set ('@'+var_name.to_s).to_sym, struct
          var = struct
          xref_from(struct) unless struct.is_a?(Array)
        end

        def xref_from(cstruct)
          cstruct.xrefs << self
        end
      end

      class GUID_Klass < Structures_Klass
        def initialize(cstruct)
          parse_struct(cstruct)
        end

        def parse_struct(cstruct)
          @value_table = {
            Data1: cstruct['data1'],
            Data2: cstruct['data2'],
            Data3: cstruct['data3'],
            Data4: cstruct['data4']
          }
        end
      end

      class RPC_VERSION_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            MajorVersion: cstruct['majorVersion'],
            MinorVersion: cstruct['minorVersion']
          }
        end
      end

      class RPC_SYNTAX_IDENTIFIER_Klass < Structures_Klass
        attr_accessor :type

        def parse_struct(cstruct)
          @value_table = {
            SyntaxGUID: cstruct['syntaxGUID'].to_s,
            SyntaxVersion:cstruct['syntaxVersion'].to_s
          }

          @type = :interface_id
          guid = @value_table[:SyntaxGUID]
          if guid  == DCE_TransferSyntax.to_s || guid == NDR64_TransferSyntax.to_s
              @type = :transfer_syntax
          end

          @syntax_guid_link_to = GUID_Klass.new(cstruct['syntaxGUID'])
          @syntax_version_link_to = RPC_VERSION_Klass.new(cstruct['syntaxVersion'])

          true
        end

        def SyntaxGUID
           @syntax_guid_link_to || @value_table[:SyntaxGUID]
        end

        def SyntaxVersion
          @syntax_version_link_to || @value_table[:SyntaxVersion]
        end

        def link_to(struct)
          case struct
          when GUID_Klass
            link_and_xref :syntax_guid_link_to, struct
          when RPC_VERSION_Klass
            link_and_xref :syntax_version_link_to, struct
          end
        end
      end

      class RPC_DISPATCH_TABLE_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            DispatchTableCount: cstruct['dispatchTableCount'].value,
            DispatchTable: cstruct['dispatchTable'].to_s,
            Reserved: cstruct['seserved'].to_s
          }

          @dispatch_table_link_to = nil
        end


        def DispatchTable
          @dispatch_table_link_to || @value_table[:DispatchTable]
        end

        def DispatchFunctions # Virtual Field
          self.DispatchTable
        end

        def link_to(dispatch_funcs)
          if dispatch_funcs.is_a?(Array)
            @dispatch_table_link_to = dispatch_funcs
          end
        end
      end

      class RPC_SERVER_INTERFACE_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            Length: cstruct['length'].value,
            InterfaceId: cstruct['interfaceId'].to_s,
            TransferSyntax: cstruct['transferSyntax'].to_s,
            DispatchTable: cstruct['dispatchTable'].value,
            RpcProtseqEndpointCount: cstruct['rpcProtseqEndpointCount'].value,
            RpcProtseqEndpoint: cstruct['rpcProtseqEndpoint'].value,
            DefaultManagerEpv: cstruct['defaultManagerEpv'].value,
            InterpreterInfo: cstruct['interpreterInfo'].value,
            Flags: cstruct['flags'].value
          }

          @interface_id_link_to = nil 
          link_and_xref :interface_id_link_to, RPC_SYNTAX_IDENTIFIER_Klass.new(cstruct['interfaceId'])
          link_and_xref :transfer_syntax_link_to, RPC_SYNTAX_IDENTIFIER_Klass.new(cstruct['transferSyntax'])
          @interpreterInfo_link_to = nil
          @dispatch_table_link_to = nil

          true
        end

        def ndr64?
          NDR64_TransferSyntax.to_s == @value_table[:TransferSyntax]
        end

        def dce?
          DCE_TransferSyntax.to_s == @value_table[:TransferSyntax]
        end

        def dispatch_table_nullptr?
          @value_table[:DispatchTable] == 0
        end

        def interpreter_info_nullptr?
          @value_table[:InterpreterInfo] == 0
        end

        def server_routines
          unless interpreter_info_nullptr?
            begin
              routines = self.InterpreterInfo.server_routines
              return routines
            end
          end

          []
        end

        def InterfaceId
          @interface_id_link_to || @value_table[:InterfaceId]
        end

        def TransferSyntax
          @transfer_syntax_link_to || @value_table[:TransferSyntax]
        end

        def DispatchTable
          @dispatch_table_link_to || @value_table[:DispatchTable]
        end

        def InterpreterInfo
          @interpreterInfo_link_to || @value_table[:InterpreterInfo]
        end

        def link_to(struct)
          if struct.to_s == DCE_TransferSyntax.to_s || struct.to_s == NDR64_TransferSyntax.to_s
            return link_and_xref(:transfer_syntax_link_to, struct)
          end

          case struct
          when RPC_SYNTAX_IDENTIFIER_Klass
            case struct.type
            when :interface_id
              link_and_xref :interface_id_link_to, struct
            when :transfer_syntax
              link_and_xref :transfer_syntax_link_to, struct
            end
          when MIDL_SERVER_INFO_Klass
            link_and_xref :interpreterInfo_link_to, struct
          when RPC_DISPATCH_TABLE_Klass
            link_and_xref :dispatch_table_link_to, struct
          when MIDL_STUBLESS_PROXY_INFO_Klass
            link_and_xref :interpreterInfo_link_to, struct
          end
        end
      end

      class SERVER_ROUTINE_Klass < Structures_Klass
        attr_reader :addr
        attr_reader :proc_num

        def initialize(routine)
          @addr = routine
          @proc_num = nil
        end
      end

      class CLIENT_ROUTINE_Klass < Structures_Klass
        attr_reader :addr
        attr_accessor :proc_num

        def initialize(routine, opts = {})
          @addr = routine
          @proc_num = opts[:proc_num]
        end
      end

      class MIDL_SERVER_INFO_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            pStubDesc: cstruct['pStubDesc'].value,
            DispatchTable: cstruct['dispatchTable'].value,
            ProcString: cstruct['procString'].value,
            ProcFormatString: cstruct['procString'].value, # alias of ProcString
            FmtStringOffset: cstruct['fmtStringOffset'].value,
            FormatStringOffset: cstruct['fmtStringOffset'].value, # alias of FmtStringOffset
            ThunkTable: cstruct['thunkTable'].value,
            pTransferSyntax: cstruct['pTransferSyntax'].value,
            nCount: cstruct['nCount'].value,
            pSyntaxInfo: cstruct['pSyntaxInfo'].value
          }

          @dispatch_table_link_to = nil
          @syntax_info_link_to = nil
          @transfer_syntax_link_to = nil
          @stub_desc_link_to = nil

          true
        end

        def server_routines
          self.DispatchTable rescue nil
        end

        def DispatchTable
          @dispatch_table_link_to || @value_table[:DispatchTable]
        end

        def pStubDesc
          @stub_desc_link_to || @value_table[:pStubDesc]
        end

        def pSyntaxInfo
          @syntax_info_link_to || @value_table[:pSyntaxInfo]
        end

        def link_to(struct)
          case struct
          when Array
            @dispatch_table_link_to = struct
          when MIDL_STUB_DESC_Klass
            link_and_xref :stub_desc_link_to, struct
          when MIDL_SYNTAX_INFO_Klass, Array
            link_and_xref :syntax_info_link_to, struct
          end
        end
      end

      class MIDL_SYNTAX_INFO_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            TransferSyntax: cstruct['transferSyntax'],
            DispatchTable: cstruct['dispatchTable'].value,
            ProcString: cstruct['procString'].value,
            FmtStringOffset: cstruct['fmtStringOffset'].value,
            TypeString: cstruct['typeString'].value,
            aUserMarshalQuadruple: cstruct['aUserMarshalQuadruple'].value,
            pMethodProperties: cstruct['pMethodProperties'].value,
            pReserved2: cstruct['pReserved2'].value
          }

          @dispatch_table_link_to = nil
        end

        def DispatchTable
          @dispatch_table_link_to || @value_table[:DispatchTable] 
        end

        def link_to(struct)
          if struct.is_a? RPC_DISPATCH_TABLE_Klass
            link_and_xref :dispatch_table_link_to, struct
          end
        end
      end

      class MIDL_STUBLESS_PROXY_INFO_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            pStubDesc: cstruct['pStubDesc'].value,
            ProcFormatString: cstruct['procFormatString'].value,
            FormatStringOffset: cstruct['formatStringOffset'].value,
            pTransferSyntax: cstruct['pTransferSyntax'].value,
            nCount: cstruct['nCount'].value,
            pSyntaxInfo: cstruct['pSyntaxInfo'].value
          }

          @stub_desc_link_to = nil
          @syntax_info_link_to = nil
          @transfer_syntax_link_to = nil
        end

        def link_to(struct)
          case struct
          when MIDL_STUB_DESC_Klass
            link_and_xref :stub_desc_link_to, struct
          when MIDL_SYNTAX_INFO_Klass
            link_and_xref :syntax_info_link_to, struct
          end
        end
      end

      class MIDL_STUB_DESC_Klass < Structures_Klass
        def parse_struct(cstruct)
          @value_table = {
            RpcInterfaceInformation: cstruct['rpcInterfaceInformation'].value,
            pfnAllocate: cstruct['pfnAllocate'].value,
            pfnFree: cstruct['pfnFree'].value,
            pAutoHandle: cstruct['implicit_handle_info'].value,
            pPrimitiveHandle: cstruct['implicit_handle_info'].value,
            pGenericBindingInfo: cstruct['implicit_handle_info'].value,
            apfnNdrRundownRoutines: cstruct['apfnNdrRundownRoutines'].value,
            aGenericBindingRoutinePairs: cstruct['aGenericBindingRoutinePairs'].value,
            apfnExprEval: cstruct['apfnExprEval'].value,
            aXmitQuintuple: cstruct['aXmitQuintuple'].value,
            pFormatTypes: cstruct['pFormatTypes'].value,
            fCheckBounds: cstruct['fCheckBounds'].value,
            Version: cstruct['version'].value,
            pMallocFreeStruct: cstruct['pMallocFreeStruct'].value,
            MIDLVersion: cstruct['midlVersion'].value,
            CommFaultOffsets: cstruct['commFaultOffsets'].value,
            aUserMarshalQuadruple: cstruct['aUserMarshalQuadruple'].value,
            NotifyRoutineTable: cstruct['notifyRoutineTable'].value,
            mFlags: cstruct['mFlags'].value,
            CsRoutineTables: cstruct['csRoutineTables'].value,
            ProxyServerInfo: cstruct['proxyServerInfo'].value,
            pExprInfo: cstruct['pExprInfo'].value
          }

          @interface_info_link_to = nil
          @format_types_link_to = nil

          true
        end

        def pFormatTypes
          @value_table[:pFormatTypes] || @format_types_link_to
        end

        def link_to(struct)
          if struct.is_a? RPC_SERVER_INTERFACE_Klass
            link_and_xref :interface_info_link_to, struct
          end
        end
      end
    end
  end
end
