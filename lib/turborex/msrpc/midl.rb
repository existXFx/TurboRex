module TurboRex
  module MSRPC
    module MIDL
      include NDRType

      class Interface
        attr_reader :uuid
        attr_reader :typedefs
        attr_reader :if_attrs
        attr_reader :procedures

        def initialize(interface)
          @uuid = interface.uuid
          @typedefs = []
          @if_attrs = [
            Attribute::EndpointAttr.new(interface.endpoints)
          ]
          @procedures = []
        end

        def push_procedure(proc)
          @procedures << proc
        end

        def push_typedef(typedef)
          @typedefs << typedef
        end

        def human

        end
      end

      class Procedure
        attr_reader :proc_num
        attr_accessor :name
        attr_reader :params
        attr_reader :return_type
        attr_reader :arity

        def initialize(proc_num)
          @proc_num = proc_num
          @name = "Proc#{proc_num}"
          @params = []
          @return_type = nil
          @arity = 0
        end

        def push_param(param)
          @params << param
          @arity += 1
        end

        def set_return_type(type)
          @return_type = type
        end

        def typedefs

        end
      end

      class Parameter
        attr_reader :data_type
        attr_accessor :name
        attr_reader :attributes

        def initialize(name, data_type=nil)
          @data_type = data_type
          @name = name
          @attributes = []
          @type_return = false
        end

        def push_attribute(attribute)
          @attributes << attribute
        end

        def set_data_type(type)
          @data_type = type
        end

        def type_return
          @type_return = true
        end

        def is_return_type?
          @type_return
        end
      end

      class Attribute
        def human

        end

        class VersionAttr < Attribute
          SYMBOL_NAME = 'version'

          def initialize(major, minor)
            @major = major 
            @minor = minor
          end
          
          def human

          end
        end

        class EndpointAttr < Attribute
          SYMBOL_NAME = 'endpoint'

          def initialize(endpoints)
            @endpoints = endpoints
          end

          def human

          end
        end

        class UUIDAttr < Attribute
          SYMBOL_NAME = 'uuid'

          def initialize(uuid)
            @uuid = uuid
          end

          def human

          end
        end
      end

      class DataType
        attr_reader :symbol_name
        attr_reader :bytesize

        class BaseType < DataType
          attr_reader :signed

          SYMBOL_NAME_TABLE = [
                               :boolean, 
                               :byte, 
                               :char, 
                               :double, 
                               :float, 
                               :handle_t, 
                               :hyper, 
                               :__int8,
                               :__int16,
                               :int, 
                               :__int32,
                               :__int3264, 
                               :__int64,
                               :long, 
                               :short, 
                               :small, 
                               :wchar_t,
                               :error_status_t
                              ]

          BYTESIZE_MAPPING = {
            boolean: 1,
            byte: 1,
            char: 1,
            double: 8,
            float: 4,
            handle_t: :variable,
            hyper: 8,
            int: 4,
            __int3264: :variable,
            long: 4,
            short: 2,
            small: 1,
            wchar_t: 2,
            error_status_t: 4
          }

          def initialize(symbol_name, signed)
            raise TurboRex::Exception::MSRPC::UnknownSymbolName unless index = SYMBOL_NAME_TABLE.index(symbol_name.to_sym)
            @symbol_name ||= SYMBOL_NAME_TABLE[index]
            @signed = signed
            @bytesize = BYTESIZE_MAPPING[@symbol_name]
          end
        end

        class Pointer < DataType
          attr_reader :pointee
          attr_reader :type
          attr_accessor :level

          def initialize(pointee, type, level=1)
            @pointee = pointee
            @type = type # ref, full, unique
            @level = level

            get_level
          end

          protected

          def get_level
            @pointee.is_a?(Pointer) ? @level += @pointee.get_level : @level
          end
        end
        
        class Enum < DataType
          attr_reader :attributes
          attr_reader :member

          def initialize(symbol_name, *member)
            @symbol_name = symbol_name
            @member = member
            @attributes = []
          end
        end

        class TypeDefinition < DataType
          def initialize(symbol_name, type_specifier, declarator_list, attributes=[])
            @symbol_name = symbol_name
            @type_specifier = type_specifier
            @declarator_list = declarator_list
            @attributes = attributes
          end
        end

        class Array < DataType
          attr_reader :member
          attr_reader :length

          def initialize(*member)
            @member = member
            @length = member.length
          end

          def method_missing(m, *args, &block)
            @member.send(m, *args, &block)
          end
        end
      end

      class ProcFormatString
        include NDRType

        attr_reader :header
        attr_reader :param_desc
        attr_accessor :cparser

        def initialize(procfs_stream, typefs_stream, cparser)
          @procfs_stream = procfs_stream
          @typefs_stream = typefs_stream
          @cparser = cparser
        end

        def decompile

        end

        def fs_length

        end

        private

        def parse_proc_fs_header_stream(stream)

        end
      end

      class ParamDesc
        attr_reader :stream
        attr_reader :typefs
        attr_reader :stack_offset


        def initialize(stream, typefs_stream, cparser, stack_index=nil)
          @stream = stream
          @typefs_stream = typefs_stream # IStream object
          @cparser = cparser
          @stack_index = stack_index
        end

        def decompile

        end

        def fs_length

        end
      end

      class OifParamDesc < ParamDesc
        FS_LENGTH = 6

        attr_reader :param_attrs
        attr_reader :typefs

        # return Parameter object
        def decompile
          raw = @stream.read(FS_LENGTH)
          header = @cparser.decode_c_struct('Oif_ParamDesc_Header_t', raw)

          @param_attrs = header.ParamAttributes
          @stack_offset = header.StackOffset

          case @cparser.cpu.size
          when 32
            ptr_len = 4
          when 64
            ptr_len = 8
          end

          virtual_stack_index = @stack_offset / ptr_len 
          param_name = "arg_#{virtual_stack_index}"

          parameter = Parameter.new(param_name)

          if @param_attrs.IsBasetype == 1
            struct = @cparser.decode_c_struct('Oif_Param_Desc_BaseType_t', raw)
            _stream = @stream.dup
            _stream.base_drift(4)
            data_type = TypeFormatString::SimpleType.new(_stream, @cparser).decompile
          else
            struct = @cparser.decode_c_struct('Oif_Param_Desc_Other_t', raw)
            typefs_offset = struct.TypeOffset
            _typefs_stream = @typefs_stream.dup
            _typefs_stream.base_drift(typefs_offset)
            @typefs = TypeFormatString.new(_typefs_stream, @cparser)

            begin
              data_type = @typefs.decompile
            rescue TurboRex::Exception::MSRPC::InvalidTypeFormatString
              raise TurboRex::Exception::MSRPC::InvalidParamDescriptor
            end
          end

          if @param_attrs.IsSimpleRef == 1 # First-level refenrence pointer
            data_type = DataType::Pointer.new(data_type, :ref)
          end

          parameter.set_data_type(data_type)

          if @param_attrs.IsReturn == 1
            parameter.type_return
            parameter.name = nil
          else
            if @param_attrs.IsIn == 1
              parameter.attributes << :in
            end
  
            if @param_attrs.IsOut == 1
              parameter.attributes << :out
            end
          end


          parameter
        end

        def fs_length
          FS_LENGTH
        end
      end

      class OifProcFormatString < ProcFormatString
        # return Procedure object
        def decompile 
          header, hlength = parse_proc_fs_header_stream(@procfs_stream)
          @header = header
          @param_desc = []
          procedure = Procedure.new(header.oi_header.common.ProcNum)

          offset = hlength
          loop do |i|
            stream = @procfs_stream.dup
            stream.base_drift(offset)

            param_desc = OifParamDesc.new(stream, @typefs_stream, @cparser)

            begin
              param = param_desc.decompile # return Parameter object
            rescue TurboRex::Exception::MSRPC::InvalidParamDescriptor
              break
            end

            @param_desc << param_desc

            if param.is_return_type?
              procedure.set_return_type(param)
            else
              procedure.push_param(param)
            end

            offset += param_desc.fs_length
          end

          procedure
        end

        def parse_proc_fs_header_stream(stream)
          raw_header = stream.read(28)
          offset = 0
          header_s = Struct.new(:oi_header, :oif_header, :win2k_ext).new
          oi_header_s = Struct.new(:common, :explicit_handle_desc).new
  
          oi_header_p1 = @cparser.decode_c_struct('Oi_Header_HType_Flags_t', raw_header)
          oi_header = if (oi_header_p1.OiFlags & Oi_HAS_RPCFLAGS) == Oi_HAS_RPCFLAGS
                        @cparser.decode_c_struct('Oi_Header_t', raw_header)
                      else
                        @cparser.decode_c_struct('Oi_Header_Without_RPCFlags_t', raw_header)
                      end
  
          oi_header_s.common = oi_header
          offset += oi_header.sizeof
          if oi_header_p1.HandleType == FC_EXPLICIT_HANDLE
            explicit_hdesc = @cparser.decode_c_struct('Handle_Desc_Common_t', raw_header, offset)
            case explicit_hdesc.HandleType
            when FC_BIND_PRIMITIVE
              explicit_handle_desc = @cparser.decode_c_struct('ExplicitHandlePrimitive_t', raw_header, offset)
            when FC_BIND_GENERIC
              explicit_handle_desc = @cparser.decode_c_struct('ExplicitHandleGeneric_t', raw_header, offset)
            when FC_BIND_CONTEXT
              explicit_handle_desc = @cparser.decode_c_struct('ExplicitHandleContext_t', raw_header, offset)
            end
  
            offset += explicit_handle_desc.sizeof
            oi_header_s.explicit_handle_desc = explicit_handle_desc
          end
  
          header_s.oi_header = oi_header_s
          oif_header = @cparser.decode_c_struct('Oif_Header_t', raw_header, offset)
          offset += oif_header.sizeof
          header_s.oif_header = oif_header

          if (oif_header.InterpreterOptFlags.HasExtensions) == 1 
            size = @cparser.decode_c_struct('WIN2K_EXT', raw_header, offset).ExtensionVersion
            case size
            when WIN2K_EXT_SIZE
              win2k_ext = @cparser.decode_c_struct('WIN2K_EXT', raw_header, offset)
            when WIN2K_EXT64_SIZE
              win2k_ext = @cparser.decode_c_struct('WIN2K_EXT64', raw_header, offset)
            end
            offset += win2k_ext.sizeof
            header_s.win2k_ext = win2k_ext
          end


          [header_s, offset]
        end
      end

      class TypeFormatString
        include NDRType

        def initialize(typefs_stream, cparser)
          @typefs_stream = typefs_stream
          @cparser = cparser
        end

        # return an object of the subclass of DataType
        def decompile
          fc = @typefs_stream.read(1).unpack('C').first
          select_handler(fc).new(@typefs_stream, @cparser).decompile
        end

        def fs_length

        end

        def select_handler(type_fc)
          HANDLER_TABLE.each do |h|
            if h[:type].include?(type_fc)
              return h[:handler] 
            end
          end

          raise TurboRex::Exception::MSRPC::InvalidTypeFormatString
        end

        class SimpleType < TypeFormatString
          MAPPING = [
            {value: FC_BYTE, mapping: :byte},
            {value: FC_CHAR, mapping: :char},
            {value: FC_SMALL, mapping: :small},
            {value: FC_USMALL, mapping: {type: :small, signed: false}},
            {value: FC_WCHAR, mapping: :wchar_t},
            {value: FC_SHORT, mapping: :short},
            {value: FC_USHORT, mapping: {type: :short, signed: false}},
            {value: FC_LONG, mapping: :long},
            {value: FC_ULONG, mapping: {type: :long, signed: false}},
            {value: FC_FLOAT, mapping: :float},
            {value: FC_HYPER, mapping: :hyper},
            {value: FC_DOUBLE, mapping: :double},
            {value: FC_ERROR_STATUS_T, mapping: :error_status_t},
            {value: FC_INT3264, mapping: :__int3264},
            {value: FC_UINT3264, mapping: {type: :__int3264, signed: false}}
          ]

          def decompile
            type_fc = @typefs_stream.read(1).unpack('C').first
            case type_fc
            when FC_ENUM16
              symbol_name = "DUMMY_ENUM16_#{SecureRandom.hex(2).upcase}".to_sym
              enum = DataType::Enum.new(symbol_name, :dummy_member)

              return DataType::TypeDefinition.new(symbol_name, enum, [symbol_name])
            when FC_ENUM32
              symbol_name = "DUMMY_ENUM32_#{SecureRandom.hex(2).upcase}".to_sym
              enum = DataType::Enum.new(symbol_name, :dummy_member)
              enum.attributes << :v1_enum
              return DataType::TypeDefinition.new(symbol_name, enum, [symbol_name], enum.attributes)
            else
              MAPPING.each do |m|
                if m[:value] == type_fc
                  signed = true
                  if m[:mapping].is_a?(Hash)
                    symbol_name = m[:mapping][:type]
                    signed = m[:mapping][:signed]
                  else
                    symbol_name = m[:mapping]
                  end
                  return DataType::BaseType.new(symbol_name, signed)
                end
              end
            end

            raise TurboRex::Exception::MSRPC::InvalidTypeFormatString
          end
        end

        class CommonPtr < TypeFormatString
          FC_ALLOCATE_ALL_NODES = 0x01
          FC_DONT_FREE = 0x02
          FC_ALLOCED_ON_STACK = 0x04
          FC_SIMPLE_POINTER = 0x08
          FC_POINTER_DEREF =  0x10

          def decompile
            raw = @typefs_stream.read(4)
            header = @cparser.decode_c_struct('CommonPtr_Header_t', raw)

            case  header.PointerType
            when FC_RP
              pointer_type = :ref
            when FC_UP
              pointer_type = :unique
            when FC_FP
              pointer_type = :full
            when FC_OP
              pointer_type = :unknown # Not Implement
            end

            if (header.PointerAttributes & FC_SIMPLE_POINTER) == FC_SIMPLE_POINTER
              struct = @cparser.decode_c_struct('CommonPtr_Simple_t', raw)
              simple_type = struct.SimpleType
              _stream = @typefs_stream.dup
              _stream.base_drift(2)
              pointee = SimpleType.new(_stream, @cparser).decompile
              return DataType::Pointer.new(pointee, pointer_type)
            else
              cstruct = @cparser.find_c_struct('CommonPtr_Complex_t')
              struct = @cparser.decode_c_struct('CommonPtr_Complex_t', raw)
              desc_offset = struct.Offset
              _stream = @typefs_stream.dup
              _stream.base_drift(cstruct.offsetof(@cparser, 'Offset')+desc_offset)
              return TypeFormatString.new(_stream, @cparser).decompile
            end
          end
        end

        class FixedSizedArray < TypeFormatString
          def decompile
            offset = 0
            type = @typefs_stream.read(1).unpack('C').first
            case type
            when FC_SMFARRAY
              size = @cparser.sizeof(@cparser.find_c_struct('SM_FArray_Header_t'))
              header = @cparser.decode_c_struct('SM_FArray_Header_t', @typefs_stream.read(size))
            when FC_LGFARRAY
              size = @cparser.sizeof(@cparser.find_c_struct('LG_FArray_Header_t'))
              header = @cparser.decode_c_struct('LG_FArray_Header_t', @typefs_stream.read(size))
            end

            total_size = header.TotalSize
            offset += size
            _stream = @typefs_stream.dup
            _stream.base_drift(offset)
            if @typefs_stream.read(1, offset).unpack('C').first == FC_PP # Pointer layout
              ptr_layout = PointerLayout.new(_stream, @cparser) # TODO: How to handle when the count of pointer instance greater than one?
              layout = ptr_layout.decompile.first
              offset += ptr_layout.fs_length
              _stream.base_drift(ptr_layout.fs_length)
              element = TypeFormatString.new(_stream, @cparser).decompile
              ary = ::Array.new(layout[:repeat], element)
              case layout[:type]
              when :fixed
                return DataType::Array.new(*ary)
              end
            end

            element = TypeFormatString.new(_stream, @cparser).decompile
            if (element_size = element.bytesize) == :variable
              case @cparser.cpu.size
              when 32
                element_size = 4
              when 64
                element_size = 8
              end
            end

            ary_len = total_size / element_size
            ary = ::Array.new(ary_len, element)
            DataType::Array.new(*ary) 
          end
        end

        class ConformatArray < TypeFormatString
          def decompile
            size = @cparser.sizeof(@cparser.find_c_struct('Conformant_Array_Header_t'))
            header = @cparser.decode_c_struct('Conformant_Array_Header_t', @typefs_stream.read(size))
            
          end
        end

        class PointerLayout < TypeFormatString
          def decompile
            offset = 2
            layouts = []
            loop do
              begin
                layout, len = decompile_instance_layout(offset)
                offset += len
                layouts << layout
              rescue TurboRex::Exception::MSRPC::InvalidTypeFormatString
                break
              end
            end

            @fs_length = offset + 1

            layouts
          end

          def fs_length
            @fs_length
          end

          private 

          def decompile_instance_layout(offset)
            length = 0
            ptr_instance_cstruct = @cparser.find_c_struct('Pointer_Instance_t')
            ptr_instance_size = @cparser.sizeof(ptr_instance_cstruct)
            
            case @typefs_stream.read(1, offset).unpack('C').first
            when FC_NO_REPEAT
              cstruct = @cparser.find_c_struct('No_Repeat_Layout_t')
              size = @cparser.sizeof(cstruct)
              layout = @cparser.decode_c_struct('No_Repeat_Layout_t', @typefs_stream.read(size))
              ptr_desc = layout.PtrDesc
              _stream = @typefs_stream.dup
              _stream.base_drift(offset+cstruct.offsetof(@cparser, 'Simple'))
              length = layout.sizeof
              pointer = CommonPtr.new(_stream, @cparser).decompile

              return {repeat: 0, type: :no_repeat, pointer: pointer}, length
            when FC_FIXED_REPEAT
              cstruct = @cparser.find_c_struct('Fixed_Repeat_Layout_Header_t')
              size = @cparser.sizeof(cstruct)
              layout_header = @cparser.decode_c_struct('Fixed_Repeat_Layout_Header_t', @typefs_stream.read(size, offset))

              ary_size = layout_header.NumberOfPointers
              #ptr_instance_ary = @cparser.decode_c_ary('Pointer_Instance_t', ary_size, @typefs_stream.read(ary_size*ptr_instance_size, offset+size))

              ptr_ary = []
              ary_size.times do |i|
                _stream = @typefs_stream.dup
                _stream.base_drift(offset+layout_header.sizeof+i*ptr_instance_size+ptr_instance_cstruct.offsetof(@cparser, 'Simple'))
                ptr_ary << CommonPtr.new(_stream, @cparser).decompile
              end

              length = layout_header.sizeof + ary_size*ptr_instance_size
              return {repeat: layout_header.Iterations, type: :fixed, pointer: ptr_ary}, length
            when FC_VARIABLE_REPEAT
              cstruct = @cparser.find_c_struct('Variable_Repeat_Layout_Header_t')
              size = @cparser.sizeof(cstruct)
              layout_header = @cparser.decode_c_struct('Variable_Repeat_Layout_Header_t', @typefs_stream.read(size, offset))

              case layout_header.OffsetType
              when FC_FIXED_OFFSET
                offset_type = :fixed
              when FC_VARIABLE_OFFSET
                offset_type = :variable
              end

              ary_size = layout_header.NumberOfPointers
              ptr_ary = []
              ary_size.times do |i|
                _stream = @typefs_stream.dup
                _stream.base_drift(offset+layout_header.sizeof+i*ptr_instance_size+ptr_instance_cstruct.offsetof(@cparser, 'Simple'))
                ptr_ary << CommonPtr.new(_stream, @cparser).decompile
              end

              length = layout_header.sizeof + ary_size*ptr_instance_size
              return {repeat: layout_header.Iterations, type: :variable, offset: offset_type, pointer: ptr_ary}, length
            else
              raise TurboRex::Exception::MSRPC::InvalidTypeFormatString
            end
          end
        end

        HANDLER_TABLE = [
          {
            type: [FC_BYTE,
              FC_CHAR,                    
              FC_SMALL,                   
              FC_USMALL,                  
              FC_WCHAR,                   
              FC_SHORT,                   
              FC_USHORT,                  
              FC_LONG,                    
              FC_ULONG,                   
              FC_FLOAT,                   
              FC_HYPER,                   
              FC_DOUBLE,                  
              FC_ENUM16,                  
              FC_ENUM32,                  
              FC_ERROR_STATUS_T,          
              FC_INT3264,                 
              FC_UINT3264],
            handler: SimpleType
          },
          {
            type: [FC_RP, FC_UP, FC_FP, FC_OP], handler: CommonPtr,
          },
          {
            type: [FC_SMFARRAY, FC_LGFARRAY], handler: FixedSizedArray
          },
          {
            type: [FC_PP], handler: PointerLayout
          }
        ]
      end
    end
  end
end