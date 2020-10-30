warn "\033[33m[-]Warning: This module doesn't currently work on non-Windows os.\033[0m" unless OS.windows?

module TurboRex
  class Windows < Metasm::WinOS
    module ALPC
      include ::TurboRex::Windows::Constants
      
      PORMSG_PAD = 0x100

      ALPC_MSGFLG_REPLY_MESSAGE = 0x1
      ALPC_MSGFLG_LPC_MODE = 0x2 
      ALPC_MSGFLG_RELEASE_MESSAGE = 0x10000
      ALPC_MSGFLG_SYNC_REQUEST = 0x20000 
      ALPC_MSGFLG_WAIT_USER_MODE = 0x100000
      ALPC_MSGFLG_WAIT_ALERTABLE = 0x200000
      ALPC_MSGFLG_WOW64_CALL = 0x80000000 

      ALPC_MESSAGE_SECURITY_ATTRIBUTE = 0x80000000
      ALPC_MESSAGE_VIEW_ATTRIBUTE = 0x40000000
      ALPC_MESSAGE_CONTEXT_ATTRIBUTE = 0x20000000
      ALPC_MESSAGE_HANDLE_ATTRIBUTE = 0x10000000
      ALPC_MESSAGE_TOKEN_ATTRIBUTE = 0x8000000
      ALPC_MESSAGE_DIRECT_ATTRIBUTE = 0x4000000
      ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE = 0x2000000

      ALPC_PORFLG_ALLOW_LPC_REQUESTS = 0x20000 

      def self.const_missing(name)
        super(name) unless APIProxy.initialized?
        const = APIProxy.cp.numeric_constants.assoc(name.to_s)
        super(name) if const.nil?

        const[1]
      end

      class APIProxy < Metasm::WinAPI
        def self.init(cpu = Metasm::Ia32)
          if @initialized
            return true
          end

          opts = {}
          opts[:cpu] = cpu
          opts[:include_path] = [TurboRex.root + "/resources/headers/alpc"]
          opts[:visual_studio] = true
          opts[:data_model] = 'llp64' if cpu == Metasm::X86_64
          opts[:predefined] = true

          @np = TurboRex::CStruct::NativeParser.new(nil, opts)
          @cp = @np.parser
          @cp.parse("#define NT_VERSION #{TurboRex::Windows.version.join}")
          @cp.parse_file TurboRex.root + '/resources/headers/alpc/ntlpcapi.h'
          new_api_c('ntdll.dll')

          @initialized = true
        end

        def self.reload(cpu = Metasm::Ia32)
          @initialized = false
          init(cpu)
        end

        def self.initialized?
          @initialized
        end

        def self.new_api_c(fromlib = nil)
          cp.toplevel.symbol.dup.each_value { |v|
            next if not v.kind_of? Metasm::C::Variable # enums
            cp.toplevel.symbol.delete v.name
            lib = fromlib || lib_from_sym(v.name)
            addr = sym_addr(lib, v.name)
            if addr == 0 or addr == -1 or addr == 0xffff_ffff or addr == 0xffffffff_ffffffff
              api_not_found(lib, v)
              next
            end

            rbname = c_func_name_to_rb(v.name)
            if not v.type.kind_of? Metasm::C::Function
              class << self;
                self;
              end.send(:define_method, rbname) { addr }
              next
            end

            next if v.initializer

            
            new_caller_for(v, rbname, addr)
          }

        
          cexist = constants.inject({}) { |h, c| h.update c.to_s => true }
          cp.toplevel.symbol.each { |k, v|
            if v.kind_of? ::Integer
              n = c_const_name_to_rb(k)
              const_set(n, v) if v.kind_of? Integer and not cexist[n]
            end
          }

          cp.lexer.definition.each_key { |k|
            n = c_const_name_to_rb(k)
            if not cexist[n] and Object.const_defined?(n) and v = @cp.macro_numeric(n)
              const_set(n, v)
            end
          }
        end

        def self.np
          @np
        end

        def self.alloc_c_type(typename, init_value = 0)
          alloc_c_ary(typename, [init_value])
        end
      end

      class Transport
        def initialize(opts = {})
          @conn_handle = nil
          @communication_handle = []
        end

        def listen(conn_handle, opts = {}, &block)
          @conn_handle = conn_handle
          #port_message = APIProxy.alloc_c_struct('PORT_MESSAGE')
          port_message = APIProxy.alloc_c_ary('BYTE', 0x1000)
          message_attr = MessageAttribute.new.struct
          buf_len = APIProxy.alloc_c_type('SIZE_T')
          buf_len[0] = port_message.sizeof
          retry_count = 0

          while true
            begin
              # call NtAlpcSendWaitReceivePort will cause interpreter blocks, until you kill it.
              ntstatus = APIProxy.ntalpcsendwaitreceiveport(@conn_handle,
                                                            opts[:flag] || 0,
                                                            0,
                                                            0,
                                                            port_message,
                                                            buf_len,
                                                            message_attr,
                                                            0)
              yield(port_message, buf_len, message_attr, TinySDK.format_hex_ntstatus(ntstatus, hex_str: true)) if block_given?
              unless TinySDK.nt_success? ntstatus
                unless buf_len[0] == port_message.sizeof
                  port_message = APIProxy.alloc_c_ary('BYTE', buf_len[0])
                  raise TurboRex::Exception::ALPC::BufferTooSmall
                else
                  raise
                end
              end
            rescue => e
              if e.is_a? TurboRex::Exception::ALPC::BufferTooSmall
                raise TurboRex::Exception::ALPC::TooManyRetries if retry_count >= 2
                retry_count += 1
                retry
              else
                raise TurboRex::Exception::UnknownError
              end
            end

            kport_message = PortMessage.new(raw_message: port_message)
            break if (kport_message.type & 0xFFF) == TurboRex::Windows::ALPC::LPC_CONNECTION_REQUEST
          end

          return kport_message
        end

        def send(handle, port_message, message_attr, opts = {})
          flag = opts[:flag] || 0
          timeout = opts[:timeout] || 0
          #buf_len = opts.fetch(:buf_len) { APIProxy.alloc_c_type('SIZE_T') }
          #buf_len = port_message.sizeof

          ntstatus = APIProxy.ntalpcsendwaitreceiveport(handle, flag, port_message, message_attr, 0, 0, 0, timeout)
          unless TinySDK.nt_success?(ntstatus)
            raise TurboRex::Exception::NotNTSuccess.new TinySDK.format_hex_ntstatus(ntstatus, hex_str: true)
          end

          TinySDK.format_hex_ntstatus ntstatus
        end


        def recv(handle, opts = {})
          port_message = opts.fetch(:port_message) { APIProxy.alloc_c_ary('BYTE', 0x1000) }
          buf_len = opts.fetch(:buf_len) { APIProxy.alloc_c_type('SIZE_T') }
          buf_len[0] = port_message.sizeof
          #message_attr = opts.fetch(:message_attr) { APIProxy.alloc_c_struct('ALPC_MESSAGE_ATTRIBUTES') }
          message_attr = MessageAttribute.new.struct
          flag = opts[:flag] || 0
          retry_count = opts[:retry_count] || 0
          timeout = opts[:timeout] || 0

          begin
            ntstatus = APIProxy.ntalpcsendwaitreceiveport(handle, flag, 0, 0, port_message, buf_len, message_attr, timeout)
            unless TinySDK.nt_success? ntstatus
              unless buf_len[0] == port_message.sizeof
                port_message = APIProxy.alloc_c_ary('BYTE', buf_len[0])
                raise TurboRex::Exception::ALPC::BufferTooSmall
              else
                raise
              end
            end
          rescue => e
            if e.is_a? TurboRex::Exception::ALPC::BufferTooSmall
              raise TurboRex::Exception::ALPC::TooManyRetries if retry_count >= 2
              retry_count += 1
              retry
            else
              raise TurboRex::Exception::NotNTSuccess.new(TinySDK.format_hex_ntstatus(ntstatus, hex_str: true))
            end
          end

          PortMessage.new(raw_message: port_message)
        end

        def send_recv(handle, send_message, send_message_attr, recv_message_attr, opts = {})
          port_message = opts.fetch(:port_message) { APIProxy.alloc_c_ary('BYTE', 0x1000) }
          buf_len = opts.fetch(:buf_len) { APIProxy.alloc_c_type('SIZE_T') }
          buf_len[0] = port_message.sizeof
          message_attr = recv_message_attr
          flag = opts[:flag] || TurboRex::Windows::ALPC::ALPC_MSGFLG_SYNC_REQUEST
          retry_count = opts[:retry_count] || 0
          timeout = opts[:timeout] || 0

          begin
            ntstatus = APIProxy.ntalpcsendwaitreceiveport(handle, 
                                                          flag, 
                                                          send_message, 
                                                          send_message_attr, 
                                                          port_message, 
                                                          buf_len, 
                                                          recv_message_attr, 
                                                          timeout)
            unless TinySDK.nt_success? ntstatus
              unless buf_len[0] == port_message.sizeof
                port_message = APIProxy.alloc_c_ary('BYTE', buf_len[0])
                raise TurboRex::Exception::ALPC::BufferTooSmall
              else
                raise
              end
            end
          rescue => e
            if e.is_a? TurboRex::Exception::ALPC::BufferTooSmall
              raise TurboRex::Exception::ALPC::TooManyRetries if retry_count >= 2
              retry_count += 1
              retry
            else
              raise TurboRex::Exception::NotNTSuccess.new(TinySDK.format_hex_ntstatus(ntstatus, hex_str: true))
            end
          end

          PortMessage.new(raw_message: port_message)
        end

        def connect(opts = {}, &block)
          unless wport_name = TurboRex::Windows::Utils.multibyte_to_widechar(opts[:port_name])
            raise "Unable to convert characters to utf-16le encoding."
          end

          dest_str = APIProxy.alloc_c_ptr('UNICODE_STRING')
          APIProxy.rtlinitunicodestring(dest_str, wport_name)

          handle = APIProxy.alloc_c_type('HANDLE')
          alpc_port_attr = APIProxy.alloc_c_struct('ALPC_PORT_ATTRIBUTES')
          alpc_port_attr.Flags = TurboRex::Windows::ALPC::ALPC_PORFLG_ALLOW_LPC_REQUESTS
          alpc_port_attr.MaxMessageLength = 0x1000
          alpc_port_attr.MemoryBandwidth = 0
          alpc_port_attr.MaxPoolUsage = 0xFFFFFFFF
          alpc_port_attr.MaxSectionSize = 0xFFFFFFFF
          alpc_port_attr.MaxViewSize = 0xFFFFFFFF
          alpc_port_attr.MaxTotalSectionSize = 0xFFFFFFFF
          alpc_port_attr.DupObjectTypes = 0xFFFFFFFF

          alpc_port_attr.SecurityQos.Length = alpc_port_attr.SecurityQos.sizeof
          alpc_port_attr.SecurityQos.ImpersonationLevel = opts[:impersonation_level] || 
                                                          TurboRex::Windows::Constants::SecurityIdentification

          # timeout
          #large_integer = APIProxy.alloc_c_struct('LARGE_INTEGER')
          #large_integer.HighPart
          #large_integer.LowPart

          kport_message = PortMessage.new(payload: opts[:payload], alloc_size: (opts[:alloc_size]||3800))
          obj_attr = opts[:obj_attr] || 0
          flags = opts[:flags] || TurboRex::Windows::ALPC::ALPC_MSGFLG_SYNC_REQUEST # Don't use the ALPC_MSGFLG_SYNC_REQUEST flag when specific attributes
          timeout = opts[:timeout] || 0
          retry_count = opts[:retry_count] || 0

          buf_len = nil
          if message_size = kport_message.message_size
            buf_len = APIProxy.alloc_c_type('SIZE_T')
            buf_len[0] = message_size
          end

          out_msg_attr = 0
          in_msg_attr = 0

          if opts[:client_obj_attr] # perform to call NtAlpcConnectPortEx
            raise NotImplementedError
          else
            ntstatus = APIProxy.ntalpcconnectport(handle, dest_str, obj_attr, alpc_port_attr, flags, 0, kport_message.message,
                                                  buf_len, out_msg_attr, in_msg_attr, timeout)
            kport_message.refresh_message
            formatted_status = TinySDK.format_hex_ntstatus(ntstatus)
            if formatted_status == 0xC0000041
              puts "[-] The server refused the connection.(STATUS_PORT_CONNECTION_REFUSED)"
              retry_count.times do |i|
                puts "[*] Retrying..."
                ntstatus = APIProxy.ntalpcconnectport(handle, dest_str, obj_attr, alpc_port_attr, flags, 0, kport_message.message,
                                                      buf_len, out_msg_attr, in_msg_attr, timeout)
                break unless TinySDK.format_hex_ntstatus(ntstatus) == 0xC0000041
              end
            elsif !TinySDK.nt_success?(ntstatus)
              raise TurboRex::Exception::NotNTSuccess.new("0x#{formatted_status.to_s(16).upcase}")
            end
          end

          @communication_handle << handle[0]
          return handle[0], kport_message          
        end

        def accept(opts = {})
          communication_handle = APIProxy.alloc_c_type('HANDLE')
          alpc_port_attr = APIProxy.alloc_c_struct('ALPC_PORT_ATTRIBUTES')
          alpc_port_attr.Flags = 0
          alpc_port_attr.MaxMessageLength = 0x1000
          alpc_port_attr.MemoryBandwidth = 0
          alpc_port_attr.MaxPoolUsage = 0xFFFFFFFF
          alpc_port_attr.MaxSectionSize = 0xFFFFFFFF
          alpc_port_attr.MaxViewSize = 0xFFFFFFFF
          alpc_port_attr.MaxTotalSectionSize = 0xFFFFFFFF
          alpc_port_attr.DupObjectTypes = 0xFFFFFFFF

          port_context = opts[:port_context] || 0
          flags = opts[:flags] || 0
          uniq_process = opts[:uniq_process]
          uniq_thread = opts[:uniq_thread]
          message_id = opts[:message_id]
          accept = 1
          port_message = opts[:port_message]

          if port_message.nil?
            raise TurboRex::Exception::ALPC::ReplyMessageMismatch if uniq_process.nil? || uniq_thread.nil? || message_id.nil?
            port_message = PortMessage.new(alloc_size: 1)
            port_message.client_id = [uniq_process, uniq_thread]
            port_message.message_id = message_id
          end

          accept = 0 if opts[:refuse]

          ntstatus = APIProxy.ntalpcacceptconnectport(communication_handle,
                                                      @conn_handle,
                                                      flags,
                                                      0,
                                                      alpc_port_attr,
                                                      port_context,
                                                      port_message.message,
                                                      0,
                                                      accept)

          unless opts[:refuse]                                         
            @communication_handle << communication_handle[0]
            [communication_handle[0], TinySDK.format_hex_ntstatus(ntstatus)]
          else
            TinySDK.format_hex_ntstatus(ntstatus)
          end
        end

        def refuse_connect(opts = {})
          opts[:refuse] = true
          accept(opts)
        end

        def close
          APIProxy.ntalpcdisconnectport(@conn_handle, 0)
          Metasm::WinAPI.closehandle @conn_handle
          @conn_handle = nil
          @communication_handle = []
        end
      end

      class PortMessage
        class ClientID
          attr_accessor :unique_thread
          attr_accessor :unique_process

          def initialize(unique_process, unique_thread)
            @unique_process = unique_process
            @unique_thread = unique_thread
          end

          def to_struct
            client_id = APIProxy.alloc_c_struct('CLIENT_ID')
            client_id.UniqueProcess = @unique_process
            client_id.UniqueThread = @unique_thread
            client_id
          end
        end

        attr_reader :message_size
        attr_reader :buf_size
        attr_reader :header_size
        attr_reader :message
        attr_reader :payload
        attr_reader :payload_size
        attr_accessor :total_length
        attr_accessor :data_length
        attr_reader :header
        attr_accessor :attributes

        # header data member
        attr_reader :length
        attr_reader :type
        attr_reader :data_info_offset
        attr_reader :zero_init
        attr_reader :client_id
        attr_reader :do_not_use_this_field
        attr_reader :message_id
        attr_reader :client_view_size
        attr_reader :callback_id

        def initialize(opts = {})
          raw_message = opts[:raw_message]
          payload = opts[:payload]
          @payload = payload
          @attributes = MessageAttribute.new.struct

          if raw_message
            perform_raw_message raw_message
          elsif payload
            port_message = opts[:port_message]
            @header = (port_message ||= APIProxy.alloc_c_struct('PORT_MESSAGE'))
            set_header
            #@message_size = @header_size = port_message.sizeof
            if payload.is_a? String
              pure_set_msg payload, payload.bytesize
            elsif payload.is_a? ::Metasm::C::AllocCStruct
              pure_set_msg payload.str, payload.sizeof
            else
              raise TurboRex::Exception::ALPC::UnknownPayloadType
            end
          elsif opts[:alloc_size]
            @header = APIProxy.alloc_c_struct('PORT_MESSAGE')
            set_header

            @payload = 0.chr * opts[:alloc_size].to_i
            pure_set_msg @payload, @payload.bytesize
          end
        end

        def payload=(payload)
          @payload = payload
          if payload.is_a? String
            @payload_size = payload.bytesize
          elsif payload.is_a? ::Metasm::C::AllocCStruct
            @payload_size = payload.sizeof
          end

          if @payload_size > @buf_size
            pure_set_msg payload, @payload_size
          else
            @message[@header_size, @payload_size] = payload
            set_data_length @payload_size
          end
        end

        def set_data_length(len)
          @total_length = @header_size + len
          @data_length = len

          @header.u1.s1.TotalLength = @total_length
          @header.u1.s1.DataLength = @data_length
        end

        def get_total_and_data_len
          [@header.u1.s1.TotalLength, @header.u1.s1.DataLength]
        end

        def header=(header)
          @header = header

          set_header
          set_data_length(@payload_size)
          pure_set_msg @payload, @payload_size
        end

        def set_header
          @total_length, @data_length = get_total_and_data_len
          @length = @header.u1.Length
          @type = @header.u2.s2.Type
          @data_info_offset = @header.u2.s2.DataInfoOffset
          @zero_init = @header.u2.ZeroInit
          @client_id = @do_not_use_this_field = ClientID.new(@header.ClientId.UniqueProcess, @header.ClientId.UniqueThread)
          @message_id = @header.MessageId
          @client_view_size = @callback_id = @header.ClientViewSize
          @header_size = @header.sizeof
        end

        def type=(type)
          binding.pry
          @type = @header.u2.s2.Type = type
          @message[0, @header_size] = @header.str
        end

        def message_id=(id)
          @message_id = @header.MessageId = id
          @message[0, @header_size] = @header.str
        end

        def client_id=(client_id)
          if client_id.is_a? ClientID
            @client_id = client_id
          elsif client_id.is_a? ::Metasm::C::AllocCStruct
            @client_id = @do_not_use_this_field = ClientID.new(client_id.UniqueProcess, client_id.UniqueThread)
          else
            @client_id = @do_not_use_this_field = ClientID.new(client_id[0], client_id[1])
          end

          @header.ClientId.UniqueProcess = @client_id.unique_process
          @header.ClientId.UniqueThread = @client_id.unique_thread

          @message[0, @header_size] = @header.str
        end

        def callback_id=(callback_id)
          @callback_id = @header.CallbackId = callback_id
          @message[0, @header_size] = @header.str
        end

        def refresh_message
          return unless @message
          perform_raw_message @message
        end

        private

        def perform_raw_message(raw_message)
          raise "Invalid message class." unless raw_message.is_a?(::Metasm::C::AllocCStruct)
          @message = raw_message
          nport_message = APIProxy.np['PORT_MESSAGE']
          @header = nport_message.from_str raw_message[0, nport_message.sizeof]
          set_header

          @message_size = @message.sizeof
          @payload_size = @data_length
          @payload = @message[@header_size, @payload_size]
          @buf_size = @message.sizeof - @header_size
        end

        def pure_set_msg(payload, payload_size)
          @message_size = @header_size = @header.sizeof
          @payload_size = payload_size
          @buf_size = @payload_size + PORMSG_PAD
          @message_size += @buf_size
          @message = APIProxy.alloc_c_ary('BYTE', @message_size)
          set_data_length @payload_size
          @message[0, @header_size] = @header.str
          @message[@header_size, @payload_size] = payload
        end
      end

      class MessageAttribute
        attr_reader :struct
        attr_reader :buf
        attr_reader :attr

        def initialize(attr = nil)
          @attr = attr ||= (
          TurboRex::Windows::ALPC::ALPC_MESSAGE_SECURITY_ATTRIBUTE |
              TurboRex::Windows::ALPC::ALPC_MESSAGE_VIEW_ATTRIBUTE |
              TurboRex::Windows::ALPC::ALPC_MESSAGE_CONTEXT_ATTRIBUTE |
              TurboRex::Windows::ALPC::ALPC_MESSAGE_HANDLE_ATTRIBUTE |
              TurboRex::Windows::ALPC::ALPC_MESSAGE_TOKEN_ATTRIBUTE |
              TurboRex::Windows::ALPC::ALPC_MESSAGE_DIRECT_ATTRIBUTE |
              TurboRex::Windows::ALPC::ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE
          )
          msg_attr = APIProxy.alloc_c_struct('ALPC_MESSAGE_ATTRIBUTES')
          reqired_buf_size = APIProxy.alloc_c_type('ULONG')
          @buf = required_buf(attr)
          ntstatus = APIProxy.alpcinitializemessageattribute(attr, @buf, @buf.sizeof, reqired_buf_size)
          unless TinySDK.nt_success? ntstatus
            formatted = TurboRex::Windows::TinySDK.format_hex_ntstatus ntstatus, hex_str: true
            raise "Failed to call AlpcInitializeMessageAttribute: #{formatted}"
          end

          @struct = @buf
        end

        def required_buf(attr)
          size = required_buf_size(attr)
          APIProxy.alloc_c_ary('BYTE', size)
        end

        def required_buf_size(attr)
          required_bud_size = APIProxy.alloc_c_type('ULONG')
          ntstatus = APIProxy.alpcinitializemessageattribute(attr, 0, 0, required_bud_size)
          required_bud_size.str.unpack('V')[0]
        end
      end

      class Client
        class ServerProxy
          def initialize(communication_handle, transport, server_pid, server_tid)
            @communication_handle = communication_handle
            @transport = transport
            @server_pid = server_pid
            @server_tid = server_tid
          end

          def gets(opts = {})
            @transport.recv(@communication_handle, opts)
          end

          def puts(message, opts = {})
            if message.is_a? String
              port_message = PortMessage.new(payload: message)
              if opts[:last_header]
                port_message.header = opts[:last_header]
              end
            elsif message.is_a? PortMessage
              port_message = message
            else
              raise TurboRex::Exception::ALPC::UnknownPayloadType
            end

            message_attr = opts.delete(:message_attr) || MessageAttribute.new.struct
            @transport.send(@communication_handle, port_message.message, message_attr, opts)
          end

          def send_recv(message, opts = {})
            if message.is_a? String
              port_message = PortMessage.new(payload: message)
            elsif message.is_a? ::Metasm::C::AllocCStruct
              port_message = message
            else
              raise TurboRex::Exception::ALPC::UnknownPayloadType
            end

            send_attr = port_message.attributes || opts[:attributes] || 0
            recv_attr = opts[:recv_attr] || MessageAttribute.new.struct
            @transport.send_recv(@communication_handle, port_message.message, send_attr, recv_attr)
          end

          def disconnect
            @transport.close
          end

          alias_method :write, :puts
          alias_method :read, :gets
        end

        def initialize(port_name, opts = {})
          if TurboRex::Windows::Utils.is_wow64?
            default_cpu = Metasm::Ia32
          else
            default_cpu = Metasm::X86_64
          end

          cpu = opts[:cpu] || default_cpu
          APIProxy.init(cpu)

          unless port_name.start_with? '\\'
            port_name = '\\' + port_name
          end
          @port_name = port_name

          @transport = Transport.new
        end

        def connect(opts = {}, &block)
          opts[:port_name] = @port_name
          @communication_handle, msg = @transport.connect(opts)
          server_pid = msg.client_id&.unique_process
          server_tid = msg.client_id&.unique_thread
          @server = ServerProxy.new(@communication_handle, @transport, server_pid, server_tid)
          yield(@server) if block_given?
          [@server, msg]
        end
      end

      class Server
        include TurboRex::Windows::ALPC

        attr_reader :port_name
        attr_reader :obj_attr

        class ClientStub
          def initialize(communication_handle, conn_handle, transport, conn_message)
            @communication_handle = communication_handle
            @connection_handle = conn_handle
            @conn_message = conn_message
            @transport = transport
            @client_id = conn_message.client_id
          end

          def gets(opts = {})
            @transport.recv(@connection_handle, opts)
          end

          def puts(message, message_id = nil, opts = {})
            if message.is_a? String
              port_message = PortMessage.new(payload: message)
              if opts[:last_header]
                port_message.header = opts[:last_header]
              elsif message_id
                port_message.message_id = message_id
              else
                raise "Message ID must be specified when :last_header option is not specified."
              end
            elsif message.is_a? PortMessage
              port_message = message
            else
              raise TurboRex::Exception::ALPC::UnknownPayloadType
            end

            message_attr = opts.delete(:message_attr) || port_message.attributes
            @transport.send(@communication_handle, port_message.message, message_attr, opts)
          end

          # def impersonate(msg)
          #   ntstatus = APIProxy.ntalpcimpersonateclientofport(@communication_handle, msg.message, 0)
          #   TurboRex::Windows::TinySDK.format_hex_ntstatus ntstatus
          # end

          alias_method :write, :puts
          alias_method :read, :gets
        end

        def initialize(port_name, opts = {})
          if TurboRex::Windows::Utils.is_wow64?
            default_cpu = Metasm::Ia32
          else
            default_cpu = Metasm::X86_64
          end

          cpu = opts[:cpu] || default_cpu
          APIProxy.init(cpu)

          @communication_port_handles = []
          @clients = []

          unless port_name.start_with? '\\'
            port_name = '\\' + port_name
          end
          @port_name = port_name

          if wport_name = TurboRex::Windows::Utils.multibyte_to_widechar(port_name)
            dest_str = APIProxy.alloc_c_struct('UNICODE_STRING')
            APIProxy.rtlinitunicodestring(dest_str, wport_name)

            handle = APIProxy.alloc_c_type('HANDLE')
            alpc_port_attr, obj_attr = make_attr(obj_name: dest_str)
            ntstatus = APIProxy.ntalpccreateport(handle, obj_attr, alpc_port_attr)

            unless TinySDK.nt_success? ntstatus
              formatted = TurboRex::Windows::TinySDK.format_hex_ntstatus ntstatus, hex_str: true
              raise "Unable to create alpc port: #{formatted}"
            end

            @conn_port_handle = handle[0]
            @transport = Transport.new
          else
            raise "Unable to convert characters to utf-16le encoding."
          end
        end

        def run(opts = {}, &block)
          loop do
            conn_message = @transport.listen(@conn_port_handle)
            puts "[*] Receiving connection request"

            if opts[:conn_req_cb]
              unless (permit_conn = opts[:conn_req_cb].call(:connection_req, conn_message, self))
                ######################################################################################################################
                ## Requires following params(UniqueProcess, UniqueThread, MessageId), otherwise raise STATUS_REPLY_MESSAGE_MISMATCH ##
                ## uniq_process = conn_message.client_id.unique_process                                                             ##
                ## uniq_thread = conn_message.client_id.unique_thread                                                               ##
                ## message_id = conn_message.message_id                                                                             ##
                ##                                                                                                                  ##
                ## Or we can pass a instance of PortMessage with the 'port_message' key                                            ##
                ######################################################################################################################
                @transport.refuse_connect(port_message: conn_message) and next
              end
            end

            client = accept(conn_message)
            if block_given?
              yield(client)
            end
          end
        end

        def accept(conn_message, &block)
          handle, ntstatus = @transport.accept(port_message: conn_message)
          if TinySDK.nt_success?(ntstatus)
            @communication_port_handles << handle
            client_stub = ClientStub.new(handle, @conn_port_handle, @transport, conn_message)
            @clients << client_stub
            yield(client_stub) if block_given?
            client_stub
          else
            puts "[-] Unable to accept connection. (0x#{ntstatus.to_s(16).upcase})"
            raise TurboRex::Exception::ALPC::UnableToAcceptConnection
          end
        end

        #def impersonate_client(client)
        #  client.impersonate
        #end

        private

        def make_attr(opts = {})
          unless @alpc_port_attr
            alpc_port_attr = APIProxy.alloc_c_struct('ALPC_PORT_ATTRIBUTES')
            alpc_port_attr.Flags = ALPC::ALPC_PORFLG_ALLOW_LPC_REQUESTS
            alpc_port_attr.MaxMessageLength = 0x1000
            alpc_port_attr.MemoryBandwidth = 0
            alpc_port_attr.MaxPoolUsage = 0xFFFFFFFF
            alpc_port_attr.MaxSectionSize = 0xFFFFFFFF
            alpc_port_attr.MaxViewSize = 0xFFFFFFFF
            alpc_port_attr.MaxTotalSectionSize = 0xFFFFFFFF
            alpc_port_attr.DupObjectTypes = 0xFFFFFFFF
          end

          unless @obj_attr
            obj_attr = APIProxy.alloc_c_struct('OBJECT_ATTRIBUTES')
            obj_attr.Length = obj_attr.sizeof
            obj_attr.ObjectName = opts[:obj_name]
            @obj_attr = obj_attr
          end

          [alpc_port_attr, obj_attr]
        end

        def np
          APIProxy.np
        end
      end
    end
  end
end