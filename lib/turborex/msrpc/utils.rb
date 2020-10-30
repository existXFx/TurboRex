module TurboRex
  module MSRPC
    module Utils
      extend TurboRex::MSRPC::RPCBase

      def get_interface_type
        raise NotImplementedError
      end

      def gen_script_rpc_client_np(opts = {})
        uuid = opts[:uuid]
        version = opts[:version] || '1.0'
        function = opts[:function]
        data = opts[:data]
        pipe = opts[:pipe]
        output = opts[:output] || 'my_rpc_client.rb'

        template = <<-EOS
          #usage: ruby your_script.rb RHOST USERNAME PASSWORD
          require 'rex'
          require 'rex/encoder/ndr'
        
          Rex::Proto::SMB::SimpleClient.class_eval do
            attr_accessor :read_timeout
          end
          
          uuid = #{uuid}
          version = #{version}
          protocol = 'ncacn_np'
          rhost = ARGV[0]
          opts = ['#{pipe}']
          handle = Rex::Proto::DCERPC::Handle.new([uuid, version], protocol, rhost, opts)
          function = #{function}
          data = #{data}
          
          sock = Rex::Socket::Tcp.create('PeerHost' => rhost, 'PeerPort' => 445)
          dcerpc = Rex::Proto::DCERPC::Client.new(handle, sock, {'smb_user' => ARGV[1], 'smb_pass' => ARGV[2]})
          res = dcerpc.call(function, data, true)

          puts res
        EOS

        file = File.new(output, 'rw')
        file.puts template
        file.close

        true
      end

      def self.raw_to_guid_str(raw, upcase = true)
        unpacked = raw.unpack("VvvCCa6")
        mac = unpacked[5].unpack("C*")
        unpacked[-1] = '%02x%02x%02x%02x%02x%02x' % mac
        formatted = ("%08x-%04x-%04x-%02x%02x-%s" % unpacked)
        upcase ? formatted.upcase : formatted
      end

      def self.read_cstring(isource, base=0)
        len=0
        cstr = ""
        until (data=isource.read(base+len, 1)) == "\x00"
          cstr << data
          len+=1
        end

        return cstr, len
      end
    end
  end
end