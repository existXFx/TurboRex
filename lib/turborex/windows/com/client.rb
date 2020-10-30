module TurboRex
  class Windows < Metasm::WinOS
    module COM
      class Client
        include WellKnownIID

        attr_reader :clsid
        attr_reader :api_proxy
        attr_reader :iunknown

        def initialize(clsid, opts = {})
          @clsid = clsid
          @context = opts[:cls_context] || CLSCTX_ALL
          @iunknown = Interface::IUnknown.new
          @apartment = opts[:apartment] || 0
          @api_proxy = Win32API.dup
          @cp = @api_proxy.cp

          Win32API.coinitializeex(0, @apartment)
        end

        # Binding to class implementation
        def create_instance(opts={})
          interface = opts[:interface] || @iunknown
          iid = interface.iid
          cls_context = opts[:cls_context] || @context
          ppv = @api_proxy.alloc_c_ptr('PVOID')
          pclsid = Utils.clsid_to_raw(@clsid)
          piid = Utils.clsid_to_raw(iid)

          hr = @api_proxy.cocreateinstance(pclsid, 0, cls_context, piid, ppv)
          raise "Failed to call CoCreateInstance: #{TinySDK.format_hex_ntstatus(hr, hex_str: true)}" unless TinySDK.nt_success?(hr)
          pthis = ppv[0]
          interface.this = pthis
          @iunknown = interface if interface.kind_of?(Interface::IUnknown)
          interface
        end

        # Binding to class object(class factory)
        def get_class_object(opts={})
          interface = Interface::IClassFactory.new
          iid = interface.iid
          cls_context = opts[:cls_context] || @context
          server_info = opts[:server_info]
          ppv = @api_proxy.alloc_c_ptr('LPVOID')
          pclsid = Utils.clsid_to_raw(@clsid)
          piid = Utils.clsid_to_raw(iid)

          hr = @api_proxy.cogetclassobject(pclsid, cls_context, server_info, piid, ppv)
          raise "Failed to call CoGetClassObject: #{TinySDK.format_hex_ntstatus(hr, hex_str: true)}" unless TinySDK.nt_success?(hr)

          pthis = ppv[0]
          interface.this = pthis
          interface
        end

        def query_interface(iid_or_iface)
          interface = nil
          if iid_or_iface.is_a?(Interface)
            interface = iid_or_iface
            iid = interface.iid
          elsif iid_or_iface.is_a?(String)
            iid = iid_or_iface
          end

          create_instance unless @iunknown.this
          iid = Utils.clsid_to_raw(iid)
          ppv = @api_proxy.alloc_c_ptr('PVOID')

          if @iunknown.QueryInterface(iid, ppv).nil?
            if interface
              interface.this = ppv[0]
              return interface
            else
              return ppv[0]
            end
          end

          false
        end
      end
    end
  end
end