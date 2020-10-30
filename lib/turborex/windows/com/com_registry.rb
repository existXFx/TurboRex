require 'win32/registry'

module TurboRex
  class Windows < Metasm::WinOS
    module COM
      class COMRegistry

        class CLSIDEntry
          attr_reader :clsid
          attr_accessor :inproc_server
          attr_accessor :inproc_server32
          attr_accessor :inproc_handler
          attr_accessor :inproc_handler32
          attr_accessor :local_server
          attr_accessor :local_server32
          attr_accessor :prog_id
          attr_accessor :treat_as
          attr_accessor :typelib

          InprocHandler = Struct.new(:path, :threading_model)
          InprocHandler32 = Struct.new(:path, :threading_model)
          InprocServer32 = Struct.new(:path, :threading_model)
          InprocServer = Struct.new(:path)
          LocalServer = Struct.new(:path, :server_executable)
          LocalServer32 = Struct.new(:path, :server_executable)

          def initialize(clsid)
            @clsid = clsid
          end

          def self.from_registry(reg_key)
            return unless reg_key.keyname  =~ /^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i
            clsid_entry = new(reg_key.keyname.delete('{}'))
            reg_key.each_key do |k|
              reg_key.open(k) do |sub_key|
                case k.downcase
                when 'inprocserver32'
                  clsid_entry.inproc_server32 = InprocServer32.new
                  clsid_entry.inproc_server32.path = sub_key[''] rescue nil
                  clsid_entry.inproc_server32.threading_model = (sub_key['ThreadingModel'] rescue 'sta')
                when 'localserver32'
                  clsid_entry.local_server32 = LocalServer32.new
                  clsid_entry.local_server32.path = sub_key[''] rescue nil
                  clsid_entry.local_server32.server_executable = sub_key['ServerExecutable'] rescue nil
                when 'progid'
                  @progid = sub_key[''] rescue nil
                when 'treatas'
                  @treat_as = sub_key[''] rescue nil
                when 'typelib'
                  @typelib = sub_key[''] rescue nil
                end
              end
            end

            clsid_entry
          end
        end

        class AppIDEntry
          attr_accessor :appid_guid
          attr_accessor :executable_name
          attr_accessor :launch_permission
          attr_accessor :access_permission
          attr_accessor :local_service

          def self.from_registry(reg_key)
            appid_entry = AppIDEntry.new
            if reg_key.keyname  =~ /^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i
              appid_entry.appid_guid = reg_key.keyname
              if (raw = reg_key.read('LaunchPermission').last rescue nil)
                sd = TurboRex::Windows::Win32API.alloc_c_ary('BYTE', raw.bytesize)
                sd.str = raw
                lpbDaclPresent = TurboRex::Windows::Win32API.alloc_c_ptr('BOOL')
                pdacl = TurboRex::Windows::Win32API.alloc_c_ptr('PVOID')
                lpbDaclDefaulted = TurboRex::Windows::Win32API.alloc_c_ptr('BOOL')

                TurboRex::Windows::Win32API.getsecuritydescriptordacl(sd, lpbDaclPresent, pdacl, lpbDaclDefaulted)
                appid_entry.launch_permission = TurboRex::Windows::Security::SecurityDescriptor.from_raw(raw)
              end

              if (raw = reg_key.read('AccessPermission').last rescue nil)
                sd = TurboRex::Windows::Win32API.alloc_c_ary('BYTE', raw.bytesize)
                sd.str = raw
                lpbDaclPresent = TurboRex::Windows::Win32API.alloc_c_ptr('BOOL')
                pdacl = TurboRex::Windows::Win32API.alloc_c_ptr('PVOID')
                lpbDaclDefaulted = TurboRex::Windows::Win32API.alloc_c_ptr('BOOL')

                TurboRex::Windows::Win32API.getsecuritydescriptordacl(sd, lpbDaclPresent, pdacl, lpbDaclDefaulted)
                appid_entry.access_permission = TurboRex::Windows::Security::SecurityDescriptor.from_raw(raw)
              end
            else
              appid_entry.executable_name = reg_key.keyname
            end

          end
        end
      end
    end
  end
end