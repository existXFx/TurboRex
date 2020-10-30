module TurboRex
  class Windows < Metasm::WinOS
    module Security
      class ACE
        attr_reader :type
        attr_reader :flags

        def initialize(type, flags)
          @type = type
          @flags = flags
        end

        def self.from_raw(raw)
          ace_header = TurboRex::Windows::Win32API.decode_c_struct('ACE_HEADER', raw)
          sid_offset = ace_header.sizeof + 4
          type = ace_header.AceType
          flags = ace_header.AceFlags
          mask = raw[ace_header.sizeof, 4].unpack('V').first

          sid = TurboRex::Windows::Win32API.decode_c_struct('SID', raw, sid_offset)
          ppszsid = TurboRex::Windows::Win32API.alloc_c_ptr('LPSTR')
          if TurboRex::Windows::Win32API.convertsidtostringsida(sid, ppszsid) == 0
            raise "Unable to call ConvertSidToStringSidA. GetLastError returns: #{TurboRex::Windows::Win32API.getlasterror}"
          end
          sz_sid = TurboRex::Windows::Win32API.memory_read_strz(ppszsid[0])

          case type
          when TurboRex::Windows::Constants::ACCESS_DENIED_ACE_TYPE
            AccessDeniedACE.new(mask, sz_sid, flags)
          when TurboRex::Windows::Constants::ACCESS_ALLOWED_ACE_TYPE
            AccessAllowedACE.new(mask, sz_sid, flags)
          end
        end
      end

      class AccessAllowedACE < ACE
        attr_reader :mask
        attr_reader :sid
        attr_reader :short

        def initialize(mask, sid, flags, type=TurboRex::Windows::Constants::ACCESS_ALLOWED_ACE_TYPE)
          @mask = mask
          @sid = sid
          @short = :allowed
          super(type, flags)
        end
      end

      class AccessDeniedACE < ACE
        attr_reader :mask
        attr_reader :sid
        attr_reader :short

        def initialize(mask, sid, flags, type=TurboRex::Windows::Constants::ACCESS_DENIED_ACE_TYPE)
          @mask = mask
          @sid = sid
          @short = :denied
          super(type, flags)
        end
      end

      class SystemAuditAce < ACE
        attr_reader :mask
        attr_reader :sid
        attr_reader :short

        def initialize(mask, sid, flags, type=TurboRex::Windows::Constants::SYSTEM_AUDIT_ACE_TYPE)
          @mask = mask
          @sid = sid
          @short = :audit
          super(type, flags)
        end
      end
    end
  end
end