module TurboRex
  class Windows < Metasm::WinOS
    module Security
      class SecurityDescriptor
        attr_reader :revision
        attr_reader :sbzl
        attr_reader :control
        attr_reader :owner
        attr_reader :group
        attr_reader :sacl
        attr_reader :dacl

        def initialize(revision, control, owner, group, sacl, dacl, sbzl=0)
          @revision = revision
          @sbzl = sbzl
          @control = control
          @owner = owner
          @group = group
          @sacl = sacl
          @dacl = dacl
        end

        # Very few robustness checks, may result in memory-corruption.
        def self.from_raw(raw)
          apiproxy_klass = TurboRex::Windows::Win32API
          sd = apiproxy_klass.alloc_c_ary('BYTE', raw.bytesize)
          sd.str = raw
          
          # Get security descriptor control and revision
          pcontrol = apiproxy_klass.alloc_c_ptr('SECURITY_DESCRIPTOR_CONTROL')
          prevision = apiproxy_klass.alloc_c_ptr('DWORD')
          if apiproxy_klass.getsecuritydescriptorcontrol(sd, pcontrol, prevision) == 0
            raise_api_call_failure('GetSecurityDescriptorControl')
          end
          control = pcontrol[0]
          revision = prevision[0]
          
          # Get owner sid
          ppsid = apiproxy_klass.alloc_c_ptr('PSID')
          pownder_default = apiproxy_klass.alloc_c_ptr('BOOL')
          if apiproxy_klass.getsecuritydescriptorowner(sd, ppsid, pownder_default) == 0
            raise_api_call_failure('GetSecurityDescriptorOwner')
          end

          ppszsid = apiproxy_klass.alloc_c_ptr('LPSTR')
          if apiproxy_klass.convertsidtostringsida(ppsid[0], ppszsid) == 0
            raise_api_call_failure('ConvertSidToStringSidA')
          end
          sz_owner_sid = apiproxy_klass.memory_read_strz(ppszsid[0])

          # Get group sid
          if apiproxy_klass.getsecuritydescriptorgroup(sd, ppsid, pownder_default) == 0
            raise_api_call_failure('GetSecurityDescriptorGroup')
          end

          ppszsid = apiproxy_klass.alloc_c_ptr('LPSTR')
          if apiproxy_klass.convertsidtostringsida(ppsid[0], ppszsid) == 0
            raise_api_call_failure('ConvertSidToStringSidA')
          end
          sz_group_sid = apiproxy_klass.memory_read_strz(ppszsid[0])          
          
          # TODO: parse SACL


          # Get DACL
          ppacl = apiproxy_klass.alloc_c_ptr('PACL')
          dacl_present = apiproxy_klass.alloc_c_ptr('BOOL')
          pdacl_default = apiproxy_klass.alloc_c_ptr('BOOL') 
          if apiproxy_klass.getsecuritydescriptordacl(sd, dacl_present, ppacl, pdacl_default) == 0
            raise_api_call_failure('GetSecurityDescriptorDacl')
          end

          acl_revision_info = apiproxy_klass.alloc_c_struct('ACL_REVISION_INFORMATION')
          if apiproxy_klass.getaclinformation(ppacl[0], acl_revision_info, acl_revision_info.sizeof, apiproxy_klass::ACLREVISIONINFORMATION) == 0
            raise_api_call_failure('GetAclInformation')
          end
          acl_revision = acl_revision_info.AclRevision

          acl_size_info = apiproxy_klass.alloc_c_struct('ACL_SIZE_INFORMATION')
          if apiproxy_klass.getaclinformation(ppacl[0], acl_size_info, acl_size_info.sizeof, apiproxy_klass::ACLSIZEINFORMATION) == 0
            raise_api_call_failure('GetAclInformation')
          end
          ace_count = acl_size_info.AceCount

          ppace = apiproxy_klass.alloc_c_ptr('LPVOID')
          aces = []
          ace_count.times do |i|
            if apiproxy_klass.getace(ppacl[0], i, ppace) == 0
              raise_api_call_failure('GetACE')
            end

            # parse ace
            aces << parse_ace_from_ptr(ppace[0])
          end

          dacl = ACL::DACL.new(acl_revision, ace_count, aces)

          new(revision, control, sz_owner_sid, sz_group_sid, nil, dacl)
        end

        
        def self.raise_api_call_failure(api_name)
          raise "Unable to call #{api_name}. GetLastError returns: #{TurboRex::Windows::Win32API.getlasterror}"
        end

        def self.parse_ace_from_ptr(ptr)
          ace_header = TurboRex::Windows::Win32API.alloc_c_struct('ACE_HEADER')
          raw_header = TurboRex::Windows::Utils.read_memory(ptr, ace_header.sizeof)
          ace_header.str = raw_header
          size = ace_header.AceSize

          raw_ace = TurboRex::Windows::Utils.read_memory(ptr, size)
          ACE.from_raw(raw_ace)
        end
      end
    end
  end
end