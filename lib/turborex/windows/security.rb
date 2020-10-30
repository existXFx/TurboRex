warn "\033[33m[-]Warning: This module doesn't currently work on non-Windows os.\033[0m" unless OS.windows?
module TurboRex
  class Windows < Metasm::WinOS
    module Security
      include TurboRex::Windows::Constants

      require 'turborex/windows/security/ace.rb'
      require 'turborex/windows/security/acl.rb'
      require 'turborex/windows/security/security_descriptor.rb'   
    end
  end
end