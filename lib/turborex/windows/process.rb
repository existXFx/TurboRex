# frozen_string_literal: true

module TurboRex
  class Windows < Metasm::WinOS
    class Process < Metasm::WinOS::Process
      def disassembler
        return @disassembler if @disassembler
        case self.cpusz 
        when 32
          @disassembler = Metasm::Shellcode.decode(self.memory, Metasm::Ia32.new).disassembler
        when 64
          @disassembler = Metasm::Shellcode.decode(self.memory, Metasm::X86_64.new).disassembler
        end
      end

      def load_symbol_table(libname)  
        initialize_sym_handler
        unless lib = modules.find { |m| m.path =~ Regexp.new(libname, true) }
          return false
        end

        if Win32API.symloadmoduleex(self.handle, 0, libname, 0, lib.addr, lib.size, 0, 0) == 0 &&
           Win32API.getlasterror != 0
            return false
        end

        # module_info = Win32API.alloc_c_struct('IMAGEHLP_MODULE64')
        # module_info.SizeOfStruct = module_info.sizeof
        # unless Win32API.symgetmoduleinfo64(self.handle, lib.addr, module_info) == 1
        #   return false
        # end

        true
      end

      def close_handle
        Metasm::WinAPI.closehandle(handle)
      end

      private

      def initialize_sym_handler
        return true if @sym_handler_initialized
        Win32API.syminitialize(self.handle, 0, false)
        Win32API.symsetoptions(Win32API.symgetoptions |
                               Win32API::SYMOPT_DEFERRED_LOADS |
                               Win32API::SYMOPT_NO_PROMPTS # | Win32API::SYMOPT_DEBUG
                               )
        sympath = ENV.fetch('_NT_SYMBOL_PATH') { 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols;' }
        Win32API.symsetsearchpath(self.handle, sympath.dup)

        @sym_handler_initialized = true
      end
    end
  end
end
