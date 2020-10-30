require 'turborex/cstruct'
module TurboRex
  class Windows < Metasm::WinOS
    module Utils
      include ::Win32 if ::OS.windows?
      include TurboRex::CStruct

      def get_version(path)
        structmgr = define_structs do
          struct tagVS_FIXEDFILEINFO {
            DWORD dwSignature;
            DWORD dwStrucVersion;
            DWORD dwFileVersionMS;
            DWORD dwFileVersionLS;
            DWORD dwProductVersionMS;
            DWORD dwProductVersionLS;
            DWORD dwFileFlagsMask;
            DWORD dwFileFlags;
            DWORD dwFileOS;
            DWORD dwFileType;
            DWORD dwFileSubtype;
            DWORD dwFileDateMS;
            DWORD dwFileDateLS;
          };
        end

        fGetFileVersionInfoSize = API.new('GetFileVersionInfoSize', 'PP', 'L', 'version')
        lpdwHandle = 0
        lptstrFilename = path
        buf_len = fGetFileVersionInfoSize.call(lptstrFilename, lpdwHandle)

        fGetFileVersionInfo = API.new('GetFileVersionInfo', 'PLLP', 'I', 'version')
        buf = 0.chr * buf_len
        res = fGetFileVersionInfo.call(lptstrFilename, 0, buf_len, buf)

        if res == 1
          fVerQueryValueW = API.new('VerQueryValue', 'PPPP', 'I', 'version')
          fileInfo = 0.chr * 8
          size = 0.chr * 4
          lpSubBlock = '\\'
          res = fVerQueryValueW.call(buf, lpSubBlock, fileInfo, size)

          if res == 1
            fReadProcessMemory = API.new('ReadProcessMemory', 'LPPPP', 'I', 'kernel32')
            size_i = size.unpack('V')[0]
            buf = 0.chr * size_i
            i1 = 0.chr * 8
            fReadProcessMemory.call(-1, fileInfo.unpack('Q<')[0], buf, size_i, i1)
            moduleVersion = structmgr['tagVS_FIXEDFILEINFO'].from_str buf
            return [moduleVersion['dwFileVersionMS'].value, moduleVersion['dwFileVersionLS'].value]
          end
        end
      end

      def self.multibyte_to_widechar(str)
        fMultiByteToWideChar = API.new('MultiByteToWideChar', 'ILSIPI', 'I', 'kernel32')
        code_page = 65001 # CP_UTF8
        flag = 0
        ilength = fMultiByteToWideChar.call(code_page, flag, str, -1, 0, 0)
        return false if ilength == 0

        buf = 0.chr * ilength * 2
        res = fMultiByteToWideChar.call(code_page, flag, str, -1, buf, ilength)
        return false if res == 0
        buf
      end

      def self.read_memory(base, size, handle = -1)
        fReadProcessMemory = API.new('ReadProcessMemory', 'LPPPP', 'I', 'kernel32')
        i1 = 0.chr * 8
        buf = 0.chr * size
        if fReadProcessMemory.call(handle, base, buf, size, i1) == 1
          buf
        else
          nil
        end
      end

      def self.is_wow64?
        fIsWow64Process = API.new('IsWow64Process', 'PP', 'I', 'kernel32')
        wow64 = 0.chr
        raise "Failed to call IsWow64Process" if fIsWow64Process.call(-1, wow64) == 0

        wow64.unpack('C').first == 1
      end

      def self.process_arch(pid=nil, handle=-1)
        case Metasm::WinOS::Process.new(pid, handle).addrsz / 8
        when 4
          'x86'
        when 8
          'x64'
        end
      end

      def self.process_arch_x64?(pid=nil, handle=-1)
        Metasm::WinOS::Process.new(pid, handle).addrsz / 8 == 8
      end

      def self.find_import_func(func, filenames, stop_when_found = false)
        found = []
        filenames.each do |f|
          dfile = ::Metasm::PE.decode_file_header f
          dfile.decode_imports
          imports = dfile.imports
          next if not imports
          imports.each do |import_dict|
            import_dict.imports.each do |import_desc|
              if import_desc.name == func
                return f if stop_when_found
                found << f
              end
            end
          end
        end

        found
      end

      def self.find_export_func(func, filenames, stop_when_found = false)
        found = []
        filenames.each do |f|
          dfile = ::Metasm::PE.decode_file_header f
          dfile.decode_exports
          export = dfile.export
          next if !export
          next if !export.exports
          export.exports.each do |exp|
            if exp.name == func && !exp.forwarder_lib
              return f if stop_when_found
              found << f
            end
          end
        end
      end
    end
  end
end
