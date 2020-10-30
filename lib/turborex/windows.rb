# frozen_string_literal: true

require 'metasm'
require 'turborex/windows/constants.rb'
require 'turborex/windows/tinysdk'
require 'turborex/windows/process'
require 'win32/api' if ::OS.windows?
require 'turborex/windows/utils'
require 'turborex/windows/alpc'
# require 'turborex/windows/com'

module TurboRex
  class Windows < Metasm::WinOS
    class Win32API < Metasm::WinAPI
      cp.lexer.warn_redefinition = false
      cp.lexer.include_search_path += TurboRex::Utils.get_all_subdir(TurboRex.root + '/resources/headers/')
      #dbghelp_path = ENV.fetch('DBGHELP_PATH') { File.join(TurboRex.root, '/resources/bin/x86/dbghelp.dll') }

      if TurboRex::Windows::Utils.process_arch_x64?
        cp.llp64
        cp.lexer.define('_WIN64')
        #dbghelp_path = ENV.fetch('DBGHELP64_PATH') { File.join(TurboRex.root, '/resources/bin/x64/dbghelp.dll') }
      end

      parse_c(File.read(TurboRex.root + '/resources/headers/tinysdk/tinysdk.h'))

      new_api_c <<-EOS, 'Psapi.dll'
        BOOL EnumProcesses(
          DWORD   *lpidProcess,
          DWORD   cb,
          LPDWORD lpcbNeeded
        );
      EOS

      new_api_c <<-EOS, 'Kernel32.dll'
        HLOCAL
        WINAPI
        LocalFree(
          HLOCAL hMem
        );

        LPVOID GlobalLock(
          HGLOBAL hMem
        );

        BOOL GlobalUnlock(
          HGLOBAL hMem
        );

        DWORD GetLastError();

        BOOL CloseHandle(
          HANDLE hObject
        );
        
        HANDLE CreateFileMappingA(
          HANDLE                hFile,
          LPVOID lpFileMappingAttributes,
          DWORD                 flProtect,
          DWORD                 dwMaximumSizeHigh,
          DWORD                 dwMaximumSizeLow,
          LPCSTR                lpName
        );

        HANDLE OpenFileMappingA(
          DWORD  dwDesiredAccess,
          BOOL   bInheritHandle,
          LPCSTR lpName
        );

        LPVOID MapViewOfFile(
          HANDLE hFileMappingObject,
          DWORD  dwDesiredAccess,
          DWORD  dwFileOffsetHigh,
          DWORD  dwFileOffsetLow,
          SIZE_T dwNumberOfBytesToMap
        );

        BOOL UnmapViewOfFile(
          LPCVOID lpBaseAddress
        );
      EOS

      new_api_c <<-EOS, 'ole32.dll'
        HRESULT CoInitialize(
          LPVOID pvReserved
        );

        HRESULT CoInitializeEx(
          LPVOID pvReserved,
          DWORD  dwCoInit
        );

        HRESULT CoCreateInstance(
          REFCLSID  rclsid,
          LPUNKNOWN pUnkOuter,
          DWORD     dwClsContext,
          REFIID    riid,
          LPVOID    *ppv
        );

        HRESULT CoGetClassObject(
          REFCLSID rclsid,
          DWORD    dwClsContext,
          LPVOID   pvReserved,
          REFIID   riid,
          LPVOID   *ppv
        );

        HRESULT CoGetPSClsid(
          REFIID riid,
          CLSID  *pClsid
        );

        HRESULT CoMarshalInterface(
          LPSTREAM  pStm,
          REFIID    riid,
          LPUNKNOWN pUnk,
          DWORD     dwDestContext,
          LPVOID    pvDestContext,
          DWORD     mshlflags
        );

        HRESULT CoUnmarshalInterface(
          LPSTREAM pStm,
          REFIID   riid,
          LPVOID   *ppv
        );

        HRESULT CreateStreamOnHGlobal(
          HGLOBAL  hGlobal,
          BOOL     fDeleteOnRelease,
          LPSTREAM *ppstm
        );

        HRESULT GetHGlobalFromStream(
          LPSTREAM pstm,
          HGLOBAL  *phglobal
        );

        HRESULT CoGetMarshalSizeMax(
          ULONG     *pulSize,
          REFIID    riid,
          LPUNKNOWN pUnk,
          DWORD     dwDestContext,
          LPVOID    pvDestContext,
          DWORD     mshlflags
        );

        HRESULT CLSIDFromString(
          LPCOLESTR lpsz,
          LPCLSID   pclsid
        );

        HRESULT StgCreateDocfile(
          const WCHAR *pwcsName,
          DWORD       grfMode,
          DWORD       reserved,
          IStorage    **ppstgOpen
        );
      EOS

      new_api_c <<-EOS, 'OleAut32.dll'
        BSTR SysAllocString(
          const OLECHAR *psz
        );

        void SysFreeString(
          BSTR bstrString
        );
      EOS

      new_api_c <<-EOS, 'dbghelp.dll'
        #define IMAGEAPI __stdcall
        #define SYMOPT_CASE_INSENSITIVE         0x00000001
        #define SYMOPT_UNDNAME                  0x00000002
        #define SYMOPT_DEFERRED_LOADS           0x00000004
        #define SYMOPT_NO_CPP                   0x00000008
        #define SYMOPT_LOAD_LINES               0x00000010
        #define SYMOPT_OMAP_FIND_NEAREST        0x00000020
        #define SYMOPT_LOAD_ANYTHING            0x00000040
        #define SYMOPT_IGNORE_CVREC             0x00000080
        #define SYMOPT_NO_UNQUALIFIED_LOADS     0x00000100
        #define SYMOPT_FAIL_CRITICAL_ERRORS     0x00000200
        #define SYMOPT_EXACT_SYMBOLS            0x00000400
        #define SYMOPT_ALLOW_ABSOLUTE_SYMBOLS   0x00000800
        #define SYMOPT_IGNORE_NT_SYMPATH        0x00001000
        #define SYMOPT_INCLUDE_32BIT_MODULES    0x00002000
        #define SYMOPT_PUBLICS_ONLY             0x00004000
        #define SYMOPT_NO_PUBLICS               0x00008000
        #define SYMOPT_AUTO_PUBLICS             0x00010000
        #define SYMOPT_NO_IMAGE_SEARCH          0x00020000
        #define SYMOPT_SECURE                   0x00040000
        #define SYMOPT_NO_PROMPTS               0x00080000
        #define SYMOPT_DEBUG                    0x80000000

        typedef int BOOL;
        typedef char CHAR;
        typedef unsigned long DWORD;
        typedef unsigned __int64 DWORD64;
        typedef void *HANDLE;
        typedef unsigned __int64 *PDWORD64;
        typedef void *PVOID;
        typedef unsigned long ULONG;
        typedef unsigned __int64 ULONG64;
        typedef const CHAR *PCSTR;
        typedef CHAR *PSTR;
        typedef struct _SYMBOL_INFO *PSYMBOL_INFO;
        typedef __stdcall BOOL (*PSYM_ENUMERATESYMBOLS_CALLBACK)(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
        typedef enum
        {
            SymNone = 0,
            SymCoff,
            SymCv,
            SymPdb,
            SymExport,
            SymDeferred,
            SymSym,
            SymDia,
            SymVirtual,
            NumSymTypes
        } SYM_TYPE;

        typedef struct _SYMBOL_INFO {
          ULONG SizeOfStruct;
          ULONG TypeIndex;
          ULONG64 Reserved[2];
          ULONG info;
          ULONG Size;
          ULONG64 ModBase;
          ULONG Flags;
          ULONG64 Value;
          ULONG64 Address;
          ULONG Register;
          ULONG Scope;
          ULONG Tag;
          ULONG NameLen;
          ULONG MaxNameLen;
          CHAR Name[1];
        } SYMBOL_INFO, *PSYMBOL_INFO;

        typedef struct _MODLOAD_DATA {
          DWORD ssize;
          DWORD ssig;
          PVOID data;
          DWORD size;
          DWORD flags;
        } MODLOAD_DATA, *PMODLOAD_DATA;


        __stdcall DWORD SymGetOptions(void);
        __stdcall DWORD SymSetOptions(DWORD SymOptions __attribute__((in)));
        __stdcall BOOL SymInitialize(HANDLE hProcess __attribute__((in)), PSTR UserSearchPath __attribute__((in)), BOOL fInvadeProcess __attribute__((in)));
        __stdcall DWORD64 SymLoadModule64(HANDLE hProcess __attribute__((in)), HANDLE hFile __attribute__((in)), PSTR ImageName __attribute__((in)), PSTR ModuleName __attribute__((in)), DWORD64 BaseOfDll __attribute__((in)), DWORD SizeOfDll __attribute__((in)));
        __stdcall BOOL SymSetSearchPath(HANDLE hProcess __attribute__((in)), PSTR SearchPathA __attribute__((in)));
        __stdcall BOOL SymFromAddr(HANDLE hProcess __attribute__((in)), DWORD64 Address __attribute__((in)), PDWORD64 Displacement __attribute__((out)), PSYMBOL_INFO Symbol __attribute__((in)) __attribute__((out)));
        __stdcall BOOL SymEnumSymbols(HANDLE hProcess __attribute__((in)), ULONG64 BaseOfDll __attribute__((in)), PCSTR Mask __attribute__((in)), PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback __attribute__((in)), PVOID UserContext __attribute__((in)));

        DWORD64 IMAGEAPI SymLoadModuleEx(
          HANDLE        hProcess,
          HANDLE        hFile,
          PCSTR         ImageName,
          PCSTR         ModuleName,
          DWORD64       BaseOfDll,
          DWORD         DllSize,
          PMODLOAD_DATA Data,
          DWORD         Flags
        );

        BOOL IMAGEAPI SymFromName(
          HANDLE       hProcess,
          PCSTR        Name,
          PSYMBOL_INFO Symbol
        );

        BOOL
        IMAGEAPI
        SymGetModuleInfo64(
             HANDLE hProcess,
             DWORD64 qwAddr,
             PIMAGEHLP_MODULE64 ModuleInfo
        );

        BOOL
        IMAGEAPI
        SymGetModuleInfoW64(
             HANDLE hProcess,
             DWORD64 qwAddr,
             PIMAGEHLP_MODULEW64 ModuleInfo
        );

        #if !defined(_IMAGEHLP_SOURCE_) && defined(_IMAGEHLP64)
        #define SymGetModuleInfo   SymGetModuleInfo64
        #define SymGetModuleInfoW  SymGetModuleInfoW64
        #else
          BOOL
          IMAGEAPI
          SymGetModuleInfo(
               HANDLE hProcess,
               DWORD dwAddr,
               PIMAGEHLP_MODULE ModuleInfo
              );

          BOOL
          IMAGEAPI
          SymGetModuleInfoW(
               HANDLE hProcess,
               DWORD dwAddr,
               PIMAGEHLP_MODULEW ModuleInfo
              );
        #endif
      EOS

      new_api_c <<-EOS, 'Advapi32.dll'
        DWORD GetSecurityDescriptorLength(
          PSECURITY_DESCRIPTOR pSecurityDescriptor
        );

        BOOL GetSecurityDescriptorDacl(
          PSECURITY_DESCRIPTOR pSecurityDescriptor,
          LPBOOL               lpbDaclPresent,
          PACL                 *pDacl,
          LPBOOL               lpbDaclDefaulted
        );

        BOOL GetSecurityDescriptorControl(
          PSECURITY_DESCRIPTOR         pSecurityDescriptor,
          PSECURITY_DESCRIPTOR_CONTROL pControl,
          LPDWORD                      lpdwRevision
        );

        BOOL GetSecurityDescriptorOwner(
          PSECURITY_DESCRIPTOR pSecurityDescriptor,
          PSID                 *pOwner,
          LPBOOL               lpbOwnerDefaulted
        );

        BOOL GetSecurityDescriptorGroup(
          PSECURITY_DESCRIPTOR pSecurityDescriptor,
          PSID                 *pGroup,
          LPBOOL               lpbGroupDefaulted
        );

        BOOL ConvertSidToStringSidA(
          PSID  Sid,
          LPSTR *StringSid
        );

        BOOL ConvertStringSidToSidW(
          LPCWSTR StringSid,
          PSID    *Sid
        );

        BOOL GetAclInformation(
          PACL                  pAcl,
          LPVOID                pAclInformation,
          DWORD                 nAclInformationLength,
          ACL_INFORMATION_CLASS dwAclInformationClass
        );

        BOOL GetAce(
          PACL   pAcl,
          DWORD  dwAceIndex,
          LPVOID *pAce
        );
      EOS
    end

    class Thread < Metasm::WinOS
    end

    class Token
    end

    def self.open_process(pid, mask = Metasm::WinAPI::PROCESS_QUERY_INFORMATION)
      if handle = Metasm::WinAPI.openprocess(mask, 0, pid)
        return open_process_handle(handle)
      end

      nil
    end

    def self.open_process_handle(handle)
      pid = begin
              WinAPI.getprocessid(handle)
            rescue StandardError
              0
            end
      TurboRex::Windows::Process.new(pid, handle)
    end

    def self.list_all_process_pid
      lpidProcess = Win32API.alloc_c_ary('DWORD', 1024)
      cb = 1024
      lpcbNeeded = 0

      Win32API.enumprocesses(lpidProcess, cb, lpcbNeeded)

      lpidProcess
    end
  end
end
