# frozen_string_literal: true

unless OS.windows?
  warn "\033[33m[-]Warning: This module doesn't currently work on non-Windows os.\033[0m"
end

module TurboRex
  class Windows < ::Metasm::WinOS
    module COM
      module WellKnownIID
        IID_IUnknown = '00000000-0000-0000-C000-000000000046'
        IID_IClassFactory = '00000001-0000-0000-C000-000000000046'
        IID_IStream = '0000000c-0000-0000-C000-000000000046'
        IID_IStorage = '0000000b-0000-0000-C000-000000000046'
        IID_IPSFactoryBuffer = 'D5F569D0-593B-101A-B569-08002B2DBF7A'
        IID_IRpcProxyBuffer = 'D5F56A34-593B-101A-B569-08002B2DBF7A'
        IID_IRpcStubBuffer = 'D5F56AFC-593B-101A-B569-08002B2DBF7A'
      end

      CLSCTX_INPROC_SERVER = 0x1
      CLSCTX_INPROC_HANDLER = 0x2
      CLSCTX_LOCAL_SERVER = 0x4
      CLSCTX_INPROC_SERVER16 = 0x8
      CLSCTX_REMOTE_SERVER = 0x10
      CLSCTX_INPROC_HANDLER16 = 0x20
      CLSCTX_RESERVED1  = 0x40
      CLSCTX_RESERVED2  = 0x80
      CLSCTX_RESERVED3  = 0x100
      CLSCTX_RESERVED4  = 0x200
      CLSCTX_NO_CODE_DOWNLOAD = 0x400
      CLSCTX_RESERVED5 = 0x800
      CLSCTX_NO_CUSTOM_MARSHAL = 0x1000
      CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000
      CLSCTX_NO_FAILURE_LOG = 0x4000
      CLSCTX_DISABLE_AAA = 0x8000
      CLSCTX_ENABLE_AAA = 0x10000
      CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000
      CLSCTX_ACTIVATE_X86_SERVER = 0x40000
      CLSCTX_ACTIVATE_32_BIT_SERVER  = CLSCTX_ACTIVATE_X86_SERVER
      CLSCTX_ACTIVATE_64_BIT_SERVER  = 0x80000
      CLSCTX_ENABLE_CLOAKING = 0x100000
      CLSCTX_APPCONTAINER = 0x400000
      CLSCTX_ACTIVATE_AAA_AS_IU = 0x800000
      CLSCTX_RESERVED6 = 0x1000000
      CLSCTX_ACTIVATE_ARM32_SERVER = 0x2000000
      CLSCTX_PS_DLL = 0x80000000

      # WinVer >= NT4 && DCOM
      if TurboRex::Windows.version.first >= 4
        CLSCTX_ALL = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER
        CLSCTX_SERVER = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER
      end

      # Mashal Flag
      MSHLFLAGS_NORMAL = 0
      MSHLFLAGS_TABLESTRONG = 1
      MSHLFLAGS_TABLEWEAK = 2
      MSHLFLAGS_NOPING = 4
      MSHLFLAGS_RESERVED1  = 8
      MSHLFLAGS_RESERVED2  = 16
      MSHLFLAGS_RESERVED3  = 32
      MSHLFLAGS_RESERVED4  = 64

      # Mashal Context
      MSHCTX_LOCAL = 0
      MSHCTX_NOSHAREDMEM = 1
      MSHCTX_DIFFERENTMACHINE = 2
      MSHCTX_INPROC = 3
      MSHCTX_CROSSCTX = 4
      MSHCTX_RESERVED1 = 5

      # Object Refenrence Flags
      OBJREF_STANDARD = 1
      OBJREF_HANDLER = 2
      OBJREF_CUSTOM = 4
      OBJREF_EXTENDED = 8

      # STGM Constant
      STGM_READ = 0x00000000
      STGM_WRITE = 0x00000001
      STGM_READWRITE = 0x00000002
      STGM_SHARE_DENY_NONE = 0x00000040
      STGM_SHARE_DENY_READ = 0x00000030
      STGM_SHARE_DENY_WRITE = 0x00000020
      STGM_SHARE_EXCLUSIVE = 0x00000010
      STGM_PRIORITY = 0x00040000
      STGM_CREATE = 0x00001000
      STGM_CONVERT = 0x00020000
      STGM_FAILIFTHERE = 0x00000000
      STGM_DIRECT = 0x00000000
      STGM_TRANSACTED = 0x00010000
      STGM_NOSCRATCH = 0x00100000
      STGM_NOSNAPSHOT = 0x00200000
      STGM_SIMPLE = 0x08000000
      STGM_DIRECT_SWMR = 0x00400000
      STGM_DELETEONRELEASE = 0x04000000

      INTERNAL_APIPROXY = TurboRex::Windows::Win32API.dup
      INTERNAL_APIPROXY.parse_c <<-EOS
        typedef struct SHashChain
        {
          struct SHashChain *pNext;
          struct SHashChain *pPrev;
        } SHashChain;

        typedef struct _CIDObject {
          void * pVtable;
          SHashChain _pidChain;
          SHashChain _oidChain;
          unsigned int _dwState;
          unsigned int _cRefs;
          void *_pServer;
          void *_pServerCtx;
          GUID _oid;
          unsigned int _aptID;
          void *_pStdWrapper;
          void *_pStdID;
          unsigned int _cCalls;
          unsigned int _cLocks;
          SHashChain _oidUnpinReqChain;
          unsigned int _dwOidUnpinReqState;
          void *_pvObjectTrackCookie;
        } CIDObject;

        typedef struct _CStdWrapper
        {
          void * pVtable;
          unsigned long _dwState;
          unsigned int _cRefs;
          unsigned int _cCalls;
          unsigned int _cIFaces;
          void *_pIFaceHead;
          void *_pCtxEntryHead;
          void *_pCtxFreeList;
          void *_pServer;
          CIDObject *_pID;
          void *_pVtableAddress;
        }CStdWrapper;

        typedef struct _tagIPIDEntry
        {
          void *pNextIPID;
          unsigned int dwFlags;
          unsigned int cStrongRefs;
          unsigned int cWeakRefs;
          unsigned int cPrivateRefs;
          void *pv;
          void *pStub;
          void *pOXIDEntry;
          GUID ipid;
          GUID iid;
          void *pChnl;
          void *pIRCEntry;
          void *pInterfaceName;
          void *pOIDFLink;
          void *pOIDBLink;
        } tagIPIDEntry;


        typedef struct _CStdIdentity
        {
          void *pVtable;
          void *pVtable2;
          unsigned int _dwFlags;
          int _cIPIDs;
          tagIPIDEntry *_pFirstIPID;
          void *_pStdId;
          void *_pChnl;
          GUID _clsidHandler;
          int _cNestedCalls;
          int _cTableRefs;
        } CStdIdentity;


        typedef struct _IRpcStubBufferVtbl
        {
          HRESULT (__fastcall *QueryInterface)(void *, const GUID *, void **);
          unsigned int (__fastcall *AddRef)(void *);
          unsigned int (__fastcall *Release)(void *);
          HRESULT (__fastcall *Connect)(void *, void *);
          void (__fastcall *Disconnect)(void *);
          HRESULT (__fastcall *Invoke)(void *, void *, void *);
          void *(__fastcall *IsIIDSupported)(void *, const GUID *);
          unsigned int (__fastcall *CountRefs)(void *);
          HRESULT (__fastcall *DebugServerQueryInterface)(void *, void **);
          void (__fastcall *DebugServerRelease)(void *, void *);
        } IRpcStubBufferVtbl;

        typedef struct tagCStdStubBuffer
        {
            const struct IRpcStubBufferVtbl *   lpVtbl;
            LONG                                RefCount;
            struct IUnknown *                   pvServerObject;

            const struct ICallFactoryVtbl *     pCallFactoryVtbl;
            const IID *                         pAsyncIID;
            struct IPSFactoryBuffer *           pPSFactory;
            const struct IReleaseMarshalBuffersVtbl *     pRMBVtbl;
        } CStdStubBuffer;

        typedef struct tagCInterfaceStubHeader
        {
            const IID               *   piid;
            const void  *   pServerInfo; // MIDL_SERVER_INFO
            ULONG               DispatchTableCount;
            const void *  pDispatchTable;
        } CInterfaceStubHeader;

        typedef struct tagCInterfaceProxyHeader
        {
        #ifdef USE_STUBLESS_PROXY
            const void *    pStublessProxyInfo;
        #endif
            const IID *     piid;
        } CInterfaceProxyHeader;

        typedef struct tagCInterfaceProxyVtbl
        {
            CInterfaceProxyHeader header;
            void *Vtbl[1];
        } CInterfaceProxyVtbl;

        typedef struct tagCInterfaceStubVtbl
        {
            CInterfaceStubHeader        header;
            IRpcStubBufferVtbl          Vtbl;
        } CInterfaceStubVtbl;

        typedef struct tagCInterfaceStubVtbl *  PCInterfaceStubVtblList;
        typedef struct tagCInterfaceProxyVtbl *  PCInterfaceProxyVtblList;
        typedef const char *                    PCInterfaceName;
        typedef int __stdcall IIDLookupRtn( const IID * pIID, int * pIndex );
        typedef IIDLookupRtn * PIIDLookup;

        typedef struct tagProxyFileInfo
        {
            const PCInterfaceProxyVtblList *pProxyVtblList;
            const PCInterfaceStubVtblList  *pStubVtblList;
            const PCInterfaceName *         pNamesArray;
            const IID **                    pDelegatedIIDs;
            const PIIDLookup                pIIDLookupRtn;
            unsigned short                  TableSize;
            unsigned short                  TableVersion;
            const IID **                    pAsyncIIDLookup;
            LONG_PTR                        Filler2;
            LONG_PTR                        Filler3;
            LONG_PTR                        Filler4;
        }ProxyFileInfo;

        typedef struct tagCStdPSFactoryBuffer
        {
            const IPSFactoryBufferVtbl  *   lpVtbl;
            LONG                            RefCount;
            const ProxyFileInfo **          pProxyFileList;
            LONG                            Filler1;  //Reserved for future use.
        } CStdPSFactoryBuffer;
      EOS

      require 'turborex/windows/com/interface.rb'
      require 'turborex/windows/com/utils.rb'
      require 'turborex/windows/com/client.rb'
      require 'turborex/windows/com/com_registry.rb'
      require 'turborex/windows/com/com_finder.rb'
    end
  end
end
