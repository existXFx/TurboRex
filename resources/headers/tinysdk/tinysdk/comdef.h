#include "rpc.h"
#define BEGIN_INTERFACE
#define END_INTERFACE
#define _COM_Outptr_
#define CONST_VTBL
#define STDMETHODCALLTYPE       __stdcall
#define interface struct
#define _Inout_
#define _Out_opt_
#define _Out_
#define _Outptr_
#define _In_opt_

typedef struct _COAUTHIDENTITY
{
    /* [size_is] */ USHORT *User;
    /* [range] */ ULONG UserLength;
    /* [size_is] */ USHORT *Domain;
    /* [range] */ ULONG DomainLength;
    /* [size_is] */ USHORT *Password;
    /* [range] */ ULONG PasswordLength;
    ULONG Flags;
} 	COAUTHIDENTITY;


typedef struct _COAUTHINFO
{
    DWORD dwAuthnSvc;
    DWORD dwAuthzSvc;
    LPWSTR pwszServerPrincName;
    DWORD dwAuthnLevel;
    DWORD dwImpersonationLevel;
    COAUTHIDENTITY *pAuthIdentityData;
    DWORD dwCapabilities;
} COAUTHINFO;

typedef struct _COSERVERINFO
{
    DWORD dwReserved1;
    LPWSTR pwszName;
    COAUTHINFO *pAuthInfo;
    DWORD dwReserved2;
} COSERVERINFO;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef enum tagCOINIT
{
    COINIT_APARTMENTTHREADED  = 0x2, /* Apartment model */
    COINIT_MULTITHREADED      = 0x0, /* OLE calls objects on any thread */
    COINIT_DISABLE_OLE1DDE    = 0x4, /* Don't use DDE for Ole1 support */
    COINIT_SPEED_OVER_MEMORY  = 0x8  /* Trade memory for speed */
} COINIT;

typedef ULONG RPCOLEDATAREP;

typedef struct tagRPCOLEMESSAGE
    {
    void *reserved1;
    RPCOLEDATAREP dataRepresentation;
    void *Buffer;
    ULONG cbBuffer;
    ULONG iMethod;
    void *reserved2[ 5 ];
    ULONG rpcFlags;
} RPCOLEMESSAGE;

typedef struct tagSTATSTG
{
    LPOLESTR pwcsName;
    DWORD type;
    ULARGE_INTEGER cbSize;
    FILETIME mtime;
    FILETIME ctime;
    FILETIME atime;
    DWORD grfMode;
    DWORD grfLocksSupported;
    CLSID clsid;
    DWORD grfStateBits;
    DWORD reserved;
} STATSTG;

/* interface IUnkown */
typedef interface IUnknown IUnknown;

typedef struct IUnknownVtbl
{
    BEGIN_INTERFACE
    
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        IUnknown * This,
        REFIID riid,
        _COM_Outptr_  void **ppvObject);
    
    ULONG ( STDMETHODCALLTYPE *AddRef )( 
      IUnknown * This);
    
    ULONG ( STDMETHODCALLTYPE *Release )( 
      IUnknown * This);
    END_INTERFACE
} IUnknownVtbl;

interface IUnknown
{
    CONST_VTBL struct IUnknownVtbl *lpVtbl;
};

typedef IUnknown *LPUNKNOWN;

typedef struct tagMULTI_QI
{
  const IID *pIID;
  IUnknown *pItf;
  HRESULT hr;
} MULTI_QI;

/* interface IClassFactory */
typedef interface IClassFactory IClassFactory;
    typedef struct IClassFactoryVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
             IClassFactory * This,
             REFIID riid,
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
             IClassFactory * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
             IClassFactory * This);
        
        HRESULT ( STDMETHODCALLTYPE *CreateInstance )( 
            IClassFactory * This,
            IUnknown *pUnkOuter,
            REFIID riid,
            _COM_Outptr_  void **ppvObject);
        
        HRESULT ( STDMETHODCALLTYPE *LockServer )( 
            IClassFactory * This,
            BOOL fLock);
        
        END_INTERFACE
    } IClassFactoryVtbl;

    interface IClassFactory
    {
        CONST_VTBL struct IClassFactoryVtbl *lpVtbl;
    };


    /* IStream */
    typedef interface IStream IStream;
    typedef struct IStreamVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
             IStream * This,
             REFIID riid,
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
             IStream * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
             IStream * This);
        
        HRESULT ( STDMETHODCALLTYPE *Read )( 
            IStream * This,
            void *pv,
            ULONG cb,
            ULONG *pcbRead);
        
        HRESULT ( STDMETHODCALLTYPE *Write )( 
            IStream * This,
            const void *pv,
            ULONG cb,
            ULONG *pcbWritten);
        
        HRESULT ( STDMETHODCALLTYPE *Seek )( 
            IStream * This,
            LARGE_INTEGER dlibMove,
            DWORD dwOrigin,
            ULARGE_INTEGER *plibNewPosition);
        
        HRESULT ( STDMETHODCALLTYPE *SetSize )( 
             IStream * This,
             ULARGE_INTEGER libNewSize);
        
        HRESULT ( STDMETHODCALLTYPE *CopyTo )( 
            IStream * This,
            IStream *pstm,
            ULARGE_INTEGER cb,
            ULARGE_INTEGER *pcbRead,
            ULARGE_INTEGER *pcbWritten);
        
        HRESULT ( STDMETHODCALLTYPE *Commit )( 
             IStream * This,
             DWORD grfCommitFlags);
        
        HRESULT ( STDMETHODCALLTYPE *Revert )( 
             IStream * This);
        
        HRESULT ( STDMETHODCALLTYPE *LockRegion )( 
             IStream * This,
             ULARGE_INTEGER libOffset,
             ULARGE_INTEGER cb,
             DWORD dwLockType);
        
        HRESULT ( STDMETHODCALLTYPE *UnlockRegion )( 
            IStream * This,
            ULARGE_INTEGER libOffset,
            ULARGE_INTEGER cb,
            DWORD dwLockType);
        
        HRESULT ( STDMETHODCALLTYPE *Stat )( 
             IStream * This,
              STATSTG *pstatstg,
             DWORD grfStatFlag);
        
        HRESULT ( STDMETHODCALLTYPE *Clone )( 
             IStream * This,
             IStream **ppstm);
        
        END_INTERFACE
    } IStreamVtbl;

    interface IStream
    {
        CONST_VTBL struct IStreamVtbl *lpVtbl;
    };

    typedef IStream *LPSTREAM;


    /* IEnumSTATSTG */
    typedef interface IEnumSTATSTG IEnumSTATSTG;
     typedef struct IEnumSTATSTGVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
             IEnumSTATSTG * This,
             REFIID riid,
              void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
             IEnumSTATSTG * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
             IEnumSTATSTG * This);
        
        HRESULT ( STDMETHODCALLTYPE *Next )( 
            IEnumSTATSTG * This,
             ULONG celt,
            STATSTG *rgelt,
            ULONG *pceltFetched);
        
        HRESULT ( STDMETHODCALLTYPE *Skip )( 
             IEnumSTATSTG * This,
             ULONG celt);
        
        HRESULT ( STDMETHODCALLTYPE *Reset )( 
             IEnumSTATSTG * This);
        
        HRESULT ( STDMETHODCALLTYPE *Clone )( 
             IEnumSTATSTG * This,
             IEnumSTATSTG **ppenum);
        
        END_INTERFACE
    } IEnumSTATSTGVtbl;

    interface IEnumSTATSTG
    {
        CONST_VTBL struct IEnumSTATSTGVtbl *lpVtbl;
    };


    /* IStorage */

    typedef  LPOLESTR *SNB;

    typedef interface IStorage IStorage;
    typedef struct IStorageVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
             IStorage * This,
             REFIID riid,
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
             IStorage * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
             IStorage * This);
        
        HRESULT ( STDMETHODCALLTYPE *CreateStream )( 
             IStorage * This,
             const OLECHAR *pwcsName,
             DWORD grfMode,
             DWORD reserved1,
             DWORD reserved2,
             IStream **ppstm);
        
        HRESULT ( STDMETHODCALLTYPE *OpenStream )( 
            IStorage * This,
              const OLECHAR *pwcsName,
              void *reserved1,
            DWORD grfMode,
            DWORD reserved2,
              IStream **ppstm);
        
        HRESULT ( STDMETHODCALLTYPE *CreateStorage )( 
             IStorage * This,
            /* [string][in] */  const OLECHAR *pwcsName,
            /* [in] */ DWORD grfMode,
            /* [in] */ DWORD reserved1,
            /* [in] */ DWORD reserved2,
            /* [out] */  IStorage **ppstg);
        
        HRESULT ( STDMETHODCALLTYPE *OpenStorage )( 
             IStorage * This,
            /* [string][unique][in] */  const OLECHAR *pwcsName,
            /* [unique][in] */  IStorage *pstgPriority,
            /* [in] */ DWORD grfMode,
            /* [unique][in] */  SNB snbExclude,
            /* [in] */ DWORD reserved,
            /* [out] */  IStorage **ppstg);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *CopyTo )( 
            IStorage * This,
            /* [in] */ DWORD ciidExclude,
            /* [annotation][size_is][unique][in] */ 
              const IID *rgiidExclude,
            /* [annotation][unique][in] */ 
              SNB snbExclude,
            /* [annotation][unique][in] */ 
              IStorage *pstgDest);
        
        HRESULT ( STDMETHODCALLTYPE *MoveElementTo )( 
             IStorage * This,
            /* [string][in] */  const OLECHAR *pwcsName,
            /* [unique][in] */  IStorage *pstgDest,
            /* [string][in] */  const OLECHAR *pwcsNewName,
            /* [in] */ DWORD grfFlags);
        
        HRESULT ( STDMETHODCALLTYPE *Commit )( 
             IStorage * This,
            /* [in] */ DWORD grfCommitFlags);
        
        HRESULT ( STDMETHODCALLTYPE *Revert )( 
             IStorage * This);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *EnumElements )( 
            IStorage * This,
            /* [annotation][in] */ 
              DWORD reserved1,
            /* [annotation][size_is][unique][in] */ 
              void *reserved2,
            /* [annotation][in] */ 
              DWORD reserved3,
            /* [annotation][out] */ 
              IEnumSTATSTG **ppenum);
        
        HRESULT ( STDMETHODCALLTYPE *DestroyElement )( 
             IStorage * This,
            /* [string][in] */  const OLECHAR *pwcsName);
        
        HRESULT ( STDMETHODCALLTYPE *RenameElement )( 
             IStorage * This,
            /* [string][in] */  const OLECHAR *pwcsOldName,
            /* [string][in] */  const OLECHAR *pwcsNewName);
        
        HRESULT ( STDMETHODCALLTYPE *SetElementTimes )( 
             IStorage * This,
            /* [string][unique][in] */  const OLECHAR *pwcsName,
            /* [unique][in] */  const FILETIME *pctime,
            /* [unique][in] */  const FILETIME *patime,
            /* [unique][in] */  const FILETIME *pmtime);
        
        HRESULT ( STDMETHODCALLTYPE *SetClass )( 
             IStorage * This,
            /* [in] */  REFCLSID clsid);
        
        HRESULT ( STDMETHODCALLTYPE *SetStateBits )( 
             IStorage * This,
            /* [in] */ DWORD grfStateBits,
            /* [in] */ DWORD grfMask);
        
        HRESULT ( STDMETHODCALLTYPE *Stat )( 
             IStorage * This,
            /* [out] */  STATSTG *pstatstg,
            /* [in] */ DWORD grfStatFlag);
        
        END_INTERFACE
    } IStorageVtbl;

    interface IStorage
    {
        CONST_VTBL struct IStorageVtbl *lpVtbl;
    };

    typedef /* [unique] */  IStorage *LPSTORAGE;

typedef interface    IRpcChannelBuffer  IRpcChannelBuffer;
    typedef struct IRpcChannelBufferVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRpcChannelBuffer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRpcChannelBuffer * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRpcChannelBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetBuffer )( 
            IRpcChannelBuffer * This,
            /* [annotation][out][in] */ 
            _Inout_  RPCOLEMESSAGE *pMessage,
            /* [annotation][in] */ 
            _In_  REFIID riid);
        
        HRESULT ( STDMETHODCALLTYPE *SendReceive )( 
            IRpcChannelBuffer * This,
            /* [annotation][out][in] */ 
            _Inout_  RPCOLEMESSAGE *pMessage,
            /* [annotation][out] */ 
            _Out_opt_  ULONG *pStatus);
        
        HRESULT ( STDMETHODCALLTYPE *FreeBuffer )( 
            IRpcChannelBuffer * This,
            /* [annotation][out][in] */ 
            _Inout_  RPCOLEMESSAGE *pMessage);
        
        HRESULT ( STDMETHODCALLTYPE *GetDestCtx )( 
            IRpcChannelBuffer * This,
            /* [annotation][out] */ 
            _Out_  DWORD *pdwDestContext,
            /* [annotation][out] */ 
            void **ppvDestContext);
        
        HRESULT ( STDMETHODCALLTYPE *IsConnected )( 
            IRpcChannelBuffer * This);
        
        END_INTERFACE
    } IRpcChannelBufferVtbl;

    interface IRpcChannelBuffer
    {
        CONST_VTBL struct IRpcChannelBufferVtbl *lpVtbl;
    };

typedef interface IRpcProxyBuffer IRpcProxyBuffer;
    typedef struct IRpcProxyBufferVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRpcProxyBuffer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRpcProxyBuffer * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRpcProxyBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *Connect )( 
            IRpcProxyBuffer * This,
            /* [annotation][unique][in] */ 
            _In_  IRpcChannelBuffer *pRpcChannelBuffer);
        
        void ( STDMETHODCALLTYPE *Disconnect )( 
            IRpcProxyBuffer * This);
        
        END_INTERFACE
    } IRpcProxyBufferVtbl;

    interface IRpcProxyBuffer
    {
        CONST_VTBL struct IRpcProxyBufferVtbl *lpVtbl;
    };

typedef interface    IRpcStubBuffer     IRpcStubBuffer;
    typedef struct IRpcStubBufferVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRpcStubBuffer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRpcStubBuffer * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRpcStubBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *Connect )( 
            IRpcStubBuffer * This,
            /* [annotation][in] */ 
            _In_  IUnknown *pUnkServer);
        
        void ( STDMETHODCALLTYPE *Disconnect )( 
            IRpcStubBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IRpcStubBuffer * This,
            /* [annotation][out][in] */ 
            _Inout_  RPCOLEMESSAGE *_prpcmsg,
            /* [annotation][in] */ 
            _In_  IRpcChannelBuffer *_pRpcChannelBuffer);
        
        IRpcStubBuffer *( STDMETHODCALLTYPE *IsIIDSupported )( 
            IRpcStubBuffer * This,
            /* [annotation][in] */ 
            _In_  REFIID riid);
        
        ULONG ( STDMETHODCALLTYPE *CountRefs )( 
            IRpcStubBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *DebugServerQueryInterface )( 
            IRpcStubBuffer * This,
            /* [annotation][out] */ 
            _Outptr_  void **ppv);
        
        void ( STDMETHODCALLTYPE *DebugServerRelease )( 
            IRpcStubBuffer * This,
            /* [annotation][in] */ 
            _In_  void *pv);
        
        END_INTERFACE
    } IRpcStubBufferVtbl;

    interface IRpcStubBuffer
    {
        CONST_VTBL struct IRpcStubBufferVtbl *lpVtbl;
    };



typedef interface IPSFactoryBuffer IPSFactoryBuffer;
  typedef struct IPSFactoryBufferVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IPSFactoryBuffer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IPSFactoryBuffer * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IPSFactoryBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *CreateProxy )( 
            IPSFactoryBuffer * This,
            /* [annotation][in] */ 
            _In_  IUnknown *pUnkOuter,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][out] */ 
            _Outptr_  IRpcProxyBuffer **ppProxy,
            /* [annotation][out] */ 
            _Outptr_  void **ppv);
        
        HRESULT ( STDMETHODCALLTYPE *CreateStub )( 
            IPSFactoryBuffer * This,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pUnkServer,
            /* [annotation][out] */ 
            _Outptr_  IRpcStubBuffer **ppStub);
        
        END_INTERFACE
    } IPSFactoryBufferVtbl;

    interface IPSFactoryBuffer
    {
        CONST_VTBL struct IPSFactoryBufferVtbl *lpVtbl;
    };



typedef __int64 OXID;
typedef __int64 OID;
typedef GUID	IPID;

typedef struct tagDUALSTRINGARRAY    {
    unsigned short wNumEntries;    
    unsigned short wSecurityOffset; 
    unsigned short aStringArray[ANYSIZE_ARRAY];
} DUALSTRINGARRAY;

typedef struct tagSTDOBJREF    {
    unsigned long  flags;              
    unsigned long  cPublicRefs;        
    OXID           oxid;               
    OID            oid;                
    IPID           ipid;               
} STDOBJREF;

typedef struct tagOBJREF    {
    unsigned long signature;           
    unsigned long flags;               
    GUID          iid;                 
    union        {
        struct            {
            STDOBJREF       std;       
            DUALSTRINGARRAY saResAddr; 
        } u_standard;    
        struct            {
            STDOBJREF       std;       
            CLSID           clsid;     
            DUALSTRINGARRAY saResAddr; 
        } u_handler;            
        struct            {
            CLSID           clsid;     
            unsigned long   cbExtension;
            unsigned long   size;      
            BYTE *pData; 
        } u_custom;        
    } u_objref;    
} OBJREF;
