#include <wintype.h>
#include <guiddef.h>


#ifndef __RPCDCEP_H__
#define __RPCDCEP_H__

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif


#pragma region Application Family or OneCore Family


typedef struct _RPC_VERSION {
    unsigned short MajorVersion;
    unsigned short MinorVersion;
} RPC_VERSION;

typedef struct _RPC_SYNTAX_IDENTIFIER {
    GUID SyntaxGUID;
    RPC_VERSION SyntaxVersion;
} RPC_SYNTAX_IDENTIFIER, __RPC_FAR * PRPC_SYNTAX_IDENTIFIER;

typedef struct _RPC_MESSAGE
{
    RPC_BINDING_HANDLE Handle;
    unsigned long DataRepresentation;
    void __RPC_FAR * Buffer;
    unsigned int BufferLength;
    unsigned int ProcNum;
    PRPC_SYNTAX_IDENTIFIER TransferSyntax;
    void __RPC_FAR * RpcInterfaceInformation;
    void __RPC_FAR * ReservedForRuntime;
    RPC_MGR_EPV __RPC_FAR * ManagerEpv;
    void __RPC_FAR * ImportContext;
    unsigned long RpcFlags;
} RPC_MESSAGE, __RPC_FAR * PRPC_MESSAGE;


#pragma endregion

#pragma region Desktop Family or OneCore Family


typedef RPC_STATUS
RPC_ENTRY RPC_FORWARD_FUNCTION(
                       IN UUID             __RPC_FAR * InterfaceId,
                       IN RPC_VERSION      __RPC_FAR * InterfaceVersion,
                       IN UUID             __RPC_FAR * ObjectId,
                       IN unsigned char         __RPC_FAR * Rpcpro,
                       IN void __RPC_FAR * __RPC_FAR * ppDestEndpoint);

enum RPC_ADDRESS_CHANGE_TYPE
{
    PROTOCOL_NOT_LOADED = 1,
    PROTOCOL_LOADED,
    PROTOCOL_ADDRESS_CHANGE
};

typedef void
RPC_ENTRY RPC_ADDRESS_CHANGE_FN(
                        IN void * arg
                        );


#pragma endregion

#pragma region Application Family or OneCore Family


#define RPC_CONTEXT_HANDLE_DEFAULT_GUARD    ((void *)(ULONG_PTR)0xFFFFF00D)

#define RPC_CONTEXT_HANDLE_DEFAULT_FLAGS    0x00000000UL
#define RPC_CONTEXT_HANDLE_FLAGS            0x30000000UL
#define RPC_CONTEXT_HANDLE_SERIALIZE        0x10000000UL
#define RPC_CONTEXT_HANDLE_DONT_SERIALIZE   0x20000000UL
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define RPC_TYPE_STRICT_CONTEXT_HANDLE      0x40000000UL
#endif 


#define RPC_NCA_FLAGS_DEFAULT       0x00000000  /* 0b000...000 */
#define RPC_NCA_FLAGS_IDEMPOTENT    0x00000001  /* 0b000...001 */
#define RPC_NCA_FLAGS_BROADCAST     0x00000002  /* 0b000...010 */
#define RPC_NCA_FLAGS_MAYBE         0x00000004  /* 0b000...100 */

#if (NTDDI_VERSION >= NTDDI_VISTA)
#define RPCFLG_HAS_GUARANTEE        0x00000010UL
#endif 

#define RPCFLG_WINRT_REMOTE_ASYNC   0x00000020UL


#define RPC_BUFFER_COMPLETE         0x00001000 /* used by pipes */
#define RPC_BUFFER_PARTIAL          0x00002000 /* used by pipes */
#define RPC_BUFFER_EXTRA            0x00004000 /* used by pipes */
#define RPC_BUFFER_ASYNC            0x00008000 /* used by async rpc */
#define RPC_BUFFER_NONOTIFY         0x00010000 /* used by async pipes */

#define RPCFLG_MESSAGE              0x01000000UL
#define RPCFLG_AUTO_COMPLETE        0x08000000UL
#define RPCFLG_LOCAL_CALL           0x10000000UL
#define RPCFLG_INPUT_SYNCHRONOUS    0x20000000UL
#define RPCFLG_ASYNCHRONOUS         0x40000000UL
#define RPCFLG_NON_NDR              0x80000000UL

#if (NTDDI_VERSION >= NTDDI_WINXP)
#define RPCFLG_HAS_MULTI_SYNTAXES   0x02000000UL
#define RPCFLG_HAS_CALLBACK         0x04000000UL
#endif 

#if (NTDDI_VERSION >= NTDDI_VISTA)
#define RPCFLG_ACCESSIBILITY_BIT1   0x00100000UL
#define RPCFLG_ACCESSIBILITY_BIT2   0x00200000UL
#define RPCFLG_ACCESS_LOCAL         0x00400000UL

#define NDR_CUSTOM_OR_DEFAULT_ALLOCATOR 0x10000000UL
#define NDR_DEFAULT_ALLOCATOR           0x20000000UL
#endif 

#if (NTDDI_VERSION >= NTDDI_WIN8)
#define RPCFLG_NDR64_CONTAINS_ARM_LAYOUT 0x04000000UL
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)


#define RPCFLG_SENDER_WAITING_FOR_REPLY 0x00800000UL 

#endif 

#define RPC_FLAGS_VALID_BIT 0x00008000

typedef void *RPC_DISPATCH_FUNCTION;
typedef struct {
    unsigned int DispatchTableCount;
    RPC_DISPATCH_FUNCTION __RPC_FAR * DispatchTable;
    LONG_PTR                          Reserved;
} RPC_DISPATCH_TABLE, __RPC_FAR * PRPC_DISPATCH_TABLE;

typedef struct _RPC_PROTSEQ_ENDPOINT
{
    unsigned char __RPC_FAR * RpcProtocolSequence;
    unsigned char __RPC_FAR * Endpoint;
} RPC_PROTSEQ_ENDPOINT, __RPC_FAR * PRPC_PROTSEQ_ENDPOINT;


#define NT351_INTERFACE_SIZE 0x40
#define RPC_INTERFACE_HAS_PIPES           0x0001

typedef struct _RPC_SERVER_INTERFACE
{
    unsigned int Length;
    RPC_SYNTAX_IDENTIFIER InterfaceId;
    RPC_SYNTAX_IDENTIFIER TransferSyntax;
    PRPC_DISPATCH_TABLE DispatchTable;
    unsigned int RpcProtseqEndpointCount;
    PRPC_PROTSEQ_ENDPOINT RpcProtseqEndpoint;
    RPC_MGR_EPV __RPC_FAR *DefaultManagerEpv;
    void const __RPC_FAR *InterpreterInfo;
    unsigned int Flags ;
} RPC_SERVER_INTERFACE, __RPC_FAR * PRPC_SERVER_INTERFACE;

typedef struct _RPC_CLIENT_INTERFACE
{
    unsigned int Length;
    RPC_SYNTAX_IDENTIFIER   InterfaceId;
    RPC_SYNTAX_IDENTIFIER   TransferSyntax;
    PRPC_DISPATCH_TABLE     DispatchTable;
    unsigned int            RpcProtseqEndpointCount;
    PRPC_PROTSEQ_ENDPOINT   RpcProtseqEndpoint;
    ULONG_PTR               Reserved;
    void const __RPC_FAR *  InterpreterInfo;
    unsigned int Flags ;
} RPC_CLIENT_INTERFACE, __RPC_FAR * PRPC_CLIENT_INTERFACE;


#pragma endregion


#endif 
