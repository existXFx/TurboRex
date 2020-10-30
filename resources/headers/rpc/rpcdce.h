#ifndef __RPCDCE_H__
#define __RPCDCE_H__

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif


#pragma region Application Family or OneCore Family

#define RPC_C_PARM_MAX_PACKET_LENGTH    1
#define RPC_C_PARM_BUFFER_LENGTH        2

#define RPC_IF_AUTOLISTEN                   0x0001
#define RPC_IF_OLE                          0x0002
#define RPC_IF_ALLOW_UNKNOWN_AUTHORITY      0x0004
#define RPC_IF_ALLOW_SECURE_ONLY            0x0008
#define RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH 0x0010
#define RPC_IF_ALLOW_LOCAL_ONLY             0x0020
#define RPC_IF_SEC_NO_CACHE                 0x0040
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define RPC_IF_SEC_CACHE_PER_PROC           0x0080
#define RPC_IF_ASYNC_CALLBACK               0x0100
#endif // (NTDDI_VERSION >= NTDDI_VISTA)

#if (NTDDI_VERSION >= NTDDI_VISTA)
#define RPC_FW_IF_FLAG_DCOM                 0x0001
#endif // (NTDDI_VERSION >= NTDDI_VISTA)

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

#ifndef DECLSPEC_NORETURN
#if (_MSC_VER >= 1200) && !defined(MIDL_PASS)
#define DECLSPEC_NORETURN   __declspec(noreturn)
#else
#define DECLSPEC_NORETURN
#endif
#endif


typedef unsigned char __RPC_FAR * RPC_CSTR;

#if defined(RPC_USE_NATIVE_WCHAR) && defined(_NATIVE_WCHAR_T_DEFINED)
typedef wchar_t __RPC_FAR * RPC_WSTR;
typedef const wchar_t * RPC_CWSTR;
#else
typedef unsigned short __RPC_FAR * RPC_WSTR;
typedef const unsigned short * RPC_CWSTR;
#endif

typedef I_RPC_HANDLE RPC_BINDING_HANDLE;
typedef RPC_BINDING_HANDLE handle_t;
#define rpc_binding_handle_t RPC_BINDING_HANDLE

#ifndef GUID_DEFINED
#include <guiddef.h>
#endif /* GUID_DEFINED */

#ifndef UUID_DEFINED
#define UUID_DEFINED
typedef GUID UUID;
#ifndef uuid_t
#define uuid_t UUID
#endif
#endif


#pragma endregion

#pragma region Desktop Family or OneCore Family


#ifndef rpc_binding_vector_t
#define rpc_binding_vector_t RPC_BINDING_VECTOR
#endif

#ifndef uuid_vector_t
#define uuid_vector_t UUID_VECTOR
#endif


#pragma endregion

#pragma region Application Family or OneCore Family

typedef void __RPC_FAR * RPC_IF_HANDLE;

#ifndef IFID_DEFINED
#define IFID_DEFINED
typedef struct _RPC_IF_ID
{
    UUID Uuid;
    unsigned short VersMajor;
    unsigned short VersMinor;
} RPC_IF_ID;
#endif



#pragma endregion

#pragma region Desktop Family or OneCore Family


#define RPC_C_BINDING_INFINITE_TIMEOUT 10
#define RPC_C_BINDING_MIN_TIMEOUT 0
#define RPC_C_BINDING_DEFAULT_TIMEOUT 5
#define RPC_C_BINDING_MAX_TIMEOUT 9

#define RPC_C_CANCEL_INFINITE_TIMEOUT -1

#define RPC_C_LISTEN_MAX_CALLS_DEFAULT 1234
#define RPC_C_PROTSEQ_MAX_REQS_DEFAULT 10

#define RPC_C_BIND_TO_ALL_NICS          1
#define RPC_C_USE_INTERNET_PORT         0x1
#define RPC_C_USE_INTRANET_PORT         0x2
#define RPC_C_DONT_FAIL                 0x4
#define RPC_C_RPCHTTP_USE_LOAD_BALANCE  0x8

#if (NTDDI_VERSION < NTDDI_VISTA)
#define RPC_C_MQ_TEMPORARY                  0x0000
#define RPC_C_MQ_PERMANENT                  0x0001
#define RPC_C_MQ_CLEAR_ON_OPEN              0x0002
#define RPC_C_MQ_USE_EXISTING_SECURITY      0x0004
#define RPC_C_MQ_AUTHN_LEVEL_NONE           0x0000
#define RPC_C_MQ_AUTHN_LEVEL_PKT_INTEGRITY  0x0008
#define RPC_C_MQ_AUTHN_LEVEL_PKT_PRIVACY    0x0010

#define RPC_C_MQ_EXPRESS                0  
#define RPC_C_MQ_RECOVERABLE            1

#define RPC_C_MQ_JOURNAL_NONE           0  
#define RPC_C_MQ_JOURNAL_DEADLETTER     1
#define RPC_C_MQ_JOURNAL_ALWAYS         2


#define RPC_C_OPT_MQ_DELIVERY            1
#define RPC_C_OPT_MQ_PRIORITY            2
#define RPC_C_OPT_MQ_JOURNAL             3
#define RPC_C_OPT_MQ_ACKNOWLEDGE         4
#define RPC_C_OPT_MQ_AUTHN_SERVICE       5
#define RPC_C_OPT_MQ_AUTHN_LEVEL         6
#define RPC_C_OPT_MQ_TIME_TO_REACH_QUEUE 7
#define RPC_C_OPT_MQ_TIME_TO_BE_RECEIVED 8
#endif 

#define RPC_C_OPT_BINDING_NONCAUSAL      9
#define RPC_C_OPT_SECURITY_CALLBACK      10
#define RPC_C_OPT_UNIQUE_BINDING         11

#if (NTDDI_VERSION <= NTDDI_WIN2K)
#define RPC_C_OPT_MAX_OPTIONS            12

#elif (NTDDI_VERSION <= NTDDI_WS03)
#define RPC_C_OPT_CALL_TIMEOUT           12
#define RPC_C_OPT_DONT_LINGER            13
#define RPC_C_OPT_MAX_OPTIONS            14

#else
#define RPC_C_OPT_TRANS_SEND_BUFFER_SIZE 5
#define RPC_C_OPT_CALL_TIMEOUT           12
#define RPC_C_OPT_DONT_LINGER            13
#define RPC_C_OPT_TRUST_PEER             14
#define RPC_C_OPT_ASYNC_BLOCK            15
#define RPC_C_OPT_OPTIMIZE_TIME          16
#define RPC_C_OPT_MAX_OPTIONS            17

#endif 

#define RPC_C_FULL_CERT_CHAIN 0x0001



#ifdef RPC_UNICODE_SUPPORTED
typedef struct _RPC_PROTSEQ_VECTORA
{
    unsigned int Count;
    unsigned char __RPC_FAR * Protseq[1];
} RPC_PROTSEQ_VECTORA;

typedef struct _RPC_PROTSEQ_VECTORW
{
    unsigned int Count;
    unsigned short __RPC_FAR * Protseq[1];
} RPC_PROTSEQ_VECTORW;

#ifdef UNICODE
#define RPC_PROTSEQ_VECTOR RPC_PROTSEQ_VECTORW
#else /* UNICODE */
#define RPC_PROTSEQ_VECTOR RPC_PROTSEQ_VECTORA
#endif /* UNICODE */

#else 

typedef struct _RPC_PROTSEQ_VECTOR
{
    unsigned int Count;
    unsigned char __RPC_FAR * Protseq[1];
} RPC_PROTSEQ_VECTOR;

#endif 
typedef struct _RPC_POLICY {
    unsigned int Length ;
    unsigned long EndpointFlags ;
    unsigned long NICFlags ;
    } RPC_POLICY,  __RPC_FAR *PRPC_POLICY ;

#pragma endregion

#pragma region Application Family or OneCore Family


#define RPC_MGR_EPV void

typedef struct
{
    unsigned int Count;
    unsigned long Stats[1];
} RPC_STATS_VECTOR;

#define RPC_C_STATS_CALLS_IN 0
#define RPC_C_STATS_CALLS_OUT 1
#define RPC_C_STATS_PKTS_IN 2
#define RPC_C_STATS_PKTS_OUT 3

typedef struct
{
  unsigned long Count;
  RPC_IF_ID __RPC_FAR * IfId[1];
} RPC_IF_ID_VECTOR;

#define _In_

typedef RPC_STATUS RPC_ENTRY
RPC_IF_CALLBACK_FN (
    _In_ RPC_IF_HANDLE  InterfaceUuid,
    _In_ void *Context
    ) ;

typedef struct _UUID_VECTOR
{
  unsigned long Count;
  UUID *Uuid[1];
} UUID_VECTOR;
#include <rpcdcep.h>

#ifdef __cplusplus
}
#endif

#endif 
