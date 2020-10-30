#include <tinysdk/wintype.h>
#include <tinysdk/winnt.h>

#define _Out_
#define _In_opt_
#define _Inout_
#define _Out_opt_
#define _In_
#define _Inout_opt_
#define _Reserved_

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef short CSHORT;
#if !defined(_M_IX86)
 typedef __int64 LONGLONG;
  typedef unsigned __int64 ULONGLONG;
#else
 typedef double LONGLONG;
  typedef double ULONGLONG;
#endif

/*
typedef union _LARGE_INTEGER {
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } u;
  LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
*/

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CLIENT_ID32
{
    ULONG UniqueProcess;
    ULONG UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _CLIENT_ID64
{
    ULONGLONG UniqueProcess;
    ULONGLONG UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

// from thread
typedef struct _RTL_SRWLOCK {
        PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;
typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;

void RtlInitUnicodeString(
  PUNICODE_STRING DestinationString,
  PCWSTR          SourceString
);