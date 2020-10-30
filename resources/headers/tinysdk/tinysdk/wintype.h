//https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types
#define APIENTRY WINAPI
#define CONST const
#define CALLBACK __stdcall
#define WINAPI __stdcall
#define far
#define MAX_PATH          260

#if defined(_WIN64)
 typedef unsigned __int64 ULONG_PTR;
#else
 typedef unsigned long ULONG_PTR;
#endif

typedef unsigned short WORD;
typedef WORD ATOM;
typedef int BOOL;
typedef long NTSTATUS;
typedef unsigned char BYTE;
typedef BYTE BOOLEAN;
typedef unsigned long DWORD;
typedef char CCHAR;
typedef char CHAR;
typedef DWORD COLORREF;
typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef signed __int64 INT64;
typedef unsigned short wchar_t; // may cause problem
typedef wchar_t WCHAR;
typedef WORD LANGID;
typedef DWORD LCID;
typedef DWORD LCTYPE;
typedef DWORD LGRPID;
typedef long LONG;
typedef short SHORT;
typedef unsigned __int64 DWORDLONG;
typedef ULONG_PTR DWORD_PTR;
typedef unsigned int DWORD32;
typedef unsigned __int64 DWORD64;
typedef float FLOAT;
typedef void *PVOID;
typedef PVOID HANDLE;
typedef HANDLE HACCEL;
typedef unsigned char UCHAR;
typedef unsigned __int64 ULONG64;
typedef unsigned short USHORT;

#ifdef _WIN64
 typedef int HALF_PTR;
#else
 typedef short HALF_PTR;
#endif

#ifdef _WIN64
 typedef unsigned int UHALF_PTR;
#else
 typedef unsigned short UHALF_PTR;
#endif

typedef HANDLE HICON;
typedef HANDLE HBITMAP;
typedef HANDLE HBRUSH;
typedef HANDLE HCOLORSPACE;
typedef HANDLE HCONV;
typedef HANDLE HCONVLIST;
typedef HICON HCURSOR;
typedef HANDLE HDC;
typedef HANDLE HDDEDATA;
typedef HANDLE HDESK;
typedef HANDLE HDROP;
typedef HANDLE HDWP;
typedef HANDLE HENHMETAFILE;
typedef int HFILE;
typedef HANDLE HFONT;
typedef HANDLE HGDIOBJ;
typedef HANDLE HGLOBAL;
typedef HANDLE HHOOK;
typedef HANDLE HINSTANCE;
typedef HANDLE HKEY;
typedef HANDLE HKL;
typedef HANDLE HLOCAL;
typedef HANDLE HMENU;
typedef HANDLE HMETAFILE;
typedef HINSTANCE HMODULE;
typedef HANDLE HMONITOR;
typedef HANDLE HPALETTE;
typedef HANDLE HPEN;
typedef LONG HRESULT;
typedef HANDLE HRGN;
typedef HANDLE HRSRC;
typedef HANDLE HSZ;
typedef HANDLE WINSTA;
typedef HANDLE HWND;
typedef int INT;


#ifdef UNICODE
 typedef WCHAR TBYTE;
#else
 typedef unsigned char TBYTE;
#endif


#if defined(_WIN64)
 typedef __int64 INT_PTR;
#else
 typedef int INT_PTR;
#endif


#if !defined(_M_IX86)
 typedef __int64 LONGLONG;
#else
 typedef double LONGLONG;
#endif

#if defined(_WIN64)
 typedef __int64 LONG_PTR;
#else
 typedef long LONG_PTR;
#endif

#ifdef UNICODE
 typedef WCHAR TCHAR;
#else
 typedef char TCHAR;
#endif

typedef signed int LONG32;
typedef __int64 LONG64;
typedef LONG_PTR LPARAM;
typedef BOOL far* LPBOOL;
typedef BYTE far * LPBYTE;
typedef DWORD *LPCOLORREF;
typedef CONST CHAR *LPCSTR;

#ifdef UNICODE
 typedef LPCWSTR LPCTSTR;
#else
 typedef LPCSTR LPCTSTR;
#endif

typedef CONST void *LPCVOID;
typedef CONST WCHAR *LPCWSTR;
typedef DWORD *LPDWORD;
typedef HANDLE *LPHANDLE;
typedef int *LPINT;
typedef long *LPLONG;
typedef CHAR *LPSTR;
typedef LONG_PTR SSIZE_T;
typedef LONG NTSTATUS;


#ifdef UNICODE
 typedef LPWSTR LPTSTR;
#else
 typedef LPSTR LPTSTR;
#endif

typedef void *LPVOID;
typedef WORD *LPWORD;
typedef WCHAR *LPWSTR;
typedef LONG_PTR LRESULT;
typedef ULONG_PTR SIZE_T;
typedef BOOL *PBOOL;
typedef BOOLEAN *PBOOLEAN;
typedef BYTE *PBYTE;
typedef CHAR *PCHAR;
typedef CONST CHAR *PCSTR;

#ifdef UNICODE
 typedef LPCWSTR PCTSTR;
#else
 typedef LPCSTR PCTSTR;
#endif

typedef CONST WCHAR *PCWSTR;
typedef DWORD *PDWORD;
typedef DWORDLONG *PDWORDLONG;
typedef DWORD_PTR *PDWORD_PTR;
typedef DWORD32 *PDWORD32;
typedef DWORD64 *PDWORD64;
typedef FLOAT *PFLOAT;

#ifdef _WIN64
 typedef HALF_PTR *PHALF_PTR;
#else
 typedef HALF_PTR *PHALF_PTR;
#endif

typedef HANDLE *PHANDLE;
typedef HKEY *PHKEY;
typedef int *PINT;
typedef INT_PTR *PINT_PTR;
typedef INT8 *PINT8;
typedef INT16 *PINT16;
typedef INT32 *PINT32;
typedef INT64 *PINT64;
typedef PDWORD PLCID;
typedef LONG *PLONG;
typedef LONG *PLONG;
typedef LONGLONG *PLONGLONG;
typedef LONG32 *PLONG32;
typedef LONG64 *PLONG64;

#if defined(_WIN64)
#define POINTER_32 __ptr32
#else
#define POINTER_32
#endif

#if (_MSC_VER >= 1300)
#define POINTER_64 __ptr64
#else
#define POINTER_64
#endif

#define POINTER_SIGNED __sptr
#define POINTER_UNSIGNED __uptr
typedef SHORT *PSHORT;
typedef SIZE_T *PSIZE_T;
typedef SSIZE_T *PSSIZE_T;
typedef CHAR *PSTR;
typedef TBYTE *PTBYTE;
typedef TCHAR *PTCHAR;

#ifdef UNICODE
 typedef LPWSTR PTSTR;
#else
  typedef LPSTR PTSTR;
#endif

typedef UCHAR *PUCHAR;

#ifdef _WIN64
 typedef UHALF_PTR *PUHALF_PTR;
#else
 typedef UHALF_PTR *PUHALF_PTR;
#endif

#if defined(_WIN64)
 typedef unsigned __int64 UINT_PTR;
#else
 typedef unsigned int UINT_PTR;
#endif


#if defined(_WIN32) || defined(_MPPC_)

// Win32 doesn't support __export

#ifdef _68K_
#define STDMETHODCALLTYPE       __cdecl
#else
#define STDMETHODCALLTYPE       __stdcall
#endif
#define STDMETHODVCALLTYPE      __cdecl

#define STDAPICALLTYPE          __stdcall
#define STDAPIVCALLTYPE         __cdecl

#else

#define STDMETHODCALLTYPE       __export __stdcall
#define STDMETHODVCALLTYPE      __export __cdecl

#define STDAPICALLTYPE          __export __stdcall
#define STDAPIVCALLTYPE         __export __cdecl

#endif

typedef unsigned char UINT8;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned __int64 UINT64;

typedef unsigned long ULONG;

#if !defined(_M_IX86)
 typedef unsigned __int64 ULONGLONG;
#else
 typedef double ULONGLONG;
#endif

typedef unsigned int ULONG32;

typedef unsigned int UINT;
typedef UINT *PUINT;
typedef UINT_PTR *PUINT_PTR;
typedef UINT8 *PUINT8;
typedef UINT16 *PUINT16;
typedef UINT32 *PUINT32;
typedef UINT64 *PUINT64;
typedef ULONG *PULONG;
typedef ULONGLONG *PULONGLONG;
typedef ULONG_PTR *PULONG_PTR;
typedef ULONG32 *PULONG32;
typedef ULONG64 *PULONG64;
typedef USHORT *PUSHORT;
typedef WCHAR *PWCHAR;
typedef WORD *PWORD;
typedef WCHAR *PWSTR;
typedef unsigned __int64 QWORD;
typedef HANDLE SC_HANDLE;
typedef LPVOID SC_LOCK;
typedef HANDLE SERVICE_STATUS_HANDLE;

typedef WCHAR OLECHAR;

typedef   OLECHAR *LPOLESTR;
typedef  const OLECHAR *LPCOLESTR;
typedef  OLECHAR *BSTR;


typedef struct _UNICODE_STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef LONGLONG USN;
#define VOID void
typedef UINT_PTR WPARAM;
