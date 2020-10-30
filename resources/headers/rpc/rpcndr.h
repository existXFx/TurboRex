#include <rpcdcep.h>
typedef struct _COMM_FAULT_OFFSETS
    {
    short       CommOffset;
    short       FaultOffset;
    } COMM_FAULT_OFFSETS;

typedef const unsigned char  * PFORMAT_STRING;

typedef struct _MIDL_METHOD_PROPERTY
{
    unsigned long                       Id;
    ULONG_PTR                           Value;
} MIDL_METHOD_PROPERTY, *PMIDL_METHOD_PROPERTY;

typedef struct _MIDL_METHOD_PROPERTY_MAP
{
    unsigned long                       Count;
    const MIDL_METHOD_PROPERTY         *Properties;
} MIDL_METHOD_PROPERTY_MAP, *PMIDL_METHOD_PROPERTY_MAP;

typedef struct _MIDL_INTERFACE_METHOD_PROPERTIES
{
    unsigned short MethodCount;
    const MIDL_METHOD_PROPERTY_MAP* const *MethodProperties;
} MIDL_INTERFACE_METHOD_PROPERTIES;

typedef struct _MIDL_SYNTAX_INFO
{
RPC_SYNTAX_IDENTIFIER               TransferSyntax;
RPC_DISPATCH_TABLE *                DispatchTable;
PFORMAT_STRING                      ProcString;
const unsigned short *              FmtStringOffset;
PFORMAT_STRING                      TypeString;
const void           *              aUserMarshalQuadruple;
const MIDL_INTERFACE_METHOD_PROPERTIES *pMethodProperties;
ULONG_PTR                           pReserved2;
} MIDL_SYNTAX_INFO, *PMIDL_SYNTAX_INFO;

