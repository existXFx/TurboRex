#include "wintype.h"
#pragma pack(push, 1)

typedef struct
{
    unsigned short MustSize : 1;
    unsigned short MustFree : 1; 
    unsigned short IsPipe : 1; 
    unsigned short IsIn : 1;
    unsigned short IsOut : 1;
    unsigned short IsReturn : 1;
    unsigned short IsBasetype : 1; 
    unsigned short IsByValue : 1; 
    unsigned short IsSimpleRef : 1; 
    unsigned short IsDontCallFreeInst : 1; 
    unsigned short SaveForAsyncFinish : 1;
    unsigned short Unused : 2;
    unsigned short ServerAllocSize : 3; 
} PARAM_ATTRIBUTES;
typedef struct _INTERPRETER_OPT_FLAGS
{
    unsigned char ServerMustSize : 1; 
    unsigned char ClientMustSize : 1;
    unsigned char HasReturn : 1; 
    unsigned char HasPipes : 1;
    unsigned char Unused : 1;
    unsigned char HasAsyncUuid : 1; 
    unsigned char HasExtensions : 1; 
    unsigned char HasAsyncHandle : 1; 
} INTERPRETER_OPT_FLAGS, *PINTERPRETER_OPT_FLAGS;

typedef struct _INTERPRETER_OPT_FLAGS2
{
    unsigned char HasNewCorrDesc : 1; 
    unsigned char ClientCorrCheck : 1; 
    unsigned char ServerCorrCheck : 1; 
    unsigned char HasNotify : 1; 
    unsigned char HasNotify2 : 1; 
    unsigned char Unused : 3; 
} INTERPRETER_OPT_FLAGS2, *PINTERPRETER_OPT_FLAGS2;


typedef struct _Oi_Header_HType_Flags_t
{
  BYTE HandleType;
  BYTE OiFlags;
} Oi_Header_HType_Flags_t;

typedef struct _ProcNum_StackSize_t
{
    WORD ProcNum;
    SHORT StackSize;
}ProcNum_StackSize_t;

typedef struct _Handle_Desc_Common_t
{
    unsigned char HandleType;
    union {
        unsigned char Flag;
        unsigned char FlagAndSize;
    };
    SHORT Offset;
}Handle_Desc_Common_t;

typedef struct _ExplicitHandlePrimitive_t
{
    Handle_Desc_Common_t Common;
} ExplicitHandlePrimitive_t;
typedef struct _ExplicitHandleGeneric_t
{
    Handle_Desc_Common_t Common;
    unsigned char BindingRoutinePairIndex;
    unsigned char PAD;
} ExplicitHandleGeneric_t;

typedef struct _ExplicitHandleContext_t
{
    Handle_Desc_Common_t Common;
	unsigned char	ContextRundownRoutineIndex;
	unsigned char	ParamNum;
} ExplicitHandleContext_t;

typedef struct _Oi_Header_t
{
    Oi_Header_HType_Flags_t part1;
    DWORD rpc_flags;
    ProcNum_StackSize_t part2;
} Oi_Header_t;

typedef struct _Oi_Header_Without_RPCFlags_t
{
    Oi_Header_HType_Flags_t part1;
    ProcNum_StackSize_t part2;
} Oi_Header_Without_RPCFlags_t;


typedef struct _Oif_Header_t
{
    SHORT ConstantClientBufferSize;
    SHORT ConstantServerBufferSize;
    INTERPRETER_OPT_FLAGS InterpreterOptFlags;
    unsigned char NumberOfParams;
} Oif_Header_t;

typedef struct _WIN2K_EXT
{
    unsigned char ExtensionVersion; 
    INTERPRETER_OPT_FLAGS2 Flags2;
    unsigned short ClientCorrHint;
    unsigned short ServerCorrHint;
    unsigned short NotifyIndex;
} WIN2K_EXT;

typedef struct _WIN2K_EXT64
{
    unsigned char ExtensionVersion;
    INTERPRETER_OPT_FLAGS2 Flags2;
    unsigned short ClientCorrHint;
    unsigned short ServerCorrHint;
    unsigned short NotifyIndex;
    unsigned short FloatDoubleMask;
} WIN2K_EXT64;

typedef struct _Oi_Param_Desc_BaseType_t
{
    unsigned char ParamBaseType;
    unsigned char SimpleType;
} Oi_Param_Desc_Simple_t;

typedef struct _Oi_Param_Desc_Other_t
{
    unsigned char ParamDirection;
    unsigned char StackSize;
    SHORT TypeOffset;
} Oi_Param_Desc_Other_t;

typedef struct _Oif_ParamDesc_Header_t
{
    PARAM_ATTRIBUTES ParamAttributes;
    SHORT StackOffset;
} Oif_ParamDesc_Header_t;

typedef struct _Oif_Param_Desc_BaseType_t
{
    Oif_ParamDesc_Header_t Header;
    unsigned char TypeFormatChar;
    unsigned char Unused;
} Oif_Param_Desc_BaseType_t;

typedef struct _Oif_Param_Desc_Other_t
{
    Oif_ParamDesc_Header_t Header;
    SHORT TypeOffset;
} Oif_Param_Desc_Other_t;

/* Type Format String */
typedef struct _CommonPtr_Header_t
{
    unsigned char PointerType;
    unsigned char PointerAttributes;
} CommonPtr_Header_t;
typedef struct _CommonPtr_Simple_t
{
    CommonPtr_Header_t Header;
    unsigned char SimpleType;
    unsigned char Pad;
} CommonPtr_Simple_t;

typedef struct _CommonPtr_Complex_t
{
    CommonPtr_Header_t Header;
    SHORT Offset;
} CommonPtr_Complex_t;

/* Array */
typedef struct _SM_FArray_Header_t
{
    unsigned char Type;
    unsigned char Alignment;
    SHORT TotalSize;
}SM_FArray_Header_t;

typedef struct _LG_FArray_Header_t
{
    unsigned char Type;
    unsigned char Alignment;
    INT32 TotalSize;
}LG_FArray_Header_t;

typedef struct _Conformant_Array_Header_t
{
    unsigned char Type;
    unsigned char Alignment;
    INT32 ElementSize;
}Conformant_Array_Header_t;

typedef Conformant_Array_Header_t Conformant_Varying_Array_Header_t;

typedef struct _SM_VArray_Header_t
{
    unsigned char Type;
    unsigned char Alignment;
    SHORT TotalSize;
    SHORT NumberElements;
    SHORT ElementSize;
}SM_VArray_Header_t;

typedef struct _LG_VArray_Header_t
{  
    unsigned char Type;
    unsigned char Alignment;
    INT32 TotalSize;
    INT32 NumberElements;
    SHORT ElementSize;
    INT32 VarianceDescription;
}LG_VArray_Header_t;

typedef struct _ComplexArray_Header_t
{
    unsigned char Type;
    unsigned char Alignment;
    SHORT NumberElements;
}ComplexArray_Header_t;


/* Pointer Layout */
typedef struct _Pointer_Instance_t
{
    SHORT PtrOffsetInMem;
    SHORT PtrOffsetInBuf;
    union {
        CommonPtr_Simple_t Simple;
        CommonPtr_Complex_t Complex;
    } PtrDesc;
}Pointer_Instance_t;

typedef struct _No_Repeat_Layout_t
{
    unsigned char Type;
    unsigned char Pad;
    Pointer_Instance_t PtrInstance;
}No_Repeat_Layout_t;

typedef struct _Fixed_Repeat_Layout_Header_t
{
    unsigned char Type;
    unsigned char Pad;
    SHORT Iterations;
    SHORT Increment;
    SHORT OffsetToArray;
    SHORT NumberOfPointers;
} Fixed_Repeat_Layout_Header_t;

typedef struct _Variable_Repeat_Layout_Header_t
{
    unsigned char Type;
    unsigned char OffsetType;
    SHORT Increment;
    SHORT OffsetToArray;
    SHORT NumberOfPointers;
} Variable_Repeat_Layout_Header_t;
#pragma pack(pop)