# frozen_string_literal: true

module TurboRex
  module MSRPC
    module NDRType
      # https://github.com/wine-mirror/wine/tree/master/tools/widl
      # https://docs.microsoft.com/en-us/windows/win32/midl/midl-data-types
      # https://github.com/wine-mirror/wine/blob/master/include/ndrtypes.h

      # FC Base Type
      FC_ZERO = 0x0
      FC_BYTE = 0x1
      FC_CHAR = 0x2
      FC_SMALL = 0x3
      FC_USMALL = 0x4
      FC_WCHAR = 0x5
      FC_SHORT = 0x6
      FC_USHORT = 0x7
      FC_LONG = 0x8
      FC_ULONG = 0x9
      FC_FLOAT = 0xA
      FC_HYPER = 0xB
      FC_DOUBLE = 0xC
      FC_ENUM16 = 0xD
      FC_ENUM32 = 0xE
      FC_IGNORE = 0xF
      FC_ERROR_STATUS_T = 0x10

      FC_RP = 0x11
      FC_UP = 0x12
      FC_OP = 0x13
      FC_FP = 0x14
      FC_STRUCT = 0x15
      FC_PSTRUCT = 0x16
      FC_CSTRUCT = 0x17
      FC_CPSTRUCT = 0x18
      FC_CVSTRUCT = 0x19
      FC_BOGUS_STRUCT = 0x1A
      FC_CARRAY = 0x1B
      FC_CVARRAY = 0x1C
      FC_SMFARRAY = 0x1D
      FC_LGFARRAY = 0x1E
      FC_SMVARRAY = 0x1F
      FC_LGVARRAY = 0x20
      FC_BOGUS_ARRAY = 0x21
      FC_C_CSTRING = 0x22
      FC_C_BSTRING = 0x23
      FC_C_SSTRING = 0x24
      FC_C_WSTRING = 0x25
      FC_CSTRING = 0x26
      FC_BSTRING = 0x27
      FC_SSTRING = 0x28
      FC_WSTRING = 0x29
      FC_ENCAPSULATED_UNION = 0x2A
      FC_NON_ENCAPSULATED_UNION = 0x2B
      FC_BYTE_COUNT_POINTER = 0x2C
      FC_TRANSMIT_AS = 0x2D
      FC_REPRESENT_AS = 0x2E
      FC_IP = 0x2F
      FC_EXPLICIT_HANDLE = 0x00
      FC_BIND_CONTEXT = 0x30
      FC_BIND_GENERIC = 0x31
      FC_BIND_PRIMITIVE = 0x32
      FC_AUTO_HANDLE = 0x33
      FC_CALLBACK_HANDLE = 0x34
      FC_UNUSED1 = 0x35
      FC_POINTER = 0x36
      FC_ALIGNM2 = 0x37
      FC_ALIGNM4 = 0x38
      FC_ALIGNM8 = 0x39
      FC_UNUSED2 = 0x3A
      FC_UNUSED3 = 0x3B
      FC_UNUSED4 = 0x3C
      FC_STRUCTPAD1 = 0x3D
      FC_STRUCTPAD2 = 0x3E
      FC_STRUCTPAD3 = 0x3F
      FC_STRUCTPAD4 = 0x40
      FC_STRUCTPAD5 = 0x41
      FC_STRUCTPAD6 = 0x42
      FC_STRUCTPAD7 = 0x43
      FC_STRING_SIZED = 0x44
      FC_UNUSED5 = 0x45
      FC_NO_REPEAT = 0x46
      FC_FIXED_REPEAT = 0x47
      FC_VARIABLE_REPEAT = 0x48
      FC_FIXED_OFFSET = 0x49
      FC_VARIABLE_OFFSET = 0x4A
      FC_PP = 0x4B
      FC_EMBEDDED_COMPLEX = 0x4C
      FC_IN_PARAM = 0x4D
      FC_IN_PARAM_BASETYPE = 0x4E
      FC_IN_PARAM_NO_FREE_INST = 0x4F
      FC_IN_OUT_PARAM = 0x50
      FC_OUT_PARAM = 0x51
      FC_RETURN_PARAM = 0x52
      FC_RETURN_PARAM_BASETYPE = 0x53
      FC_DEREFERENCE = 0x54
      FC_DIV_2 = 0x55
      FC_MULT_2 = 0x56
      FC_ADD_1 = 0x57
      FC_SUB_1 = 0x58
      FC_CALLBACK = 0x59
      FC_CONSTANT_IID = 0x5A
      FC_END = 0x5B
      FC_PAD = 0x5C
      FC_EXPR = 0x5D
      FC_SPLIT_DEREFERENCE = 0x74
      FC_SPLIT_DIV_2 = 0x75
      FC_SPLIT_MULT_2 = 0x76
      FC_SPLIT_ADD_1 = 0x77
      FC_SPLIT_SUB_1 = 0x78
      FC_SPLIT_CALLBACK = 0x79
      FC_HARD_STRUCT = 0xB1
      FC_TRANSMIT_AS_PTR = 0xB2
      FC_REPRESENT_AS_PTR = 0xB3
      FC_USER_MARSHAL = 0xB4
      FC_PIPE = 0xB5
      FC_BLKHOLE = 0xB6
      FC_RANGE = 0xB7
      FC_INT3264 = 0xB8 # base type
      FC_UINT3264 = 0xB9 # base type
      FC_END_OF_UNIVERSE = 0xBA

      # The Oi flags
      Oi_FULL_PTR_USED = 0x01
      Oi_RPCSS_ALLOC_USED = 0x02
      Oi_OBJECT_PROC = 0x04
      Oi_HAS_RPCFLAGS = 0x08
      Oi_overloaded1 =  0x10
      Oi_overloaded2 = 0x20
      Oi_USE_NEW_INIT_ROUTINES = 0x40
      Oi_Unused = 0x80

      # Overloaded Oi flags
      ENCODE_IS_USED = 0x10
      DECODE_IS_USED = 0x20
      Oi_IGNORE_OBJECT_EXCEPTION_HANDLING = 0x10
      Oi_HAS_COMM_OR_FAULT = 0x20
      Oi_OBJ_USE_V2_INTERPRETER = 0x20

      # Interpreter opt flags
      module InterpreterOptFlags
        ServerMustSize = 0x01
        ClientMustSize = 0x02
        HasReturn = 0x04
        HasPipes = 0x08
        Unused = 0x10
        HasAsyncUuid = 0x20
        HasExtensions = 0x40
        HasAsyncHandle = 0x80
      end

      module InterpreterOptFlags2
        HasNewCorrDesc = 0x01
        ClientCorrCheck = 0x02
        ServerCorrCheck = 0x04
        HasNotify = 0x08
        HasNotify2 =  0x10
        HasComplexReturn = 0x20
        HasRangeOnConformance = 0x40
      end

      WIN2K_EXT_SIZE = 8
      WIN2K_EXT64_SIZE = 10 # 12?
    end
  end
end
