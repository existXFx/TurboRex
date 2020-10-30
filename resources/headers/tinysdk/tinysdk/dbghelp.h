

#ifdef _WIN64
#ifndef _IMAGEHLP64
#define _IMAGEHLP64
#endif
#endif


typedef enum {
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

//
// module data structure
//

typedef struct _IMAGEHLP_MODULE64 {
    DWORD    SizeOfStruct;           
    DWORD64  BaseOfImage;            
    DWORD    ImageSize;              
    DWORD    TimeDateStamp;          
    DWORD    CheckSum;               
    DWORD    NumSyms;                
    SYM_TYPE SymType;                
    CHAR     ModuleName[32];         
    CHAR     ImageName[256];         
    CHAR     LoadedImageName[256];   
    CHAR     LoadedPdbName[256];     
    DWORD    CVSig;                  
    CHAR     CVData[MAX_PATH * 3];   // Contents of the CV record
    DWORD    PdbSig;                 // Signature of PDB
    GUID     PdbSig70;               // Signature of PDB (VC 7 and up)
    DWORD    PdbAge;                 // DBI age of pdb
    BOOL     PdbUnmatched;           // loaded an unmatched pdb
    BOOL     DbgUnmatched;           // loaded an unmatched dbg
    BOOL     LineNumbers;            // we have line number information
    BOOL     GlobalSymbols;          // we have internal symbol information
    BOOL     TypeInfo;               // we have type information
    BOOL     SourceIndexed;          // pdb supports source server
    BOOL     Publics;                // contains public symbols
    DWORD    MachineType;            // IMAGE_FILE_MACHINE_XXX from ntimage.h and winnt.h
    DWORD    Reserved;               // Padding - don't remove.
} IMAGEHLP_MODULE64, *PIMAGEHLP_MODULE64;

typedef struct _IMAGEHLP_MODULEW64 {
    DWORD    SizeOfStruct;           
    DWORD64  BaseOfImage;            
    DWORD    ImageSize;              
    DWORD    TimeDateStamp;          
    DWORD    CheckSum;              
    DWORD    NumSyms;                
    SYM_TYPE SymType;                // type of symbols loaded
    WCHAR    ModuleName[32];         // module name
    WCHAR    ImageName[256];         // image name
    WCHAR    LoadedImageName[256];   // symbol file name
    WCHAR    LoadedPdbName[256];     // pdb file name
    DWORD    CVSig;                  // Signature of the CV record in the debug directories
    WCHAR        CVData[MAX_PATH * 3];   // Contents of the CV record
    DWORD    PdbSig;                 // Signature of PDB
    GUID     PdbSig70;               // Signature of PDB (VC 7 and up)
    DWORD    PdbAge;                 // DBI age of pdb
    BOOL     PdbUnmatched;           // loaded an unmatched pdb
    BOOL     DbgUnmatched;           
    BOOL     LineNumbers;            
    BOOL     GlobalSymbols;          
    BOOL     TypeInfo;               
    BOOL     SourceIndexed;          
    BOOL     Publics;                
    DWORD    MachineType;            
    DWORD    Reserved;               
} IMAGEHLP_MODULEW64, *PIMAGEHLP_MODULEW64;


#if !defined(_IMAGEHLP_SOURCE_) && defined(_IMAGEHLP64)
#define IMAGEHLP_MODULE IMAGEHLP_MODULE64
#define PIMAGEHLP_MODULE PIMAGEHLP_MODULE64
#define IMAGEHLP_MODULEW IMAGEHLP_MODULEW64
#define PIMAGEHLP_MODULEW PIMAGEHLP_MODULEW64
#else
typedef struct _IMAGEHLP_MODULE {
    DWORD    SizeOfStruct;           // set to sizeof(IMAGEHLP_MODULE)
    DWORD    BaseOfImage;            // base load address of module
    DWORD    ImageSize;              // virtual size of the loaded module
    DWORD    TimeDateStamp;          // date/time stamp from pe header
    DWORD    CheckSum;               // checksum from the pe header
    DWORD    NumSyms;                // number of symbols in the symbol table
    SYM_TYPE SymType;                // type of symbols loaded
    CHAR     ModuleName[32];         // module name
    CHAR     ImageName[256];         // image name
    CHAR     LoadedImageName[256];   // symbol file name
} IMAGEHLP_MODULE, *PIMAGEHLP_MODULE;

typedef struct _IMAGEHLP_MODULEW {
    DWORD    SizeOfStruct;           // set to sizeof(IMAGEHLP_MODULE)
    DWORD    BaseOfImage;            // base load address of module
    DWORD    ImageSize;              // virtual size of the loaded module
    DWORD    TimeDateStamp;          // date/time stamp from pe header
    DWORD    CheckSum;               // checksum from the pe header
    DWORD    NumSyms;                // number of symbols in the symbol table
    SYM_TYPE SymType;                // type of symbols loaded
    WCHAR    ModuleName[32];         // module name
    WCHAR    ImageName[256];         // image name
    WCHAR    LoadedImageName[256];   // symbol file name
} IMAGEHLP_MODULEW, *PIMAGEHLP_MODULEW;
#endif



