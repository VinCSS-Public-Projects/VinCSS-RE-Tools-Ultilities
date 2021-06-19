/**
 * Delphi_System.h
 * Some Delphi System/SysInit types need for RE Delphi binaries in IDA
 * Extract from System.pas, System.hpp, SysInit.hpp and sysmac.h files in RADStudio Sydney 10.4
 * Import this file into IDA by File - Load file - Parse C header file
 * Uses only with Delphi/C++Builder Windows PE 32/64bit
 * In IDA32, set Compiler to Borland C++ or Delphi
 * In IDA64, set Compiler to Visual C++
 * Created by HTC - VinCSS (a member of Vingroup)
 */

#ifndef __DELPHI_SYSTEM_H__
#define __DELPHI_SYSTEM_H__

#include <windows.h>    // If IDA can not parse windows.h, comment it

#pragma pack(push,8)

#ifndef _Windows
    #define _Windows    1
#endif

#ifdef __EA64__         // IDA64
    #define _WIN64      1
    #undef _WIN32
    #undef __WIN32__
#else                   // IDA32
    #define __WIN32__   1
    #define _WIN32      1
    #undef _WIN64
#endif

// Comment below for old Delphi version <= 7.0
#define _DELPHI_NEW

#ifdef _DELPHI_NEW
    #define _DELPHI_STRING_UNICODE
#endif

// Declares in sysmac.h

// IDA parser not support parsing C++ namespace, template and Delphi set type :(
class TObject;
class TInterfacedObject;

class TMetaClass;
typedef TMetaClass* TClass;
class DelphiMetaClass;

struct AnsiString;
struct UnicodeString;
struct SmallString;

class RawByteString;
class UTF8String;

typedef RawByteString   *PRawByteString;
typedef UTF8String      *PUTF8String;

typedef CURRENCY Currency;
typedef DATE TDateTime;
typedef VARIANT OleVariant;
typedef VARIANT Variant;
typedef float Comp;
typedef BSTR WideString;

// The following typedefs are aliases to use the Delphi naming convention
// such as Boolean, Integer, UInt64, Cardinal, etc
// I have remove Shortint, Smallint, Longint, convert to ShortInt, SmallInt, LongInt
//
typedef bool                Boolean;
typedef int                 Integer;        // -2147483648..2147483647
typedef wchar_t             WideChar;       // Unicode character

// ShortInt is a source of confusion for C++ where Short implies, well, short!!
typedef signed char         ShortInt;       // -128..127
typedef ShortInt           *PShortInt;

typedef signed char         Int8;           // -128..127
typedef short               SmallInt;       // -32768..32767
typedef unsigned char       Byte;           // 0..255
typedef unsigned short      Word;           // 0..65535
typedef unsigned long       DWord;          // 0..4294967295

#if defined(_PLAT_IOS64) || defined(_PLAT_LINUX64)
    typedef unsigned long   LongWord;       // 0..18446744073709551615
#elif defined(_PLAT_IOS32)
    typedef unsigned        LongWord;       // 0..4294967295
#else   // WINDOWS
    typedef unsigned        LongWord;       // 0..4294967295
#endif
typedef long long           Int64;          // −9,223,372,036,854,775,807..9,223,372,036,854,775,807
typedef unsigned long long  UInt64;         // 0..18,446,744,073,709,551,615
typedef void               *Pointer;        //
typedef Pointer            *PPointer;       //
typedef char                AnsiChar;       //

#if defined(_PLAT_IOS64) || defined(_PLAT_LINUX64)
    typedef long            LongInt;        // -9223372036854775808..9223372036854775807
#elif defined(_PLAT_IOS32)
    // Delphi mangles 'LongInt' as an 'Integer' in 32-bit :(
    typedef int /*long*/    LongInt;        // -2147483648..2147483647
#else   // WINDOWS
    typedef int             LongInt;        // -2147483648..2147483647
#endif

typedef unsigned int        Cardinal;       // 0..4294967295
typedef long double         Extended;       // 10 byte real
typedef float               Single;         // 4 byte real
typedef Single             *PSingle;        //
typedef double              Double;         // 8 byte real
typedef char* const         Openstring;     // D16 string/D32 shortstring formalparm
typedef void               *file;           //

typedef char               *PAnsiChar;
typedef WideChar           *PWideChar;

#if defined(_DELPHI_STRING_UNICODE)
    typedef WideChar        Char;
    typedef PWideChar       PChar;
#else
    typedef char            Char;           // 0..255
    typedef PAnsiChar       PChar;
#endif

class DelphiInterface;

typedef IUnknown IInterface;
typedef IUnknown IInvokable;

#if defined(_Windows)
    typedef unsigned char   ByteBool;
    typedef unsigned short  WordBool;
    typedef int             LongBool;
    #if defined(_WIN64)
        typedef __int64             NativeInt;
        typedef unsigned __int64    NativeUInt;
    #else
        typedef int                 NativeInt;
        typedef unsigned int        NativeUInt;
    #endif
#endif

#if defined(_DELPHI_STRING_UNICODE)
    typedef UnicodeString   String;
#endif

typedef SmallString         ShortString;
typedef ShortString        *PShortString;
typedef AnsiString         *PAnsiString;
typedef UnicodeString      *PUnicodeString;

#if defined(_DELPHI_STRING_UNICODE)
    typedef PUnicodeString  PString;
#else
    typedef PAnsiString     PString;
#endif

typedef WideString         *PWideString;
typedef Extended           *PExtended;
typedef Currency           *PCurrency;
typedef Variant            *PVariant;
typedef OleVariant         *POleVariant;
typedef GUID                TGUID;
typedef TGUID              *PGUID;
typedef HRESULT             HResult;

typedef Byte               *PByte;
typedef Integer            *PInteger;
typedef __int64            *PInt64;
typedef LongWord           *PLongWord;
typedef SmallInt           *PSmallInt;
typedef Boolean            *PBoolean;
typedef PChar              *PPChar;
typedef Double             *PDouble;
typedef Cardinal            UCS4Char;
typedef UCS4Char           *PUCS4Char;
typedef char              **_PPAnsiChar;

// Declares in System.hpp

typedef UCS4Char           *TUCS4CharArray;
typedef TUCS4CharArray     *PUCS4CharArray;
typedef int                *IntegerArray;
typedef __int64            *Int64Array;
typedef void               *PointerArray;
typedef PChar               TPCharArray;
typedef LongInt            *PLongInt;
typedef LongBool           *PLongBool;

// IDA parser not support interface
struct IEnumerator;
struct IEnumerable;
struct IComparable;

//-- type declarations -------------------------------------------------------
typedef int                *PFixedInt;
typedef unsigned           *PFixedUInt;
typedef short               Int16;
typedef int                 Int32;
typedef NativeInt           IntPtr;
typedef Byte                UInt8;
typedef Word                UInt16;
typedef unsigned            UInt32;
typedef NativeUInt          UIntPtr;
typedef float               Float32;
typedef double              Float64;
typedef char                UTF8Char;
typedef char               *PUTF8Char;

// Variant type codes (wtypes.h)
enum TVarData_VType
{
    varEmpty    = 0x0000, // vt_empty        0
    varNull     = 0x0001, // vt_null         1
    varSmallint = 0x0002, // vt_i2           2
    varInteger  = 0x0003, // vt_i4           3
    varSingle   = 0x0004, // vt_r4           4
    varDouble   = 0x0005, // vt_r8           5
    varCurrency = 0x0006, // vt_cy           6
    varDate     = 0x0007, // vt_date         7
    varOleStr   = 0x0008, // vt_bstr         8
    varDispatch = 0x0009, // vt_dispatch     9
    varError    = 0x000A, // vt_error       10
    varBoolean  = 0x000B, // vt_bool        11
    varVariant  = 0x000C, // vt_variant     12
    varUnknown  = 0x000D, // vt_unknown     13
//  varDecimal  = 0x000E, // vt_decimal      14  UNSUPPORTED as of v6.x code base
//  varUndef0F  = 0x000F, // undefined       15  UNSUPPORTED per Microsoft
    varShortInt = 0x0010, // vt_i1          16
    varByte     = 0x0011, // vt_ui1         17
    varWord     = 0x0012, // vt_ui2         18
    varLongWord = 0x0013, // vt_ui4         19  deprecated 'use varUInt32' ,
    varUInt32   = 0x0013, // vt_ui4         19
    varInt64    = 0x0014, // vt_i8          20
    varUInt64   = 0x0015, // vt_ui8         21
    varRecord   = 0x0024, // VT_RECORD      36
    // if adding new items, update Variants' varLast, BaseTypeMap and OpTypeMap
    varStrArg   = 0x0048, // vt_clsid        72
    varObject   = 0x0049, //                 73
    varUStrArg  = 0x004A, //                 74
    varString   = 0x0100, // Pascal string  256  not OLE compatible
    varAny      = 0x0101, // Corba any      257  not OLE compatible
    varUString  = 0x0102, // Unicode string 258  not OLE compatible
    // custom types range from 0x110 (272) to 0x7FF (2047)
    varTypeMask = 0x0FFF,
    varArray    = 0x2000,
    varByRef    = 0x4000,
};

enum TVarRect_VType
{
    vtInteger       = 0,
    vtBoolean       = 1,
    vtChar          = 2,
    vtExtended      = 3,
    vtString        = 4,
    vtPointer       = 5,
    vtPChar         = 6,
    vtObject        = 7,
    vtClass         = 8,
    vtWideChar      = 9,
    vtPWideChar     = 10,
    vtAnsiString    = 11,
    vtCurrency      = 12,
    vtVariant       = 13,
    vtInterface     = 14,
    vtWideString    = 15,
    vtInt64         = 16,
    vtUnicodeString = 17,
};

#ifdef _WIN64
    #define CPP_ABI_ADJUST  3 * sizeof(void *)
#else
    #define CPP_ABI_ADJUST  0
#endif

enum VMTOFFSET
{
#ifdef _WIN64
    vmtSelfPtr           = -176 - CPP_ABI_ADJUST,
    vmtIntfTable         = -168 - CPP_ABI_ADJUST,
    vmtAutoTable         = -160 - CPP_ABI_ADJUST,
    vmtInitTable         = -152 - CPP_ABI_ADJUST,
    vmtTypeInfo          = -144 - CPP_ABI_ADJUST,
    vmtFieldTable        = -136 - CPP_ABI_ADJUST,
    vmtMethodTable       = -128 - CPP_ABI_ADJUST,
    vmtDynamicTable      = -120 - CPP_ABI_ADJUST,
    vmtClassName         = -112 - CPP_ABI_ADJUST,
    vmtInstanceSize      = -104 - CPP_ABI_ADJUST,   // or vmtObjAddRef
    vmtParent            = -96  - CPP_ABI_ADJUST,   // or VmtObjRelease
    vmtEquals            = -88 - CPP_ABI_ADJUST,
    vmtGetHashCode       = -80 - CPP_ABI_ADJUST,
    vmtToString          = -72 - CPP_ABI_ADJUST,
    vmtSafeCallException = -64 - CPP_ABI_ADJUST,
    vmtAfterConstruction = -56 - CPP_ABI_ADJUST,
    vmtBeforeDestruction = -48 - CPP_ABI_ADJUST,
    vmtDispatch          = -40 - CPP_ABI_ADJUST,
    vmtDefaultHandler    = -32 - CPP_ABI_ADJUST,
    vmtNewInstance       = -24 - CPP_ABI_ADJUST,
    vmtFreeInstance      = -16 - CPP_ABI_ADJUST,
    vmtDestroy           =  -8 - CPP_ABI_ADJUST,
    vmtQueryInterface    =  0,
    vmtAddRef            =  8,
    vmtRelease           = 16,
    vmtCreateObject      = 24,
#else
    vmtSelfPtr           = -88 - CPP_ABI_ADJUST,
    vmtIntfTable         = -84 - CPP_ABI_ADJUST,
    vmtAutoTable         = -80 - CPP_ABI_ADJUST,
    vmtInitTable         = -76 - CPP_ABI_ADJUST,
    vmtTypeInfo          = -72 - CPP_ABI_ADJUST,
    vmtFieldTable        = -68 - CPP_ABI_ADJUST,
    vmtMethodTable       = -64 - CPP_ABI_ADJUST,
    vmtDynamicTable      = -60 - CPP_ABI_ADJUST,
    vmtClassName         = -56 - CPP_ABI_ADJUST,
    vmtInstanceSize      = -52 - CPP_ABI_ADJUST,
    vmtParent            = -48 - CPP_ABI_ADJUST,
    vmtEquals            = -44 - CPP_ABI_ADJUST,
    vmtGetHashCode       = -40 - CPP_ABI_ADJUST,
    vmtToString          = -36 - CPP_ABI_ADJUST,
    vmtSafeCallException = -32 - CPP_ABI_ADJUST,
    vmtAfterConstruction = -28 - CPP_ABI_ADJUST,
    vmtBeforeDestruction = -24 - CPP_ABI_ADJUST,
    vmtDispatch          = -20 - CPP_ABI_ADJUST,
    vmtDefaultHandler    = -16 - CPP_ABI_ADJUST,
    vmtNewInstance       = -12 - CPP_ABI_ADJUST,
    vmtFreeInstance      = -8 - CPP_ABI_ADJUST,
    vmtDestroy           = -4 - CPP_ABI_ADJUST,
    vmtQueryInterface    = 0,
    vmtAddRef            = 4,
    vmtRelease           = 8,
    vmtCreateObject      = 12,
#endif
};

// Self in Delphi =  this in C++
typedef HRESULT (__fastcall *TSafeCallException)(TObject *Self, TObject *ExceptObject, Pointer ExceptAddr);
typedef void (__fastcall *TAfterConstruction)(TObject *Self);
typedef void (__fastcall *TBeforeDestruction)(TObject *Self);
typedef void (__fastcall *TDispatch)(TObject *Self, void *Msg);

enum TVisibilityClasses : unsigned char     // bitwise
{
    vcPrivate,
    vcProtected,
    vcPublic,
    vcPublished
};

#pragma pack(push,1)
struct TInterfaceEntry
{
public:
    GUID IID;
    void *VTable;
    int IOffset;
#ifdef _WIN64
    unsigned _Filler;
#endif /* _WIN64 */
    NativeUInt ImplGetter;
};
#pragma pack(pop)
typedef TInterfaceEntry *PInterfaceEntry;

#pragma pack(push,1)
struct TInterfaceTable
{
public:
    int EntryCount;
#ifdef _WIN64
    unsigned _Filler;
#endif /* _WIN64 */
    TInterfaceEntry Entries[0];
};
#pragma pack(pop)
typedef TInterfaceTable *PInterfaceTable;

struct TMethod
{
public:
    void *Code;
    void *Data;
};
typedef TMethod *PMethod;

struct TDispatchMessage
{
public:
    Word MsgID;
};

typedef unsigned TThreadID;

struct TMonitor
{
private:
    struct TWaitingThread
    {
    public:
        TMonitor::TWaitingThread *Next;
        unsigned Thread;
        void *WaitEvent;
    };

    typedef TWaitingThread *PWaitingThread;

    struct TSpinWait
    {
    private:
        int FCount;
    };

    struct TSpinLock
    {
    private:
        int FLock;
    };

private:
    int FLockCount;
    int FRecursionCount;
    unsigned FOwningThread;
    void *FLockEvent;
    int FSpinCount;
    TWaitingThread *FWaitQueue;
    TSpinLock FQueueLock;
    static int CacheLineSize;
    static int FDefaultSpinCount;
};

typedef TMonitor *PMonitor;
typedef PMonitor *PPMonitor;

#ifndef _WIN64
    typedef TMetaClass* TInterfacedClass;
#else
    typedef TMetaClass  TInterfacedClass;
#endif

typedef WideChar            UCS2Char;
typedef WideChar           *PUCS2Char;
typedef UTF8String         *PUTF8String;
typedef RawByteString      *PRawByteString;
typedef IntegerArray       *PIntegerArray;
typedef Int64Array         *PInt64Array;
typedef PointerArray       *PPointerArray;
typedef NativeInt          *TBoundArray;
typedef TPCharArray        *PPCharArray;
typedef unsigned           *PCardinal;
typedef Word               *PWord;
typedef unsigned           *PUint32;
typedef unsigned __int64   *PUInt64;
typedef double             *PDate;
typedef unsigned           *PError;
typedef WordBool           *PWordBool;
typedef IInterface         *PUnknown;
typedef PUnknown           *PPUnknown;
typedef WideChar          **PPWideChar;
typedef char              **PPAnsiChar;
typedef Comp               *PComp;
typedef NativeInt          *PNativeInt;
typedef NativeUInt         *PNativeUInt;
typedef TDateTime          *PDateTime;

struct TVarArrayBound
{
public:
    int ElementCount;
    int LowBound;
};
typedef TVarArrayBound      *PVarArrayBound;

typedef TVarArrayBound      TVarArrayBoundArray[0];
typedef TVarArrayBoundArray *PVarArrayBoundArray;
typedef int                 TVarArrayCoorArray[0];
typedef TVarArrayCoorArray  *PVarArrayCoorArray;

struct TVarArray
{
public:
    Word DimCount;
    Word Flags;
    int ElementSize;
    int LockCount;
    void *Data;
    TVarArrayBoundArray Bounds;
};
typedef TVarArray *PVarArray;

struct TVarRecord
{
public:
    void *PRecord;
    void *RecInfo;
};
typedef TVarRecord *PVarRecord;

struct TLargestVarData
{
public:
    void *_Reserved1;
    void *_Reserved2;
};

typedef Word TVarType;

// TVarData = VARIANT
struct TVarData
{
    TVarType VType;    // Delphi-compatible - Variant Type member
    Word Reserved1;
    Word Reserved2;
    Word Reserved3;
    union
    {
        // Delphi-compatible TVarData/Variant members
        SmallInt    VSmallInt;    //  iVal
        Integer     VInteger;     //  lVal
        Single      VSingle;      //  fltVal
        Double      VDouble;      //  dblVal
        Currency    VCurrency;    //  cyVal
        TDateTime   VDate;        //  date
        PWideChar   VOleStr;      //  bstrVal
        IDispatch  *VDispatch;    //  pdispVal
        HResult     VError;       //  scode
        WordBool    VBoolean;     //  boolVal
        IUnknown   *VUnknown;     //  punkVal
        Byte        VByte;        //  bVal
        Int8        VShortInt;    //  charVal
        Pointer     VString;      //  ??????
        PVarArray   VArray;       //  parray
        Pointer     VPointer;     //  byref
        __int64     VInt64;       //  llVal
        UInt64      VUInt64;      //  ullVal
        Word        VWord;        //  uiVal
        LongWord    VLongWord;    //  ulVal
        TVarRecord  VRecord;      //  struct __tagBRECORD
    };
};
typedef TVarData *PVarData;

struct TVarRec
{
public:
    union
    {
        int          VInteger;
        bool         VBoolean;
        AnsiChar     VChar;
        long double* VExtended;
        PShortString VString;
        void*        VPointer;
        PAnsiChar    VPChar;
        void*        VObject;
        TClass       VClass;
        WideChar     VWideChar;
        WideChar*    VPWideChar;
        void*        VAnsiString;
        Currency*    VCurrency;
        Variant*     VVariant;
        void*        VInterface;
        void*        VWideString;
        __int64*     VInt64;
        void*        VUnicodeString;
    };
    union
    {
        Byte VType;
    };
};
typedef TVarRec *PVarRec;

enum TTypeKind : unsigned char
{
    tkUnknown,
    tkInteger,
    tkChar,
    tkEnumeration,
    tkFloat,
    tkString,
    tkSet,
    tkClass,
    tkMethod,
    tkWChar,
    tkLString,
    tkWString,
    tkVariant,
    tkArray,
    tkRecord,
    tkInterface,
    tkInt64,
    tkDynArray,
    tkUString,
    tkClassRef,
    tkPointer,
    tkProcedure,
    tkMRecord,
    tkAnsiChar = tkChar,
    tkWideChar = tkWChar,
    tkUnicodeString = tkUString,
    tkAnsiString = tkLString,
    tkWideString = tkWString,
    tkShortString = tkString,
};

enum TVarOp
{
    opAdd =        0,
    opSubtract =   1,
    opMultiply =   2,
    opDivide =     3,
    opIntDivide =  4,
    opModulus =    5,
    opShiftLeft =  6,
    opShiftRight = 7,
    opAnd =        8,
    opOr =         9,
    opXor =        10,
    opCompare =    11,
    opNegate =     12,
    opNot =        13,
    opCmpEQ =      14,
    opCmpNE =      15,
    opCmpLT =      16,
    opCmpLE =      17,
    opCmpGT =      18,
    opCmpGE =      19,
};

#pragma pack(push,1)
struct TCallDesc
{
public:
    Byte CallType;
    Byte ArgCount;
    Byte NamedArgCount;
    Byte ArgTypes[256];
};
#pragma pack(pop)
typedef TCallDesc *PCallDesc;

#pragma pack(push,1)
struct TDispDesc
{
public:
    int DispID;
    Byte ResType;
    TCallDesc CallDesc;
};
#pragma pack(pop)
typedef TDispDesc *PDispDesc;

typedef void *TVarArgList;

#pragma pack(push,1)
struct TDynArrayTypeInfo
{
    TTypeKind kind;
    Byte name;  // string[0];
    Integer elSize;
    TDynArrayTypeInfo *elType;
    Integer varType;
};
#pragma pack(pop)
typedef TDynArrayTypeInfo   *PDynArrayTypeInfo;

struct TMemoryManager
{
public:
    void * __fastcall (*GetMem)(NativeInt Size);
    int __fastcall (*FreeMem)(void * P);
    void * __fastcall (*ReallocMem)(void * P, NativeInt Size);
};
typedef TMemoryManager *PMemoryManager;

struct TMemoryManagerEx
{
public:
    void * __fastcall (*GetMem)(NativeInt Size);
    int __fastcall (*FreeMem)(void * P);
    void * __fastcall (*ReallocMem)(void * P, NativeInt Size);
    void * __fastcall (*AllocMem)(NativeInt Size);
    bool __fastcall (*RegisterExpectedMemoryLeak)(void * P);
    bool __fastcall (*UnregisterExpectedMemoryLeak)(void * P);
};
typedef TMemoryManagerEx *PMemoryManagerEx;

struct THeapStatus
{
public:
    NativeUInt TotalAddrSpace;
    NativeUInt TotalUncommitted;
    NativeUInt TotalCommitted;
    NativeUInt TotalAllocated;
    NativeUInt TotalFree;
    NativeUInt FreeSmall;
    NativeUInt FreeBig;
    NativeUInt Unused;
    NativeUInt Overhead;
    unsigned HeapErrorCode;
};

#pragma pack(push,1)
struct TSmallBlockTypeState
{
public:
    unsigned InternalBlockSize;
    unsigned UseableBlockSize;
    NativeUInt AllocatedBlockCount;
    NativeUInt ReservedAddressSpace;
};
#pragma pack(pop)

#ifndef _WIN64
    typedef TSmallBlockTypeState    TSmallBlockTypeStates[55];
#else
    typedef TSmallBlockTypeState    TSmallBlockTypeStates[46];
#endif

#pragma pack(push,1)
struct TMemoryManagerState
{
public:
    TSmallBlockTypeStates SmallBlockTypeStates;
    unsigned AllocatedMediumBlockCount;
    NativeUInt TotalAllocatedMediumBlockSize;
    NativeUInt ReservedMediumBlockAddressSpace;
    unsigned AllocatedLargeBlockCount;
    NativeUInt TotalAllocatedLargeBlockSize;
    NativeUInt ReservedLargeBlockAddressSpace;
};
#pragma pack(pop)

struct TMonitorSupport
{
public:
    void * __fastcall (*NewSyncObject)(void);
    void __fastcall (*FreeSyncObject)(void * SyncObject);
    void * __fastcall (*NewWaitObject)(void);
    void __fastcall (*FreeWaitObject)(void * WaitObject);
    unsigned __fastcall (*WaitOrSignalObject)(void * SignalObject, void * WaitObject, unsigned Timeout);
};
typedef TMonitorSupport *PMonitorSupport;

struct TPtrWrapper
{
private:
    Byte *Value;
};

enum TChunkStatus : unsigned char
{
    csUnallocated,
    csAllocated,
    csReserved,
    csSysAllocated,
    csSysReserved
};

typedef TChunkStatus TMemoryMap[65536];

enum TMinimumBlockAlignment : unsigned char
{
    mba8Byte,
    mba16Byte
};

// Compiler generated table to be processed sequentially to init & finit all package units
// Init: 0..Max-1; Final: Last Initialized..0
#pragma pack(push,1)
struct PackageUnitEntry
{
public:
    void *Init;
    void *FInit;
};
#pragma pack(pop)

typedef PackageUnitEntry UnitEntryTable[10000000];
typedef UnitEntryTable *PUnitEntryTable;

/*
 * Pointer in this table is PPTypeInfo, except when it's not; if the value is 1,
 * then it's a "unit boundary" marker, indicating that following types are in
 * the next unit along in the TPackageTypeInfo.UnitNames unit name list sequence.
*/
#ifndef _WIN64
    typedef void* TTypeTable[536870911];
#else
    typedef void* TTypeTable[268435455];
#endif
typedef TTypeTable *PTypeTable;

struct TPackageTypeInfo
{
public:
    NativeUInt TypeCount;
    TTypeTable *TypeTable;
    NativeUInt UnitCount;
    ShortString *UnitNames;     // concatenation of Pascal strings, one for each unit
};
typedef TPackageTypeInfo *PPackageTypeInfo;

struct PackageInfoTable
{
public:
    NativeUInt UnitCount;       // number of entries in UnitInfo array; always > 0
    UnitEntryTable *UnitInfo;
    TPackageTypeInfo TypeInfo;
};
typedef PackageInfoTable *PackageInfo;

#pragma pack(push,1)
struct TCVModInfo
{
public:
    char *ModName;
    char *LibName;
    void *UserData;
};
#pragma pack(pop)
typedef TCVModInfo *PCVModInfo;

enum CPUTYPE
{
    CPUi386     = 2,
    CPUi486     = 3,
    CPUPentium  = 4,
};

struct TCPUIDRec
{
public:
    unsigned EAX;
    unsigned EBX;
    unsigned ECX;
    unsigned EDX;
};

enum TTextLineBreakStyle : unsigned char
{
    tlbsLF,
    tlbsCRLF
};

enum TFileMode
{
    fmClosed = 0xD7B0,
    fmInput  = 0xD7B1,
    fmOutput = 0xD7B2,
    fmInOut  = 0xD7B3,
};

typedef NativeUInt TResourceHandle;

#pragma pack(push,1)
struct TFileRec
{
public:
    NativeInt Handle;
    Word Mode;
    Word Flags;

public:
    union
    {
        struct
        {
            unsigned BufSize;
            unsigned BufPos;
            unsigned BufEnd;
            char *BufPtr;
            void *OpenFunc;
            void *InOutFunc;
            void *FlushFunc;
            void *CloseFunc;
            Byte UserData[32];
            WideChar Name[260];
        };
        struct
        {
            unsigned RecSize;
        };

    };
};
#pragma pack(pop)

typedef char        TTextBuf[128];
typedef TTextBuf    *PTextBuf;

#pragma pack(push,1)
struct TTextRec
{
public:
    NativeInt Handle;
    Word Mode;
    Word Flags;
    unsigned BufSize;
    unsigned BufPos;
    unsigned BufEnd;
    char *BufPtr;
    void *OpenFunc;
    void *InOutFunc;
    void *FlushFunc;
    void *CloseFunc;
    Byte UserData[32];
    WideChar Name[260];
    TTextBuf Buffer;
    Word CodePage;
    Int8 MBCSLength;
    Byte MBCSBufPos;

    union
    {
        struct
        {
            WideChar UTF16Buffer[3];
        };
        struct
        {
            char MBCSBuffer[6];
        };

    };
};
#pragma pack(pop)

struct TLibModule
{
public:
    TLibModule *Next;
    NativeUInt Instance;
    NativeUInt CodeInstance;
    NativeUInt DataInstance;
    NativeUInt ResInstance;
    TPackageTypeInfo *TypeInfo;
    NativeInt Reserved;
};
typedef TLibModule *PLibModule;

struct TModuleUnloadRec
{
public:
    TModuleUnloadRec *Next;
    void *Proc;
};
typedef TModuleUnloadRec *PModuleUnloadRec;

#pragma pack(push,1)
struct TResStringRec
{
public:
    HMODULE *Module;
    NativeUInt Identifier;
};
#pragma pack(pop)
typedef TResStringRec *PResStringRec;

enum TFloatSpecial : unsigned char
{
    fsZero,
    fsNZero,
    fsDenormal,
    fsNDenormal,
    fsPositive,
    fsNegative,
    fsInf,
    fsNInf,
    fsNaN
};

#pragma pack(push,1)
struct TSingleRec
{
private:
    float aSingle;
};
#pragma pack(pop)
typedef TSingleRec *PSingleRec;

#pragma pack(push,1)
struct TDoubleRec
{
private:
    double aDouble;
};
#pragma pack(pop)
typedef TDoubleRec *PDoubleRec;

#pragma pack(push,1)
struct TExtended80Rec
{
private:
#ifndef _WIN64
    Extended aExtended80;
#else /* _WIN64 */
    unsigned __int64 aExtended80Frac;
    Word aExtended80Exp;
#endif /* _WIN64 */
};
#pragma pack(pop)
typedef TExtended80Rec *PExtended80Rec;

#ifndef _WIN64
    typedef PExtended80Rec  PExtendedRec;
    typedef TExtended80Rec  TExtendedRec;
#else
    typedef TDoubleRec      TExtendedRec;
    typedef PDoubleRec      PExtendedRec;
#endif /* _WIN64 */

#ifdef _WIN64
struct __m128
{
    UInt64 Lo, Hi;
};

struct __TExitDllJumpBuf
{
    Int64 _RIP, _RSP, _RBX, _RBP, _RSI, _RDI,
          _R12, _R13, _R14, _R15;
    __m128 XmmBuf[10];
};
#endif

struct TInitContext
{
public:
    TInitContext *OuterContext;     // saved InitContext
    void *ExcFrame;                 // bottom exc handler
    PackageInfoTable *InitTable;    // unit init info
    int InitCount;                  // how far we got
    TLibModule *Module;             // ptr to module desc
#ifdef _WIN32
    void *DLLSaveEBP;               // saved regs for DLLs
    void *DLLSaveEBX;               // saved regs for DLLs
    void *DLLSaveESI;               // saved regs for DLLs
    void *DLLSaveEDI;               // saved regs for DLLs
#endif
    void __fastcall (*ExitProcessTLS)(void);    // Shutdown for TLS
    Byte DLLInitState;              // 0 = package, 1 = DLL shutdown, 2 = DLL startup
    unsigned ThreadID;              // Initializing Thread
#ifdef _WIN64
    __TExitDllJumpBuf ExitDllJmpBuf;
#endif
};
typedef TInitContext *PInitContext;

struct TExceptionRecord
{
public:
    unsigned ExceptionCode;
    unsigned ExceptionFlags;
    TExceptionRecord *ExceptionRecord;
    void *ExceptionAddress;
    unsigned NumberParameters;

public:
    union
    {
        struct
        {
            void *ExceptAddr;
            void *ExceptObject;
        };
        struct
        {
            NativeUInt  ExceptionInformation[15];
        };
    };
};
typedef TExceptionRecord *PExceptionRecord;

struct TExceptionPointers
{
    TExceptionRecord *ExceptionRecord;
    CONTEXT *ContextRecord;
};
typedef TExceptionPointers  *PExceptionPointers;

// ZCX_BASED_EXCEPTIONS was defined in _WIN64 and TABLE_BASED_EXCEPTIONS and EXTERNAL_LINKER
//
#ifdef _WIN64
enum _Unwind_Reason_Code : int
{
    _URC_NO_REASON,                 // = 0
    _URC_FOREIGN_EXCEPTION_CAUGHT,  // = 1
    _URC_FATAL_PHASE2_ERROR,        // = 2
    _URC_FATAL_PHASE1_ERROR,        // = 3
    _URC_NORMAL_STOP,               // = 4
    _URC_END_OF_STACK,              // = 5
    _URC_HANDLER_FOUND,             // = 6
    _URC_INSTALL_CONTEXT,           // = 7
    _URC_CONTINUE_UNWIND,           // = 8
    _URC_FAILURE                    // = 9
};

struct _Unwind_Exception
{
    UInt64 exception_class;
    void __cdecl *_Unwind_Exception_Cleanup_Fn(_Unwind_Reason_Code reason, _Unwind_Exception *exc);
    UIntPtr private_1;
    UIntPtr private_2;
};

enum _Unwind_Action : int
{
    _UA_SEARCH_PHASE = 1,
    _UA_CLEANUP_PHASE = 2,
    _UA_HANDLER_FRAME = 3,
    _UA_FORCE_UNWIND = 4,
};

enum _Unwind_State : int
{
    _US_VIRTUAL_UNWIND_FRAME = 0,
    _US_UNWIND_FRAME_STARTING = 1,
    _US_UNWIND_FRAME_RESUME = 2,
    _US_ACTION_MASK = 3,
    _US_FORCE_UNWIND = 8,
    _US_END_OF_STACK = 16,
};
#endif

// For System.pas internal use only. Keep in sync with StrRec in getmem.inc
#pragma pack(push,1)
// String internal type
struct
{
    unsigned short codePage;
    unsigned short elemSize;
    int refCnt;
    int length;
};

// Method info
struct MethRec
{
    Word recSize;       // Method record size
    Pointer methAddr;   // Pointer to method address
    Byte nameLen;
    char nameChars[0 /*nameLen*/];
};
#pragma pack(pop)

enum TRuntimeError
{
    reNone,
    reOutOfMemory,
    reInvalidPtr,
    reDivByZero,
    reRangeError,
    reIntOverflow,
    reInvalidOp,
    reZeroDivide,
    reOverflow,
    reUnderflow,
    reInvalidCast,
    reAccessViolation,
    rePrivInstruction,
    reControlBreak,
    reStackOverflow,
    // reVar* used in Variants.pas
    reVarTypeCast,
    reVarInvalidOp,
    reVarDispatch,
    reVarArrayCreate,
    reVarNotArray,
    reVarArrayBounds,
    reAssertionFailed,
    reExternalException,    //  not used here; in SysUtils
    reIntfCastError,
    reSafeCallError,
    reMonitorNotLocked,
    reNoMonitorSupport,
    rePlatformNotImplemented,
    reObjectDisposed
};

// Convert from reMap array to enums - HTC
enum TRuntimeErrorMap
{
    remNone = 0,
    remOutOfMemory = 203,
    remInvalidPtr = 204,
    remDivByZero = 200,
    remRangeError = 201,
    remAbstractError = 210,
    remIntOverflow = 215,
    remInvalidOp = 207,
    remZeroDivide = 200,
    remOverflow = 205,
    remUnderflow = 206,
    remInvalidCast = 219,
    remAccessViolation = 216,
    remPrivInstruction = 218,
    remControlBreak = 217,
    remStackOverflow = 202,
    remVarTypeCast = 220,
    remVarInvalidOp = 221,
    remVarDispatch = 222,
    remVarArrayCreate = 223,
    remVarNotArray = 224,
    remVarArrayBounds = 225,
    remThreadInitFailed = 226,
    remAssertionFailed = 227,
    remIntfCastError = 228,
    remSafeCallError = 229,
    remMonitorNotLocked = 235,
    remNoMonitorSupport = 236,
    remCompilerReserved = 230,
    remTooManyNestedExceptions = 231,
    remNonDelphiFatalSignal = 232,
    remQuit = 233,
    remCodesetConversion = 234,
    remPlatformNotImplemented = 237,
    remObjectDisposed = 238,
};

#pragma pack(push,1)
// Dynamic array internal
struct TDynArrayRec
{
#ifdef _WIN64
    Integer _Padding;   // Make 16 byte align for payload..
#endif
    Integer RefCnt;
    NativeInt Length;
};
typedef TDynArrayRec *PDynArrayRec;
#pragma pack(pop)

enum TExceptionFlags : int
{
    cContinuable        = 0,
    cNonContinuable     = 1,
    cUnwinding          = 2,
    cUnwindingForExit   = 4,
    cUnwindInProgress   = cUnwinding | cUnwindingForExit,
    cDelphiException    = 0x0EEDFADE,
    cDelphiReRaise      = 0x0EEDFADF,
    cDelphiExcept       = 0x0EEDFAE0,
    cDelphiFinally      = 0x0EEDFAE1,
    cDelphiTerminate    = 0x0EEDFAE2,
    cDelphiUnhandled    = 0x0EEDFAE3,
    cNonDelphiException = 0x0EEDFAE4,
    cDelphiExitFinally  = 0x0EEDFAE5,
#ifdef _WIN64
    cCppExceptionMask   = 0xFFFFFFFE,
    cCppException       = 0xE36C6700,
#else
    cCppException       = 0x0EEFFACE,    // used by BCB
#endif
    cEXCEPTION_CONTINUE_SEARCH    = 0,
    cEXCEPTION_EXECUTE_HANDLER    = 1,
    cEXCEPTION_CONTINUE_EXECUTION = -1,
};

typedef Integer (__fastcall *_TDelphiFinallyHandlerProc)(PExceptionPointers ExceptionPointers,
                                                         NativeUInt EstablisherFrame);

typedef Integer (__fastcall *_TExceptionHandlerProc)(PExceptionPointers ExceptionPointers,
                                                     NativeUInt EstablisherFrame);

typedef NativeUInt (__fastcall *_TDelphiSafeCallCatchHandlerProc)(PExceptionPointers ExceptionPointers,
                                                                  NativeUInt EstablisherFrame,
                                                                  Pointer ExceptionObject,
                                                                  Pointer ExceptionAddress);
#ifdef _WIN32

#pragma pack(push,1)
struct JmpInstruction
{
    Byte opCode;
    LongInt distance;
};
#pragma pack(pop)

struct TExcDescEntry
{
    Pointer VTable;
    Pointer Handler;
};
typedef TExcDescEntry *PExcDescEntry;

#pragma pack(push,1)
struct TExcDesc
{
    JmpInstruction jmp;
    union
    {
        struct
        {
            Byte instructions[0];
        };
        struct
        {
            Integer cnt;
            TExcDescEntry excTab[0];
        };
    };
};
typedef TExcDesc *PExcDesc;
#pragma pack(pop)

struct TExcFrame
{
    TExcFrame *next;
    PExcDesc *desc;
    Pointer hEBP;
    union
    {
        Pointer ConstructedObject;
        Pointer SelfOfMethod;
    };
};
typedef TExcFrame *PExcFrame;

#pragma pack(push, 1)
struct TRaiseFrame
{
    TRaiseFrame *NextRaise;
    Pointer ExceptAddr;
    Pointer ExceptObject;   // pointer to TObject instance
    PExceptionRecord ExceptionRecord;
};
typedef TRaiseFrame *PRaiseFrame;
#pragma pack(pop)

#else   // _WIN64

// Language specific exception data, at the end of of array of UNWIND_CODE, after handler proc pointer

struct TExcDescEntry
{
    DWORD VTable;    // 32bit RVA
    DWORD Handler;   // 32bit RVA
};
typedef TExcDescEntry *PExcDescEntry;

struct TExcDesc
{
    Integer DescCount;
    TExcDescEntry DescTable[0 /* DescCount */];
};
typedef TExcDesc *PExcDesc;

struct TExcScope
{
    DWORD BeginOffset;        // 32 bit RVA
    DWORD EndOffset;          // 32 bit RVA
    DWORD TableOffset;        // 32 bit RVA. 0:TargetOffset=finally block
                              //             1:TargetOffset=safecall catch block
                              //             2:TargetOffset=catch block
                              //         other:TableOffset=TExcDesc
    DWORD TargetOffset;       // 32 bit RVA. start of finally/catch block.
                              //   TableOffset=0: signature is _TDelphiFinallyHandlerProc
                              //   TableOffset=1: signature is _TDelphiSafeCallCatchHandlerProc
                              //   TableOffset=2: Location to the catch block
                              //   other: TargetOffset=0
};
typedef TExcScope *PExcScope;

struct TExcData
{
    Integer ScopeCount;
    TExcScope ScopeTable[0 /* ScopeCount */];
}
typedef TExcData *PExcData;

struct TRaiseFrame
{
    TRaiseFrame *NextRaise;
    Pointer ExceptAddr;
    Pointer ExceptObject;   // pointer to TObject instance
    Boolean Allocated;
};
typedef TRaiseFrame *PRaiseFrame, **PPRaiseFrame;
#endif

// Internal startup functions prototype

// SysInit.pas
//
#ifdef _WIN64
void __fastcall _InitLib(PInitContext pContext, PackageInfo InitTable, HINSTANCE hInst,
                         DWORD dwReason, LPVOID lpReserved);
#else
void _InitLib(void);
#endif

void __fastcall _InitExe(PackageInfo InitTable);
BOOL __fastcall _InitPkg(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved);

// Invoked by C++ startup code to allow initialization of VCL global vars
void __cdecl VclInit(Boolean isDll, Boolean isPkg, HINSTANCE hInst, Boolean isGui);
void VclExit(void);

// System.pas
//
int  __fastcall _DllMain(PInitContext Context);
void __fastcall _StartExe(PackageInfo InitTable, PLibModule Module);

#ifdef _WIN64
void __fastcall _StartLib(PInitContext ContextBuf, PackageInfo InitTable, PLibModule Module,
                          Pointer TlsProc, Pointer DllProc, HINSTANCE hInst, DWORD dwReason);
#else
void __fastcall _StartLib(void);
#endif

void __fastcall _PackageLog(const PackageInfo Table, PLibModule Module);
void __fastcall _PackageUnload(const PackageInfo Table, PLibModule Module);

// Exception support functions
#ifdef _WIN64
void __fastcall _RaiseExcept(TObject *Obj);
void __fastcall _RaiseAtExcept(TObject *Obj, Pointer Address);
void __fastcall _RaiseAgain(void);
void __fastcall _DestroyException(PExceptionPointers ExceptionPointers, NativeUInt EstablisherFrame);
void __fastcall _DoneExcept(void);
void __fastcall _TryFinallyExit(NativeUInt EstablisherFrame, NativeUInt TargetAddr);
void __fastcall _UnhandledException(void);
int  __fastcall _DelphiExceptionHandler(PExceptionRecord ExceptionRecord, NativeUInt EstablisherFrame,
                                        PCONTEXT ContextRecord, PDISPATCHER_CONTEXT DispatcherContext);
#else
void _RaiseAtExcept(void);
void _RaiseExcept(void);
void _RaiseAgain(void);
void _DestroyException(void);
void _DoneExcept(void);
void _HandleAnyException(void);
void _HandleAutoException(void);
void _HandleOnException(void);
void _HandleFinally(void);
void _HandleOnExceptionPIC(void);
void _ClassHandleException(void);
void _UnhandledException(void);
#endif

// to be continue...

#endif  // __DELPHI_SYSTEM_H__
