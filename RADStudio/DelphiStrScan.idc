// NOLINT(whitespace/braces)

//=============================================================================
//--- IDA Pro v7.X IDC Script File
//      File: DelphiStrScan.idc
//   Authors: HTC - VinCSS (a member of Vingroup)
//   Version: 0.1
//   Purpose: Scan all sections and find old, new constants Long String,
//            AnsiString and Unicode String in Delphi/C++Builder binaries.
//            Delphi compiler puts constant strings in .text, CODE section,
//            between functions boundary so IDA Strings won't find them
//  Category: IDC
//   History:
//       0.1: 27/05/2020 - HTC - start coding for the first version
//=============================================================================

/*
Copy from Wikipedia CODEPAGE:

+ Microsoft Unicode code pages
1200 – UTF-16LE Unicode (little-endian)
1201 – UTF-16BE Unicode (big-endian)
12000 – UTF-32LE Unicode (little-endian)
12001 – UTF-32BE Unicode (big-endian)
65000 – UTF-7 Unicode
65001 – UTF-8 Unicode
65520 – Empty Unicode Plane

+ Windows ANSI code pages
874 – Windows Thai
1250 – Windows Central Europe
1251 – Windows Cyrillic
1252 – Windows Western
1253 – Windows Greek
1254 – Windows Turkish
1255 – Windows Hebrew
1256 – Windows Arabic
1257 – Windows Baltic
1258 – Windows Vietnamese

+ RawByteString have codepage = 0xFFFF
+ UFT8String = AnsiString, codepage = 65001
*/

#include <idc.idc>

//
// Delphi valid code pages on Windows
//

#define CP_RAW          0xFFFF
#define CP_ACP          0   // ElementSize = 1, default ANSI code page
#define CP_OEMCP        1   // ElementSize = 1, default OEM ANSI code page

// Unicode 16 LE/BE and UTF-7/8
#define CP_UTF16_LE     1200    // ElementSize = 2
#define CP_UTF16_BE     1201    // ElementSize = 2

// All below codepages, elemSize = 1
// UTF 7/8
#define CP_UTF7         65000
#define CP_UTF8         65001

// ANSI codepages
#define CP_LATIN_1      863     // Latin_1 Greek
#define CP_THAI         874
#define CP_JAPANESE     932
#define CP_CHINESE_1    936
#define CP_KOREAN       949
#define CP_CHINESE_2    950
#define CP_EUROPE       1250    // Central_Europe
#define CP_CYRILLIC     1251
#define CP_WESTERN      1252    // Latin_1
#define CP_GREEK        1253
#define CP_TURKISH      1254
#define CP_HEBREW       1255
#define CP_ARABIC       1256
#define CP_BALTIC       1257
#define CP_VIETNAM      1258

#define LONG_STRREC     "LongStrRec"
#define ANSI_STRREC     "AnsiStrRec"
#define UNICODE_STRREC  "UnicodeStrRec"

#define NOT_STRING      0
#define UNICODE_STRING  1
#define RAWBYTE_STRING  2
#define UTF8_STRING     3
#define ANSI_STRING     4
#define LONG_STRING     5

#define DEBUG_MODE      1   // 0 to turn off debug print msgs

#define DBG_MSG_0(x)            { if (DEBUG_MODE) { msg((x)); }}
#define DBG_MSG_1(x, a)         { if (DEBUG_MODE) { msg(sprintf((x), (a))); }}
#define DBG_MSG_2(x, a, b)      { if (DEBUG_MODE) { msg(sprintf((x), (a), (b))); }}
#define DBG_MSG_3(x, a, b, c)   { if (DEBUG_MODE) { msg(sprintf((x), (a), (b), (c))); }}
#define ASSERT(x, a)            { if (DEBUG_MODE && !(x)) { warning(x); return 0; }}
#define MAP_NAME(x, a, b)       { if ((a) == (x)) { return (b); }}

static AddDelphiStrRecs()
{
    auto sid;    // struct ID

    // StrRec record in Delphi rtl\sys\System.pas
    // All structs is same in Delphi 32 and 64

    // Delphi Old AnsiString (LongString)
    sid = get_struc_id(LONG_STRREC);
    if (BADADDR == sid)
    {
        sid = add_struc(-1, LONG_STRREC, 0);
        if (BADADDR == sid)
        {
            DBG_MSG("Could not create "LONG_STRREC"\n");
            return 0;
        }

        add_struc_member(sid, "refCnt", 0, FF_DATA | FF_DWORD, -1, 4);
        add_struc_member(sid, "length", 0x4, FF_DATA | FF_DWORD, -1, 4);
        add_struc_member(sid, "Data", 0x8, FF_DATA | FF_STRLIT, STRTYPE_C, 0);
    }

    // AnsiString, RawByteString, Utf8String
    sid = get_struc_id(ANSI_STRREC);
    if (BADADDR == sid)
    {
        sid = add_struc(-1, ANSI_STRREC, 0);
        if (BADADDR == sid)
        {
            DBG_MSG("Could not create "ANSI_STRREC"\n");
            return 0;
        }
        add_struc_member(sid, "codePage", 0, FF_DATA | FF_WORD, -1, 2);
        add_struc_member(sid, "elemSize", 2, FF_DATA | FF_WORD, -1, 2);
        add_struc_member(sid, "refCnt", 4, FF_DATA | FF_DWORD, -1, 4);
        add_struc_member(sid, "length", 8, FF_DATA | FF_DWORD, -1, 4);
        add_struc_member(sid, "Data", 12, FF_DATA | FF_STRLIT, STRTYPE_C, 0);
    }

    // UnicodeString
    sid = get_struc_id(UNICODE_STRREC);
    if (BADADDR == sid)
    {
        sid = add_struc(-1, UNICODE_STRREC, 0);
        if (BADADDR == sid)
        {
            DBG_MSG("Could not create "UNICODE_STRREC"\n");
            return 0;
        }

        add_struc_member(sid, "codePage", 0, FF_DATA | FF_WORD, -1, 2);
        add_struc_member(sid, "elemSize", 2, FF_DATA | FF_WORD, -1, 2);
        add_struc_member(sid, "refCnt", 4, FF_DATA | FF_DWORD, -1, 4);
        add_struc_member(sid, "length", 8, FF_DATA | FF_DWORD, -1, 4);
        add_struc_member(sid, "Data", 12, FF_DATA | FF_STRLIT, STRTYPE_C_16, 0);
    }

    return 1;
}

// IDC language not support switch-case :(
static getStringType(st)
{
    ASSERT((UNICODE_STRING <= st) && (st <= LONG_STRING), sprintf("Script bug - Unknown string type %d\n", st));

    MAP_NAME(st, UNICODE_STRING, "UnicodeString");
    MAP_NAME(st, RAWBYTE_STRING, "RawByteString");
    MAP_NAME(st, UTF8_STRING, "Utf8String");
    MAP_NAME(st, ANSI_STRING, "AnsiString");
    MAP_NAME(st, LONG_STRING, "LongString");
    MAP_NAME(st, NOT_STRING, "Not a Delphi string");
}

static isValidCodePage(cp)
{
    return (CP_RAW == cp) ||
           (CP_UTF8 == cp) ||
           (CP_UTF16_LE == cp) ||
           (CP_LATIN_1 == cp) ||
           (CP_THAI == cp) ||
           (CP_JAPANESE == cp) ||
           (CP_CHINESE_1 == cp) ||
           (CP_KOREAN == cp) ||
           (CP_CHINESE_2 == cp) ||
           ((CP_EUROPE <= cp) && (cp <= CP_VIETNAM));
}

static getCodePageName(cp)
{
    ASSERT(isValidCodePage(cp), sprintf("Script bug - Codepage %d not support\n", cp));

    MAP_NAME(cp, CP_RAW, "Raw Codepage");
    MAP_NAME(cp, CP_ACP, "Ansi Codepage");
    MAP_NAME(cp, CP_OEMCP, "OEM Ansi Codepage");

    MAP_NAME(cp, CP_UTF7, "UTF-7");
    MAP_NAME(cp, CP_UTF8, "UTF-8 Unicode");
    MAP_NAME(cp, CP_UTF16_LE, "UTF-16LE Unicode");

    MAP_NAME(cp, CP_LATIN_1, "Windows Latin_1 Greek");
    MAP_NAME(cp, CP_THAI, "Windows Thai");
    MAP_NAME(cp, CP_JAPANESE, "Windows Japanese");
    MAP_NAME(cp, CP_CHINESE_1, "Windows Chinese 1");
    MAP_NAME(cp, CP_KOREAN, "Windows Korean");
    MAP_NAME(cp, CP_CHINESE_2, "Windows Chinese 2");

    MAP_NAME(cp, CP_EUROPE, "Windows Central Europe");
    MAP_NAME(cp, CP_CYRILLIC, "Windows Cyrillic");
    MAP_NAME(cp, CP_WESTERN, "Windows Western");
    MAP_NAME(cp, CP_GREEK, "Windows Greek");
    MAP_NAME(cp, CP_TURKISH, "Windows Turkish");
    MAP_NAME(cp, CP_HEBREW, "Windows Hebrew");
    MAP_NAME(cp, CP_ARABIC, "Windows Arabic");
    MAP_NAME(cp, CP_BALTIC, "Windows Baltic");
    MAP_NAME(cp, CP_VIETNAM, "Windows Vietnamese");
}

static isValidElemSize(es)
{
    return (1 == es) || (2 == es);
}

// Make align group for duplicate bytes at address ea and after
static makeAlign(ea)
{
    auto ia, b, count;

    ia = ea;
    b = get_wide_byte(ia);  // b = 0 or 0xCC or 0x90
    while (b == get_wide_byte(ia + 1))
    {
        ia = ia + 1;
    }

    if (ia > ea)
    {
        // We have some duplicate bytes
        count = ia - ea + 1;    // include byte at ia
        create_align(ea, count, 0);
        DBG_MSG_2("0x%X - make align %d bytes\n", ea, count);
    }
}

// Create a LongString at address ea
// We do not apply string struct at address ea because when decompling, Data member sz string will not displayed :(
static createLongString(ea)
{
    auto len, easz, oldIDAStrType, ret;

    oldIDAStrType = get_inf_attr(INF_STRTYPE);
    set_inf_attr(INF_STRTYPE, STRTYPE_C);

    ret = 0;
    easz = ea + 8;
    len = get_wide_dword(ea + 4);

    del_items(ea, DELIT_SIMPLE, 8);     // Only delete two DWORD, avoid delete len bytes !!!

    create_data(ea, FF_DWORD, 4, BADADDR);
    set_name(ea, sprintf("%s_%X", getStringType(LONG_STRING), ea), SN_NOCHECK | SN_NOWARN);
    set_cmt(ea, "refCnt", 0);

    create_data(ea + 4, FF_DWORD, 4, BADADDR);
    set_cmt(ea + 4, "length", 0);

    // Creat the NULL terminated string, +1 for NULL char
    del_items(easz, DELIT_SIMPLE, len + 1);
    create_strlit(easz, len + 1);
    set_cmt(easz, "Data", 0);

    makeAlign(easz + len + 1);

    set_inf_attr(INF_STRTYPE, oldIDAStrType);

    return 1;
}

static createNewString(ea)
{
    auto cea, sea, codepage, type, esize;
    auto len, easz, oldIDAStrType, ret;

    ret = 0;
    cea = ea - 4;   // codepage
    sea = ea - 2;   // elemSize
    easz = ea + 8;
    len = get_wide_dword(ea + 4);

    del_items(cea, DELIT_SIMPLE, 12);   // Only delete three DWORD, avoid delete len bytes !!!

    codepage = get_wide_word(cea);
    if (CP_UTF16_LE == codepage)
        type = UNICODE_STRING;
    else if (CP_UTF8 == codepage)
        type = UTF8_STRING;
    else if (CP_RAW == codepage)
        type = RAWBYTE_STRING;
    else
        type = ANSI_STRING;

    oldIDAStrType = get_inf_attr(INF_STRTYPE);
    set_inf_attr(INF_STRTYPE, type == UNICODE_STRING ? STRTYPE_C_16 : STRTYPE_C);

    create_data(cea, FF_WORD, 2, BADADDR);
    set_name(cea, sprintf("%s_%X", getStringType(type), cea), SN_NOCHECK | SN_NOWARN);
    set_cmt(cea, getCodePageName(codepage), 0);
    op_dec(cea, 0);     // convert codepage to decimal number

    create_data(sea, FF_WORD, 2, BADADDR);
    set_cmt(sea, "elementSize", 0);
    esize = get_wide_word(sea);

    create_data(ea, FF_DWORD, 4, BADADDR);
    set_cmt(ea, "refCnt", 0);

    create_data(ea + 4, FF_DWORD, 4, BADADDR);
    set_cmt(ea + 4, "length", 0);

    // Creat the NULL terminated string, +1 for NULL char
    del_items(easz, DELIT_SIMPLE, (len + 1) * esize);
    create_strlit(easz, (len + 1) * esize);
    set_cmt(easz, "Data", 0);

    makeAlign(easz + (len + 1) * esize);

    set_inf_attr(INF_STRTYPE, oldIDAStrType);

    return 1;
}

// Check NULL char in the middle of a ansi string
static haveZeroByte(ea, len)
{
    auto ia;
    for (ia = ea; ia < ea + len; ia++)
    {
        if (0 == get_wide_byte(ia))
        {
            return 1;
        }
    }
    return 0;
}

static main()
{
    auto oldstatus, ea, end_ea, nfixed;
    auto easz, codePage, elemSize, strType, ia, len, ret;
    auto funcAtStart, funcAtEnd;

    oldstatus = set_ida_state(IDA_STATUS_THINKING);

    AddDelphiStrRecs();

    nfixed = 0;
    end_ea = get_inf_attr(INF_MAX_EA);

    ea = find_binary(get_inf_attr(INF_MIN_EA), SEARCH_DOWN, "FF FF FF FF");
    while ((ea != BADADDR) && (ea < end_ea))
    {
        strType = NOT_STRING;
        len = get_wide_dword(ea + 4);

        // Check ea and len, 0x7FFFFFFF = MAX_INT
        if ((len > 0) && (0xFFFFFFFF != len) && (len < 0x7FFFFFFF) && (ea + len < end_ea))
        {
            codePage = get_wide_word(ea - 4);
            elemSize = get_wide_word(ea - 2);   // Size in bytes of a character, only can be 1 or 2

            if (isValidElemSize(elemSize) && isValidCodePage(codePage))
            {
                // New Delphi string
                if ((2 == elemSize) && (CP_UTF16_LE == codePage))
                {
                    strType = UNICODE_STRING;
                }
                else
                {
                    // RawByteString and Utf8String internal is 1 byte AnsiString
                    strType = ANSI_STRING;
                }
            }
            else
            {
                // Check for old LongString
                easz = ea + 8;  // 8 = 2 * sizeof(DWORD)
                if (0 == get_wide_byte(easz + len))     // we have NULL char at end
                {
                    funcAtStart = get_func_attr(ea, FUNCATTR_START);
                    funcAtEnd = get_func_attr(easz + len, FUNCATTR_START);

                    if (haveZeroByte(easz, len))
                    {
                        // Outside a function, print msg, else ignore
                        if (funcAtStart == BADADDR)
                        {
                            DBG_MSG_2("0x%X - len = %d - Possible not a Long Delphi string. NULL char in the string\n", ea, len);
                        }
                    }
                    else
                    {
                        if ((funcAtStart != BADADDR) && (funcAtEnd != BADADDR) &&
                            (funcAtStart == funcAtEnd) && (ea > funcAtStart) &&
                            (easz + len <= get_func_attr(funcAtStart, FUNCATTR_END)))
                        {
                            DBG_MSG_1("0x%X - Delphi Long string at the end of function\n", ea);

                        }
                        strType = LONG_STRING;
                    }
                }
            }
        }

        if (NOT_STRING != strType)
        {
            ret = 0;
            if (LONG_STRING == strType)
            {
                ret = createLongString(ea);
            }
            else
            {
                ret = createNewString(ea);
            }

            if (1 == ret)
            {
                nfixed++;
                DBG_MSG_2("0x%X: %s\n", ea + 8, getStringType(strType));
            }
        }

        // Don't skip sizeof(xxxStrRec), we will missing some strings
        // skip 4 bytes 0xFFFFFFFF, search next.
        ea = find_binary(ea + 4, SEARCH_DOWN | SEARCH_NEXT, "FF FF FF FF");
    }

    set_ida_state(oldstatus);

    DBG_MSG_1("\nDone. Found and fixed %d strings.\n", nfixed);
}
