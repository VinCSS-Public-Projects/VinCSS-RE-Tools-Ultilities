/*
 * From https://github.com/Yara-Rules/rules
 * This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
 * and open to any user or organization, as long as you use it under this license.
 * Add another rules from many sources by HTC (VinCSS)
**/

rule Big_Numbers0
{
    meta:
        author = "_pusher_"
        description = "Looks for big numbers 20:sized"
        date = "2016-07"
    strings:
        $c0 = /[0-9a-fA-F]{20}/ fullword ascii
    condition:
        $c0
}

rule Big_Numbers1
{
    meta:
        author = "_pusher_"
        description = "Looks for big numbers 32:sized"
        date = "2016-07"
    strings:
        $c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
    condition:
        $c0
}

rule Big_Numbers2
{
    meta:
        author = "_pusher_"
        description = "Looks for big numbers 48:sized"
        date = "2016-07"
    strings:
        $c0 = /[0-9a-fA-F]{48}/ fullword wide ascii
    condition:
        $c0
}

rule Big_Numbers3
{
    meta:
        author = "_pusher_"
        description = "Looks for big numbers 64:sized"
        date = "2016-07"
    strings:
            $c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
    condition:
        $c0
}

rule Big_Numbers4
{
    meta:
        author = "_pusher_"
        description = "Looks for big numbers 128:sized"
        date = "2016-08"
    strings:
            $c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
    condition:
        $c0
}

rule Big_Numbers5
{
    meta:
        author = "_pusher_"
        description = "Looks for big numbers 256:sized"
        date = "2016-08"
    strings:
            $c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
    condition:
        $c0
}

rule Prime_Constants_char {
    meta:
        author = "_pusher_"
        description = "List of primes [char]"
        date = "2016-07"
    strings:
        $c0 = { 03 05 07 0B 0D 11 13 17 1D 1F 25 29 2B 2F 35 3B 3D 43 47 49 4F 53 59 61 65 67 6B 6D 71 7F 83 89 8B 95 97 9D A3 A7 AD B3 B5 BF C1 C5 C7 D3 DF E3 E5 E9 EF F1 FB }
    condition:
        $c0
}

rule Prime_Constants_long {
    meta:
        author = "_pusher_"
        description = "List of primes [long]"
        date = "2016-07"
    strings:
        $c0 = { 03 00 00 00 05 00 00 00 07 00 00 00 0B 00 00 00 0D 00 00 00 11 00 00 00 13 00 00 00 17 00 00 00 1D 00 00 00 1F 00 00 00 25 00 00 00 29 00 00 00 2B 00 00 00 2F 00 00 00 35 00 00 00 3B 00 00 00 3D 00 00 00 43 00 00 00 47 00 00 00 49 00 00 00 4F 00 00 00 53 00 00 00 59 00 00 00 61 00 00 00 65 00 00 00 67 00 00 00 6B 00 00 00 6D 00 00 00 71 00 00 00 7F 00 00 00 83 00 00 00 89 00 00 00 8B 00 00 00 95 00 00 00 97 00 00 00 9D 00 00 00 A3 00 00 00 A7 00 00 00 AD 00 00 00 B3 00 00 00 B5 00 00 00 BF 00 00 00 C1 00 00 00 C5 00 00 00 C7 00 00 00 D3 00 00 00 DF 00 00 00 E3 00 00 00 E5 00 00 00 E9 00 00 00 EF 00 00 00 F1 00 00 00 FB 00 00 00 }
    condition:
        $c0
}

rule BigLib_BigMod {
    meta:
        author = "_pusher_"
        description = "Look for BigLib BigMod"
        date = "2016-10"
    strings:
        $c0 = { 55 8B EC 83 C4 FC 53 51 57 56 8B 7D 0C 8B 1F 85 DB 0F 84 F7 00 00 00 8B 75 08 8B 0E 85 C9 0F 84 F7 00 00 00 FF 75 0C FF 75 08 E8 ?? ?? ?? ?? 0F 8C FA 00 00 00 0F 84 E0 00 00 00 6A 00 E8 ?? ?? ?? ?? 89 45 FC C1 E1 05 49 8B 7D FC C7 07 01 00 00 00 0F A3 4E 04 72 03 49 EB F7 8B 17 8D 5F 04 F8 90 D1 13 8D 5B 04 4A 75 F8 73 04 FF 03 FF 07 0F A3 4E 04 0F 92 C0 08 47 04 8B 55 0C 8B 1A 39 1F 72 67 77 1D 51 8B 0F 8D 1C 8D 00 00 00 00 03 FB 8B F2 03 F3 FD F3 A7 FC 59 8B 75 08 8B 7D FC 77 48 51 8B 75 0C 8B 1F 8B 0E 2B D9 83 C6 04 83 C7 04 F8 8D 49 00 8B 16 19 17 8D 76 04 8D 7F 04 49 75 F3 73 0A 90 83 1F 00 8D 7F 04 4B 72 F7 8B 75 FC 83 7F FC 00 75 0B FF 0E 74 05 83 EF 04 EB F1 FF 06 59 8B 75 08 8B 7D FC 49 0F 89 6A FF FF FF FF 75 10 FF 75 FC E8 ?? ?? ?? ?? FF 75 FC E8 ?? ?? ?? ?? 33 C0 5E 5F 59 5B C9 C2 0C 00 B8 FF FF FF FF 5E 5F 59 5B C9 C2 0C 00 8B 7D 10 33 C0 8B 0F 41 F3 AB 33 C0 5E 5F 59 5B C9 C2 0C 00 }
    condition:
        $c0
}

rule BigLib_BigPowMod {
    meta:
        author = "_pusher_"
        description = "Look for BigLib BigPowMod"
        date = "2016-10"
    strings:
        $c0 = { 55 8B EC 53 51 57 56 8B 5D 10 83 3B 00 74 5D 6A 01 E8 ?? ?? ?? ?? 8B F8 8B 75 0C 8B 0E 85 C9 74 32 C1 E1 05 49 8D 49 00 57 57 57 E8 ?? ?? ?? ?? 57 53 57 E8 ?? ?? ?? ?? 0F A3 4E 04 73 12 57 FF 75 08 57 E8 ?? ?? ?? ?? 57 53 57 E8 ?? ?? ?? ?? 49 79 D5 FF 75 14 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 33 C0 5E 5F 59 5B C9 C2 10 00 B8 FF FF FF FF 5E 5F 59 5B C9 C2 10 00 }
    condition:
        $c0
}

rule Advapi_Hash_API {
    meta:
        author = "_pusher_"
        description = "Looks for advapi API functions"
        date = "2016-07"
    strings:
        $advapi32 = "advapi32.dll" wide ascii nocase
        $CryptCreateHash = "CryptCreateHash" wide ascii
        $CryptHashData = "CryptHashData" wide ascii
        $CryptAcquireContext = "CryptAcquireContext" wide ascii
    condition:
        $advapi32 and ($CryptCreateHash and $CryptHashData and $CryptAcquireContext)
}

rule Crypt32_CryptBinaryToString_API {
    meta:
        author = "_pusher_"
        description = "Looks for crypt32 CryptBinaryToStringA function"
        date = "2016-08"
    strings:
        $crypt32 = "crypt32.dll" wide ascii nocase
        $CryptBinaryToStringA = "CryptBinaryToStringA" wide ascii
    condition:
        $crypt32 and ($CryptBinaryToStringA)
}

rule MurmurHash3_Constants {
    meta:
        author = "_pusher_"
        description = "Look for MurmurHash3 constants"
        date = "2017-05"
        version = "0.1"
    strings:
        $c0 = { 512D9ECC }
        $c1 = { 9335871B }
        //N
        $c2 = { 6BCAEB85 }
        $c3 = { 35AEB2C2 }
    condition:
        all of them
}

rule CRC32c_poly_Constant {
    meta:
        author = "_pusher_"
        description = "Look for CRC32c (Castagnoli) [poly]"
        date = "2016-08"
    strings:
        $c0 = { 783BF682 }
    condition:
        $c0
}

rule CRC32_poly_Constant {
    meta:
        author = "_pusher_"
        description = "Look for CRC32 [poly]"
        date = "2015-05"
        version = "0.1"
    strings:
        $c0 = { 2083B8ED }
    condition:
        $c0
}

rule CRC32_table {
    meta:
        author = "_pusher_"
        description = "Look for CRC32 table"
        date = "2015-05"
        version = "0.1"
    strings:
        $c0 = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 }
    condition:
        $c0
}

rule CRC32_table_lookup {
    meta:
        author = "_pusher_"
        description = "CRC32 table lookup"
        date = "2015-06"
        version = "0.1"
    strings:
        $c0 = { 8B 54 24 08 85 D2 7F 03 33 C0 C3 83 C8 FF 33 C9 85 D2 7E 29 56 8B 74 24 08 57 8D 9B 00 00 00 00 0F B6 3C 31 33 F8 81 E7 FF 00 00 00 C1 E8 08 33 04 BD ?? ?? ?? ?? 41 3B CA 7C E5 5F 5E F7 D0 C3 }
    condition:
        $c0
}

rule CRC32b_poly_Constant {
    meta:
        author = "_pusher_"
        description = "Look for CRC32b [poly]"
        date = "2016-04"
        version = "0.1"
    strings:
        $c0 = { B71DC104 }
    condition:
        $c0
}


rule CRC16_table {
    meta:
        author = "_pusher_"
        description = "Look for CRC16 table"
        date = "2016-04"
        version = "0.1"
    strings:
        $c0 = { 00 00 21 10 42 20 63 30 84 40 A5 50 C6 60 E7 70 08 81 29 91 4A A1 6B B1 8C C1 AD D1 CE E1 EF F1 31 12 10 02 73 32 52 22 B5 52 94 42 F7 72 D6 62 39 93 18 83 7B B3 5A A3 BD D3 9C C3 FF F3 DE E3 }
    condition:
        $c0
}


rule FlyUtilsCnDES_ECB_Encrypt {
    meta:
        author = "_pusher_"
        description = "Look for FlyUtils.CnDES Encrypt ECB function"
        date = "2016-07"
    strings:
        $c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D E8 89 5D EC 8B D9 89 55 F8 89 45 FC 8B 7D 08 8B 75 20 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 80 7D 18 00 74 1A 0F B6 55 18 8D 4D EC 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 EC 8D 45 F8 E8 ?? ?? ?? ?? 80 7D 1C 00 74 1A 0F B6 55 1C 8D 4D E8 8B 45 FC E8 ?? ?? ?? ?? 8B 55 E8 8D 45 FC E8 ?? ?? ?? ?? 85 DB 75 07 E8 ?? ?? ?? ?? 8B D8 85 F6 75 07 E8 ?? ?? ?? ?? 8B F0 53 6A 00 8B 4D FC B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 8B 45 F4 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 6A 00 33 C9 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F0 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 56 }
    condition:
        $c0
}

rule FlyUtilsCnDES_ECB_Decrypt {
    meta:
        author = "_pusher_"
        description = "Look for FlyUtils.CnDES Decrypt ECB function"
        date = "2016-07"
    strings:
        $c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D E8 89 5D EC 8B F9 89 55 F8 89 45 FC 8B 5D 18 8B 75 20 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 84 DB 74 18 8B D3 8D 4D EC 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 EC 8D 45 F8 E8 ?? ?? ?? ?? 85 FF 75 07 E8 ?? ?? ?? ?? 8B F8 85 F6 75 07 E8 ?? ?? ?? ?? 8B F0 8B 4D FC B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 57 6A 00 33 C9 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F0 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 FF 75 14 FF 75 10 8B 45 0C 50 8B 4D F8 8B 55 F0 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 6A 00 8B 45 F0 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 08 8B 45 F0 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB 12 E9 ?? ?? ?? ?? 8B 45 08 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F0 33 D2 89 55 F0 E8 ?? ?? ?? ?? C3 }
    condition:
        $c0
}

rule Elf_Hash {
    meta:
        author = "_pusher_"
        description = "Look for ElfHash"
        date = "2015-06"
        version = "0.3"
    strings:
        $c0 = { 53 56 33 C9 8B DA 4B 85 DB 7C 25 43 C1 E1 04 33 D2 8A 10 03 CA 8B D1 81 E2 00 00 00 F0 85 D2 74 07 8B F2 C1 EE 18 33 CE F7 D2 23 CA 40 4B 75 DC 8B C1 5E 5B C3 }
        $c1 = { 53 33 D2 85 C0 74 2B EB 23 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 D7 8B C2 5B C3 }
        $c2 = { 53 56 33 C9 8B D8 85 D2 76 23 C1 E1 04 33 C0 8A 03 03 C8 8B C1 25 00 00 00 F0 85 C0 74 07 8B F0 C1 EE 18 33 CE F7 D0 23 C8 43 4A 75 DD 8B C1 5E 5B C3 }
        $c3 = { 53 56 57 8B F2 8B D8 8B FB 53 E8 ?? ?? ?? ?? 6B C0 02 71 05 E8 ?? ?? ?? ?? 8B D7 33 C9 8B D8 83 EB 01 71 05 E8 ?? ?? ?? ?? 85 DB 7C 2C 43 C1 E1 04 0F B6 02 03 C8 71 05 E8 ?? ?? ?? ?? 83 C2 01 B8 00 00 00 F0 23 C1 85 C0 74 07 8B F8 C1 EF 18 33 CF F7 D0 23 C8 4B 75 D5 8B C1 99 F7 FE 8B C2 85 C0 7D 09 03 C6 71 05 E8 ?? ?? ?? ?? 5F 5E 5B C3 }
        $c4 = { 53 33 D2 EB 2C 8B D9 80 C3 BF 80 EB 1A 73 03 80 C1 20 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 CE 8B C2 5B C3 }
        $c5 = { 89 C2 31 C0 85 D2 74 30 2B 42 FC 74 2B 89 C1 29 C2 31 C0 53 0F B6 1C 11 01 C3 8D 04 1B C1 EB 14 8D 04 C5 00 00 00 00 81 E3 00 0F 00 00 31 D8 83 C1 01 75 E0 C1 E8 04 5B C3 }
        $c6 = { 53 33 D2 85 C0 74 38 EB 30 8B D9 80 C3 BF 80 EB 1A 73 03 80 C1 20 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 CA 8B C2 5B C3 }
    condition:
        any of them
}

rule BLOWFISH_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for Blowfish constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { D1310BA6 }
        $c1 = { A60B31D1 }
        $c2 = { 98DFB5AC }
        $c3 = { ACB5DF98 }
        $c4 = { 2FFD72DB }
        $c5 = { DB72FD2F }
        $c6 = { D01ADFB7 }
        $c7 = { B7DF1AD0 }
        $c8 = { 4B7A70E9 }
        $c9 = { E9707A4B }
        $c10 = { F64C261C }
        $c11 = { 1C264CF6 }
    condition:
        6 of them
}

rule MD5_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for MD5 constants"
        date = "2014-01"
        version = "0.2"
    strings:
        // Init constants
        $c0 = { 67452301 }
        $c1 = { efcdab89 }
        $c2 = { 98badcfe }
        $c3 = { 10325476 }
        $c4 = { 01234567 }
        $c5 = { 89ABCDEF }
        $c6 = { FEDCBA98 }
        $c7 = { 76543210 }
        // Round 2
        $c8 = { F4D50d87 }
        $c9 = { 78A46AD7 }
    condition:
        5 of them
}

rule MD5_API {
    meta:
        author = "_pusher_"
        description = "Looks for MD5 API"
        date = "2016-07"
    strings:
        $advapi32 = "advapi32.dll" wide ascii nocase
        $cryptdll = "cryptdll.dll" wide ascii nocase
        $MD5Init = "MD5Init" wide ascii
        $MD5Update = "MD5Update" wide ascii
        $MD5Final = "MD5Final" wide ascii
    condition:
        ($advapi32 or $cryptdll) and ($MD5Init and $MD5Update and $MD5Final)
}

rule RC6_Constants {
    meta:
        author = "chort (@chort0)"
        description = "Look for RC6 magic constants in binary"
        reference = "https://twitter.com/mikko/status/417620511397400576"
        reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
        date = "2013-12"
        version = "0.2"
    strings:
        $c1 = { B7E15163 }
        $c2 = { 9E3779B9 }
        $c3 = { 6351E1B7 }
        $c4 = { B979379E }
    condition:
        2 of them
}


rule RIPEMD128_Constants {
    meta:
        author = "_pusher_"
        description = "Look for RIPEMD constants"
        date = "2017-05"
        version = "0.1"
    strings:
        $c0 = { 01234567 }
        $c1 = { 89ABCDEF }
        $c2 = { FEDCBA98 }
        $c3 = { 76543210 }
        $c4 = { 9979825A }
        $c5 = { A1EBD96E }

        $c6 = { DCBC1B8F }
        $c7 = { E68BA250 }
        $c8 = { 24D14D5C }
        $c9 = { F33E706D }

        //not ripemd128 if:
        //$a0 = { 4EFD53A9 }
        //$a1 = { E9766D7A }
    condition:
        all of ($c*)
}


rule RIPEMD160_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for RIPEMD-160 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 67452301 }
        $c1 = { EFCDAB89 }
        $c2 = { 98BADCFE }
        $c3 = { 10325476 }
        $c4 = { C3D2E1F0 }
        $c5 = { 01234567 }
        $c6 = { 89ABCDEF }
        $c7 = { FEDCBA98 }
        $c8 = { 76543210 }
        $c9 = { F0E1D2C3 }
    condition:
        5 of them
}

rule SHA1_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for SHA1 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 67452301 }
        $c1 = { EFCDAB89 }
        $c2 = { 98BADCFE }
        $c3 = { 10325476 }
        $c4 = { C3D2E1F0 }
        $c5 = { 01234567 }
        $c6 = { 89ABCDEF }
        $c7 = { FEDCBA98 }
        $c8 = { 76543210 }
        $c9 = { F0E1D2C3 }
        //added by _pusher_ 2016-07 - last round
        $c10 = { D6C162CA }
    condition:
        5 of them
}

rule SHA512_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for SHA384/SHA512 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 428a2f98 }
        $c1 = { 982F8A42 }
        $c2 = { 71374491 }
        $c3 = { 91443771 }
        $c4 = { B5C0FBCF }
        $c5 = { CFFBC0B5 }
        $c6 = { E9B5DBA5 }
        $c7 = { A5DBB5E9 }
        $c8 = { D728AE22 }
        $c9 = { 22AE28D7 }
    condition:
        5 of them
}

rule SHA2_BLAKE2_IVs {
    meta:
        author = "spelissier"
        description = "Look for SHA2/BLAKE2/Argon2 IVs"
        date = "2019-12"
        version = "0.1"
    strings:
        $c0 = { 67 E6 09 6A }
        $c1 = { 85 AE 67 BB }
        $c2 = { 72 F3 6E 3C }
        $c3 = { 3A F5 4F A5 }
        $c4 = { 7F 52 0E 51 }
        $c5 = { 8C 68 05 9B }
        $c6 = { AB D9 83 1F }
        $c7 = { 19 CD E0 5B }

    condition:
        all of them
}

rule TEAN {
    meta:
        author = "_pusher_"
        description = "Look for TEA Encryption"
        date = "2016-08"
    strings:
        $c0 = { 2037EFC6 }
    condition:
        $c0
}

rule WHIRLPOOL_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for WhirlPool constants"
        date = "2014-02"
        version = "0.1"
    strings:
        $c0 = { 18186018c07830d8 }
        $c1 = { d83078c018601818 }
        $c2 = { 23238c2305af4626 }
        $c3 = { 2646af05238c2323 }
    condition:
        2 of them
}

rule DarkEYEv3_Cryptor {
    meta:
        description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
        author = "Florian Roth"
        reference = "http://darkeyev3.blogspot.fi/"
        date = "2015-05-24"
        hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
        hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
        hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
        hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
        hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
        hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
        hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
        hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
        hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"
        score = 55
    strings:
        $s0 = "\\DarkEYEV3-"
    condition:
        uint16(0) == 0x5a4d and $s0
}

rule Miracl_powmod
{   meta:
        author = "Maxx"
        description = "Miracl powmod"
    strings:
        $c0 = { 53 55 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 0F 85 EC 01 00 00 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 12 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 06 8B 4E 10 3B C1 74 2E 8B 7C 24 1C 57 E8 ?? ?? ?? ?? 83 C4 04 83 F8 02 7C 33 8B 57 04 8B 0E 51 8B 02 50 E8 ?? ?? ?? ?? 83 C4 08 83 F8 01 0F 84 58 01 00 00 EB 17 8B 7C 24 1C 6A 02 57 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 3F 01 00 00 8B 8E C4 01 00 00 8B 54 24 18 51 52 E8 ?? ?? ?? ?? 8B 86 CC }
    condition:
        $c0
}

rule Miracl_crt
{   meta:
        author = "Maxx"
        description = "Miracl crt"
    strings:
        $c0 = { 51 56 57 E8 ?? ?? ?? ?? 8B 74 24 10 8B F8 89 7C 24 08 83 7E 0C 02 0F 8C 99 01 00 00 8B 87 18 02 00 00 85 C0 0F 85 8B 01 00 00 8B 57 1C 42 8B C2 89 57 1C 83 F8 18 7D 17 C7 44 87 20 4A 00 00 00 8B 87 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 46 04 8B 54 24 14 53 55 8B 08 8B 02 51 50 E8 ?? ?? ?? ?? 8B 4E 0C B8 01 00 00 00 83 C4 08 33 ED 3B C8 89 44 24 18 0F 8E C5 00 00 00 BF 04 00 00 00 8B 46 04 8B 0C 07 8B 10 8B 44 24 1C 51 52 8B 0C 07 51 E8 ?? ?? ?? ?? 8B 56 04 8B 4E 08 8B 04 }
    condition:
        $c0
}

rule CryptoPP_a_exp_b_mod_c
{   meta:
        author = "Maxx"
        description = "CryptoPP a_exp_b_mod_c"
    strings:
        $c0 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC ?? 00 00 00 56 8B B4 24 B0 00 00 00 57 6A 00 8B CE C7 44 24 0C 00 00 00 00 E8 ?? ?? ?? ?? 84 C0 0F 85 16 01 00 00 8D 4C 24 24 E8 ?? ?? ?? ?? BF 01 00 00 00 56 8D 4C 24 34 89 BC 24 A4 00 00 00 E8 ?? ?? ?? ?? 8B 06 8D 4C 24 3C 50 6A 00 C6 84 24 A8 00 00 00 02 E8 ?? ?? ?? ?? 8D 4C 24 48 C6 84 24 A0 00 00 00 03 E8 ?? ?? ?? ?? C7 44 24 24 ?? ?? ?? ?? 8B 8C 24 AC 00 00 00 8D 54 24 0C 51 52 8D 4C 24 2C C7 84 24 A8 }
        $c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 4C 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 70 8D 4C 24 18 56 89 7C 24 60 E8 ?? ?? ?? ?? 8B 76 08 8D 4C 24 2C 56 57 C6 44 24 64 01 E8 ?? ?? ?? ?? 8D 4C 24 40 C6 44 24 5C 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 4C 24 6C 8B 54 24 68 8B 74 24 64 51 52 56 8D 4C 24 18 C7 44 24 68 03 00 00 00 E8 ?? ?? ?? ?? 8B 7C 24 4C 8B 4C 24 48 8B D7 33 C0 F3 }
        $c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 34 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 58 8D 4C 24 18 56 89 7C 24 48 E8 ?? ?? ?? ?? 8B 0E C6 44 24 44 01 51 57 8D 4C 24 2C E8 ?? ?? ?? ?? 8D 4C 24 30 C6 44 24 44 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 54 24 54 8B 44 24 50 8B 74 24 4C 52 50 56 8D 4C 24 18 C7 44 24 50 03 00 00 00 E8 ?? ?? ?? ?? 8B 4C 24 30 8B 7C 24 34 33 C0 F3 AB 8B 4C }
    condition:
        any of them
}

rule CryptoPP_modulo
{   meta:
        author = "Maxx"
        description = "CryptoPP modulo"
    strings:
        $c0 = { 83 EC 20 53 55 8B 6C 24 2C 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 04 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 04 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 04 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 34 33 C9 53 0B CA 55 }
        $c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 56 57 8B F1 33 FF 8D 4C 24 20 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 0C 89 7C 24 3C E8 ?? ?? ?? ?? 8B 44 24 48 8D 4C 24 0C 50 56 8D 54 24 28 51 52 C6 44 24 4C 01 E8 ?? ?? ?? ?? 8B 74 24 54 83 C4 10 8D 44 24 20 8B CE 50 E8 ?? ?? ?? ?? 8B 7C 24 18 8B 4C 24 14 8B D7 33 C0 F3 AB 52 E8 ?? ?? ?? ?? 8B 7C 24 30 8B 4C 24 2C 8B D7 33 C0 C7 44 24 10 ?? ?? ?? ?? 52 F3 AB E8 ?? ?? ?? ?? 8B 4C 24 3C 83 C4 08 8B C6 64 89 }
        $c2 = { 83 EC 24 53 55 8B 6C 24 30 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 0C 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 0C 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 0C 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 38 33 C9 53 0B CA 55 }
        $c3 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 1C 56 57 8B F1 33 FF 8D 4C 24 0C 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 18 89 7C 24 2C E8 ?? ?? ?? ?? 8B 44 24 38 8D 4C 24 18 50 56 8D 54 24 14 51 52 C6 44 24 3C 01 E8 ?? ?? ?? ?? 8B 74 24 44 83 C4 10 8D 44 24 0C 8B CE 50 E8 ?? ?? ?? ?? 8B 4C 24 18 8B 7C 24 1C 33 C0 F3 AB 8B 4C 24 1C 51 E8 ?? ?? ?? ?? 8B 4C 24 10 8B 7C 24 14 33 C0 F3 AB 8B 54 24 14 52 E8 ?? ?? ?? ?? 8B 4C 24 2C 83 C4 08 8B C6 64 89 0D 00 00 00 }
    condition:
        any of them
}

rule FGint_MontgomeryModExp
{   meta:
        author = "_pusher_"
        date = "2015-06"
        version = "0.2"
        description = "FGint MontgomeryModExp"
    strings:
        $c0 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
        $c1 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
        $c2 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 ?? E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
        $c3 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 D0 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 47 4C 47 00 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 D0 E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 02 02 00 00 }
    condition:
        any of them
}

rule FGint_FGIntModExp
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint FGIntModExp"
    strings:
        $c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D ?? 8B F1 89 55 ?? 8B D8 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 46 04 8B 40 04 83 E0 01 83 F8 01 75 0F 57 8B CE 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? EB ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 F4 8B C3 E8 ?? ?? ?? ?? 8B 45 }
    condition:
        $c0
}

rule FGint_MulByInt
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint MulByInt"
    strings:
        $c0 = { 53 56 57 55 83 C4 E8 89 4C 24 04 8B EA 89 04 24 8B 04 24 8B 40 04 8B 00 89 44 24 08 8B 44 24 08 83 C0 02 50 8D 45 04 B9 01 00 00 00 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 04 33 F6 8B 7C 24 08 85 FF 76 6D BB 01 00 00 00 8B 04 24 8B 40 04 8B 04 98 33 D2 89 44 24 10 89 54 24 14 8B 44 24 04 33 D2 52 50 8B 44 24 18 8B 54 24 1C ?? ?? ?? ?? ?? 89 44 24 10 89 54 24 14 8B C6 33 D2 03 44 24 10 13 54 24 14 89 44 24 10 89 54 24 14 8B 44 24 10 25 FF FF FF 7F 8B 55 04 89 04 9A 8B 44 24 10 8B 54 24 14 0F AC D0 1F C1 EA 1F 8B F0 43 4F 75 98 }
    condition:
        $c0
}

rule FGint_DivMod
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint FGIntDivMod"
    strings:
        $c0 = { 55 8B EC 83 C4 BC 53 56 57 8B F1 89 55 F8 89 45 FC 8B 5D 08 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 FC 8A 00 88 45 D7 8B 45 F8 8A 00 88 45 D6 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B D3 8B 45 FC E8 ?? ?? ?? ?? 8D 55 E0 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 F8 8B 45 FC }
    condition:
        $c0
}

rule FGint_FGIntDestroy
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint FGIntDestroy"
    strings:
        $c0 = { 53 8B D8 8D 43 04 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B C3 }
    condition:
        $c0
}

rule FGint_Base10StringToGInt
{   meta:
        author = "_pusher_"
        date = "2015-06"
        version = "0.2"
        description = "FGint Base10StringToGInt"
    strings:
        $c0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 8B DA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC ?? ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC ?? ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? EB 18 C6 45 EB 01 EB 12 8D 45 FC }
        $c1 = { 55 8B EC 83 C4 D8 53 56 57 33 C9 89 4D D8 89 4D DC 89 4D E0 89 4D E4 89 4D EC 8B DA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 0F 42 45 00 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC E8 ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 45 E4 BA 28 42 45 00 E8 ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? EB 18 C6 45 EB 01 }
        $c2 = { 55 8B EC 83 C4 D8 53 56 33 C9 89 4D D8 89 4D DC 89 4D E0 89 4D F8 89 4D F4 8B DA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 A6 32 47 00 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 8B 45 FC 0F B6 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC E8 ?? ?? ?? ?? 48 7F D3 8D 45 E0 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 45 E0 BA BC 32 47 00 E8 ?? ?? ?? ?? 75 18 C6 45 E9 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? EB 18 C6 45 E9 01 }

    condition:
        any of them
}

rule FGint_ConvertBase256to64
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint ConvertBase256to64"
    strings:
        $c0 = { 55 8B EC 81 C4 EC FB FF FF 53 56 57 33 C9 89 8D EC FB FF FF 89 8D F0 FB FF FF 89 4D F8 8B FA 89 45 FC B9 00 01 00 00 8D 85 F4 FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 F4 FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 7E 2F BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F4 FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E5 EB }
    condition:
        $c0
}

rule FGint_ConvertHexStringToBase256String
{   meta:
        author = "_pusher_"
        date = "2015-06"
        version = "0.2"
        description = "FGint ConvertHexStringToBase256String"
    strings:
        $c0 = { 55 8B EC 83 C4 F0 53 56 33 C9 89 4D F0 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? D1 F8 79 03 83 D0 00 85 C0 7E 5F 89 45 F4 BE 01 00 00 00 8B C6 03 C0 8B 55 FC 8A 54 02 FF 8B 4D FC 8A 44 01 FE 3C 3A 73 0A 8B D8 80 EB 30 C1 E3 04 EB 08 8B D8 80 EB 37 C1 E3 04 80 FA 3A 73 07 80 EA 30 0A DA EB 05 80 EA 37 0A DA 8D 45 F0 8B D3 }
        $c1 = { 55 8B EC 83 C4 EC 53 56 33 C9 89 4D EC 89 4D F4 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 ?? ?? ?? ?? 79 05 48 83 C8 FE 40 48 75 12 8D 45 F4 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 0B 8D 45 F4 8B 55 FC E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? D1 F8 79 03 83 D0 00 85 C0 7E 62 89 45 F0 BE ?? ?? ?? ?? 8B C6 03 C0 8B 55 F4 8A 54 02 FF 8B 4D F4 8A 44 01 FE 3C 3A 73 0A 8B D8 80 EB 30 C1 E3 04 EB 08 8B D8 80 EB 37 C1 E3 04 80 FA 3A 73 07 80 EA 30 0A DA EB 08 80 EA 37 80 E2 0F 0A DA 8D 45 EC 8B D3 }
    condition:
        any of them
}

rule FGint_Base256StringToGInt
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint Base256StringToGInt"
    strings:
        $c0 = { 55 8B EC 81 C4 F8 FB FF FF 53 56 57 33 C9 89 4D F8 8B FA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? B9 00 01 00 00 8D 85 F8 FB FF FF 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F8 ?? ?? ?? ?? ?? 8D 85 F8 FB FF FF BA FF 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC ?? ?? ?? ?? ?? 8B D8 85 DB 7E 34 BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F8 FB FF FF ?? ?? ?? ?? ?? 46 4B 75 E5 EB 12 8D 45 F8 B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 F8 80 38 30 75 0F }
    condition:
        $c0
}

rule FGint_FGIntToBase256String
{   meta:
        author = "_pusher_"
        date = "2015-06"
        version = "0.2"
        description = "FGint FGIntToBase256String"
    strings:
        $c0 = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4B 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 8A 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 4B 75 B5 }
        $c1 = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC 85 C0 74 05 83 E8 04 8B 00 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4C 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 0F B6 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 }
    condition:
        any of them
}

rule FGint_ConvertBase256StringToHexString
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint ConvertBase256StringToHexString"
    strings:
        $c0 = { 55 8B EC 33 C9 51 51 51 51 51 51 53 56 57 8B F2 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C6 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B F8 85 FF 0F 8E AB 00 00 00 C7 45 F8 01 00 00 00 8B 45 FC 8B 55 F8 8A 5C 10 FF 33 C0 8A C3 C1 E8 04 83 F8 0A 73 1E 8D 45 F4 33 D2 8A D3 C1 EA 04 83 C2 30 E8 ?? ?? ?? ?? 8B 55 F4 8B C6 E8 ?? ?? ?? ?? EB 1C 8D 45 F0 33 D2 8A D3 C1 EA 04 83 C2 37 E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8B C3 24 0F 3C 0A 73 22 8D 45 EC 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 30 E8 ?? ?? ?? ?? 8B 55 EC 8B C6 E8 ?? ?? ?? ?? EB 20 8D 45 E8 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 37 }
    condition:
        $c0
}


rule FGint_PGPConvertBase256to64
{   meta:
        author = "_pusher_"
        date = "2016-08"
        description = "FGint PGPConvertBase256to64"
    strings:
        $c0 = { 55 8B EC 81 C4 E8 FB FF FF 53 56 57 33 C9 89 8D E8 FB FF FF 89 4D F8 89 4D F4 89 4D F0 8B FA 89 45 FC B9 00 01 00 00 8D 85 EC FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 EC FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC 8B 00 E8 ?? ?? ?? ?? 8B D8 85 DB 7E 22 BE 01 00 00 00 8D 45 F8 8B 55 FC 8B 12 0F B6 54 32 FF 8B 94 95 EC FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E3 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 85 D2 75 0A 8D 45 F0 E8 ?? ?? ?? ?? EB 4B 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 83 FA 04 75 1C 8D 45 F8 BA 4C 33 40 00 E8 ?? ?? ?? ?? 8D 45 F0 BA 58 33 40 00 E8 ?? ?? ?? ?? EB 1A 8D 45 F8 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B D8 85 DB 7E 57 8D 45 F4 50 B9 06 00 00 00 BA 01 00 00 00 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 EC 8B 55 F4 E8 ?? ?? ?? ?? 8D 85 E8 FB FF FF 8B 55 EC 8A 92 ?? ?? ?? ?? E8 }
    condition:
        $c0
}


rule FGint_RSAEncrypt
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "FGint RSAEncrypt"
    strings:
        $c0 = { 55 8B EC 83 C4 D0 53 56 57 33 DB 89 5D D0 89 5D DC 89 5D D8 89 5D D4 8B F9 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 DC 8B C7 E8 ?? ?? ?? ?? 8B 45 DC E8 ?? ?? ?? ?? 8B D8 8D 55 DC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 DC 8B 4D DC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F3 4E EB 10 }
    condition:
        $c0
}

rule FGint_RsaDecrypt
{   meta:
        author = "Maxx"
        description = "FGint RsaDecrypt"
    strings:
        $c0 = { 55 8B EC 83 C4 A0 53 56 57 33 DB 89 5D A0 89 5D A4 89 5D A8 89 5D B4 89 5D B0 89 5D AC 89 4D F8 8B FA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 }
    condition:
        $c0
}

rule FGint_RSAVerify
{   meta:
        author = "_pusher_"
        description = "FGint RSAVerify"
    strings:
        $c0 = { 55 8B EC 83 C4 E0 53 56 8B F1 89 55 F8 89 45 FC 8B 5D 0C 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E8 8B 45 F8 E8 ?? ?? ?? ?? 8D 55 F0 8B 45 FC E8 ?? ?? ?? ?? 8D 4D E0 8B D3 8D 45 F0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 50 8B CB 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E8 E8 ?? ?? ?? ?? 3C 02 8B 45 08 0F 94 00 8D 45 E8 E8 ?? ?? ?? ?? 8D 45 F0 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? B9 03 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 BA 02 00 00 00 E8 ?? ?? ?? ?? C3 }
    condition:
        $c0
}

rule FGint_FindPrimeGoodCurveAndPoint
{   meta:
        author = "_pusher_"
        date = "2015-06"
        description = "FGint FindPrimeGoodCurveAndPoint"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 F4 53 56 57 33 DB 89 5D F4 89 4D FC 8B FA 8B F0 33 C0 55 }
    condition:
        $c0
}

rule FGint_ECElGamalEncrypt
{   meta:
        author = "_pusher_"
        date = "2016-08"
        description = "FGint ECElGamalEncrypt"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 81 C4 3C FF FF FF 53 56 57 33 DB 89 5D D8 89 5D D4 89 5D D0 8B 75 10 8D 7D 8C A5 A5 A5 A5 A5 8B 75 14 8D 7D A0 A5 A5 A5 A5 A5 8B 75 18 8D 7D DC A5 A5 8B 75 1C 8D 7D E4 A5 A5 8B F1 8D 7D EC A5 A5 8B F2 8D 7D F4 A5 A5 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 8C 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 78 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 64 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 50 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 3C FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 7D CF }
        $c1 = { 55 8B EC 83 C4 A8 53 56 57 33 DB 89 5D A8 89 5D AC 89 5D BC 89 5D B8 89 5D B4 89 4D F4 89 55 F8 89 45 FC 8B 75 0C 8B 45 FC E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 71 14 41 00 64 FF 30 64 89 20 8D 55 BC 8B C6 E8 ?? ?? ?? ?? 8B 45 BC E8 ?? ?? ?? ?? 8B D8 8D 55 BC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 BC 8B 4D BC BA 8C 14 41 00 E8 ?? ?? ?? ?? 8B FB 4F EB 10 8D 45 BC 8B 4D BC BA 98 14 41 00 E8 ?? ?? ?? ?? 8B 45 BC }
    condition:
        $c0 or $c1
}

rule FGint_ECAddPoints
{   meta:
        author = "_pusher_"
        date = "2015-06"
        description = "FGint ECAddPoints"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 A8 53 56 57 8B 75 0C 8D 7D F0 A5 A5 8B F1 8D 7D F8 A5 A5 8B F2 8D 7D A8 A5 A5 A5 A5 A5 8B F0 8D 7D BC A5 A5 A5 A5 A5 8B 5D 08 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 }
    condition:
        $c0
}

rule FGint_ECPointKMultiple
{   meta:
        author = "_pusher_"
        date = "2015-06"
        description = "FGint ECPointKMultiple"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 BC 53 56 57 33 DB 89 5D E4 8B 75 0C 8D 7D E8 A5 A5 8B F1 8D 7D F0 A5 A5 8B F2 8D 7D F8 A5 A5 8B F0 8D 7D D0 A5 A5 A5 A5 A5 8B 5D 08 8D 45 D0 8B 15 ?? ?? ?? 00 E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 }
    condition:
        $c0
}

rule FGint_ECPointDestroy
{   meta:
        author = "_pusher_"
        date = "2015-06"
        description = "FGint ECPointDestroy"
        version = "0.1"
    strings:
        $c0 = { 53 8B D8 8B C3 E8 ?? ?? ?? ?? 8D 43 08 E8 ?? ?? ?? ?? 5B C3 }
    condition:
        $c0
}

rule FGint_DSAPrimeSearch
{   meta:
        author = "_pusher_"
        date = "2016-08"
        description = "FGint DSAPrimeSearch"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 DC 53 56 8B DA 8B F0 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 4D F8 8B D6 8B C6 E8 ?? ?? ?? ?? 8D 4D E8 8B D6 8B C3 E8 ?? ?? ?? ?? 8D 55 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D E0 8D 55 E8 8B C3 E8 ?? ?? ?? ?? 8D 45 E8 E8 ?? ?? ?? ?? 8D 4D E8 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 F0 E8 ?? ?? ?? ?? 8B 45 EC 8B 40 04 83 E0 01 85 C0 75 18 8D 4D E0 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 ?? ?? ?? ?? 8B D3 8D 45 E8 E8 ?? ?? ?? ?? C6 45 DF 00 EB 26 8D 4D E8 8D 55 F8 8B C3 E8 ?? ?? ?? ?? 8B D3 8D 45 E8 E8 ?? ?? ?? ?? 8D 4D DF 8B C3 BA 05 00 00 00 E8 ?? ?? ?? ?? 80 7D DF 00 74 D4 8D 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? B9 04 00 00 00 E8 ?? ?? ?? ?? C3 }
    condition:
        $c0
}

rule FGint_DSASign
{   meta:
        author = "_pusher_"
        date = "2016-08"
        description = "FGint DSASign"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 CC 53 56 57 89 4D FC 8B DA 8B F8 8B 75 14 8B 45 10 E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F4 50 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 4D D4 8B D3 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8B C6 E8 ?? ?? ?? ?? 8D 55 EC 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 D4 8B 45 18 E8 ?? ?? ?? ?? 8D 4D DC 8D 55 E4 8D 45 EC E8 ?? ?? ?? ?? 8D 45 EC E8 ?? ?? ?? ?? 8D 45 E4 E8 ?? ?? ?? ?? 8D 45 CC 50 8B CB 8D 55 DC 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 DC E8 ?? ?? ?? ?? 8B 55 0C 8D 45 D4 E8 ?? ?? ?? ?? 8B 55 08 8D 45 CC E8 ?? ?? ?? ?? 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 CC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? B9 06 00 00 00 E8 }
    condition:
        $c0
}

rule FGint_DSAVerify
{   meta:
        author = "_pusher_"
        date = "2016-08"
        description = "FGint DSAVerify"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 B4 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 8B 45 14 E8 ?? ?? ?? ?? 8B 45 10 E8 ?? ?? ?? ?? 8B 45 0C E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 CC 8B 45 0C E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8D 45 CC E8 ?? ?? ?? ?? 8D 55 C4 8B 45 14 E8 ?? ?? ?? ?? 8D 45 EC 50 8B CB 8D 55 F4 8D 45 C4 E8 ?? ?? ?? ?? 8D 45 C4 E8 ?? ?? ?? ?? 8D 55 D4 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 F4 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 C4 50 8B CE 8D 55 EC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 BC 50 8B CE 8D 55 E4 8B 45 18 E8 ?? ?? ?? ?? 8D 45 B4 50 8B CE 8D 55 BC 8D 45 C4 E8 ?? ?? ?? ?? 8D 45 C4 E8 }
    condition:
        $c0
}


rule DES_Long
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "DES [long]"
    strings:
        $c0 = { 10 80 10 40 00 00 00 00 00 80 10 00 00 00 10 40 10 00 00 40 10 80 00 00 00 80 00 40 00 80 10 00 00 80 00 00 10 00 10 40 10 00 00 00 00 80 00 40 10 00 10 00 00 80 10 40 00 00 10 40 10 00 00 00 }
    condition:
        $c0
}

rule DES_sbox
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "DES [sbox]"
    strings:
        $c0 = { 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 }
    condition:
        $c0
}

rule DES_pbox_long
{   meta:
        author = "_pusher_"
        date = "2015-05"
        description = "DES [pbox] [long]"
    strings:
        $c0 = { 0F 00 00 00 06 00 00 00 13 00 00 00 14 00 00 00 1C 00 00 00 0B 00 00 00 1B 00 00 00 10 00 00 00 00 00 00 00 0E 00 00 00 16 00 00 00 19 00 00 00 04 00 00 00 11 00 00 00 1E 00 00 00 09 00 00 00 01 00 00 00 07 00 00 00 17 00 00 00 0D 00 00 00 1F 00 00 00 1A 00 00 00 02 00 00 00 08 00 00 00 12 00 00 00 0C 00 00 00 1D 00 00 00 05 00 00 00 }
    condition:
        $c0
}

rule OpenSSL_BN_mod_exp2_mont
{   meta:
        author = "Maxx"
        description = "OpenSSL BN_mod_exp2_mont"
    strings:
        $c0 = { B8 30 05 00 00 E8 ?? ?? ?? ?? 8B 84 24 48 05 00 00 53 33 DB 56 8B 08 57 89 5C 24 24 89 5C 24 30 8A 01 89 5C 24 28 A8 01 89 5C 24 0C 75 24 68 89 00 00 00 68 ?? ?? ?? ?? 6A 66 6A 76 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 30 05 00 00 C3 8B 94 24 48 05 00 00 52 E8 ?? ?? ?? ?? 8B F0 8B 84 24 54 05 00 00 50 E8 ?? ?? ?? ?? 83 C4 08 3B F3 8B F8 75 20 3B FB 75 1C 8B 8C 24 40 05 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 30 05 00 00 C3 3B F7 89 74 24 18 7F 04 89 }
    condition:
        $c0
}

rule OpenSSL_BN_mod_exp_mont
{   meta:
        author = "Maxx"
        description = "OpenSSL BN_mod_exp_mont"
    strings:
        $c0 = { B8 A0 02 00 00 E8 ?? ?? ?? ?? 53 56 57 8B BC 24 BC 02 00 00 33 F6 8B 07 89 74 24 24 89 74 24 20 89 74 24 0C F6 00 01 75 24 68 72 01 00 00 68 ?? ?? ?? ?? 6A 66 6A 6D 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 A0 02 00 00 C3 8B 8C 24 B8 02 00 00 51 E8 ?? ?? ?? ?? 8B D8 83 C4 04 3B DE 89 5C 24 18 75 1C 8B 94 24 B0 02 00 00 6A 01 52 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 A0 02 00 00 C3 55 8B AC 24 C4 02 00 00 55 E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8B F0 55 89 74 24 24 E8 }
    condition:
        $c0
}

rule OpenSSL_BN_mod_exp_recp
{   meta:
        author = "Maxx"
        description = "OpenSSL BN_mod_exp_recp"
    strings:
        $c0 = { B8 C8 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 D4 02 00 00 55 56 33 F6 50 89 74 24 1C 89 74 24 18 E8 ?? ?? ?? ?? 8B E8 83 C4 04 3B EE 89 6C 24 0C 75 1B 8B 8C 24 D4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 C8 02 00 00 C3 53 57 8B BC 24 EC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DE 0F 84 E7 02 00 00 8D 54 24 24 52 E8 ?? ?? ?? ?? 8B B4 24 EC 02 00 00 83 C4 04 8B 46 0C 85 C0 74 32 56 53 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 BA 02 00 00 57 8D 44 24 28 53 }
    condition:
        $c0
}

rule OpenSSL_BN_mod_exp_simple
{   meta:
        author = "Maxx"
        description = "OpenSSL BN_mod_exp_simple"
    strings:
        $c0 = { B8 98 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 A4 02 00 00 55 56 33 ED 50 89 6C 24 1C 89 6C 24 18 E8 ?? ?? ?? ?? 8B F0 83 C4 04 3B F5 89 74 24 0C 75 1B 8B 8C 24 A4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 98 02 00 00 C3 53 57 8B BC 24 BC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DD 0F 84 71 02 00 00 8D 54 24 28 52 E8 ?? ?? ?? ?? 8B AC 24 BC 02 00 00 8B 84 24 B4 02 00 00 57 55 8D 4C 24 34 50 51 C7 44 24 30 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F }
    condition:
        $c0
}

rule OpenSSL_BN_mod_exp_inverse
{   meta:
        author = "Maxx"
        description = "OpenSSL BN_mod_exp_inverse"
    strings:
        $c0 = { B8 18 00 00 00 E8 ?? ?? ?? ?? 53 55 56 57 8B 7C 24 38 33 C0 57 89 44 24 20 89 44 24 24 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 57 89 44 24 1C E8 ?? ?? ?? ?? 57 8B F0 E8 ?? ?? ?? ?? 57 89 44 24 28 E8 ?? ?? ?? ?? 57 8B E8 E8 ?? ?? ?? ?? 57 8B D8 E8 ?? ?? ?? ?? 8B F8 8B 44 24 54 50 89 7C 24 38 E8 ?? ?? ?? ?? 83 C4 20 89 44 24 24 85 C0 8B 44 24 2C 0F 84 78 05 00 00 85 C0 75 05 E8 ?? ?? ?? ?? 85 C0 89 44 24 1C 0F 84 63 05 00 00 8B 4C 24 14 6A 01 51 E8 ?? ?? ?? ?? 6A 00 57 E8 }
    condition:
        $c0
}

rule OpenSSL_DSA
{
    meta:
        author="_pusher_"
        date="2016-08"
    strings:
        $a0 = "bignum_data" wide ascii nocase
        $a1 = "DSA_METHOD" wide ascii nocase
        $a2 = "PDSA" wide ascii nocase
        $a3 = "dsa_mod_exp" wide ascii nocase
        $a4 = "bn_mod_exp" wide ascii nocase
        $a5 = "dsa_do_verify" wide ascii nocase
        $a6 = "dsa_sign_setup" wide ascii nocase
        $a7 = "dsa_do_sign" wide ascii nocase
        $a8 = "dsa_paramgen" wide ascii nocase
        $a9 = "BN_MONT_CTX" wide ascii nocase
    condition:
        7 of ($a*)
}

rule FGint_RsaSign
{   meta:
        author = "Maxx"
        description = "FGint RsaSign"
    strings:
        $c0 = { 55 8B EC 83 C4 B8 53 56 57 89 4D F8 8B FA 89 45 FC 8B 75 0C 8B 5D 10 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 }
    condition:
        $c0
}


rule LockBox_RsaEncryptFile
{   meta:
        author = "Maxx"
        description = "LockBox RsaEncryptFile"
    strings:
        $c0 = { 55 8B EC 83 C4 F8 53 56 8B F1 8B DA 6A 20 8B C8 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 FC 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 68 FF FF 00 00 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8A 45 08 50 8B CE 8B 55 F8 8B 45 FC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? C3 }
    condition:
        $c0
}

rule LockBox_DecryptRsaEx
{   meta:
        author = "Maxx"
        description = "LockBox DecryptRsaEx"
    strings:
        $c0 = { 55 8B EC 83 C4 F4 53 56 57 89 4D F8 89 55 FC 8B D8 33 C0 8A 43 04 0F B7 34 45 ?? ?? ?? ?? 0F B7 3C 45 ?? ?? ?? ?? 8B CE B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 FC 8B CE 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 B1 02 8B D3 8B 45 F4 E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B C7 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 8B C8 8B 55 F8 8B 45 F4 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 }
    condition:
        $c0
}

rule LockBox_EncryptRsaEx
{   meta:
        author = "Maxx"
        description = "LockBox EncryptRsaEx"
    strings:
        $c0 = { 55 8B EC 83 C4 F8 53 56 57 89 4D FC 8B FA 8B F0 33 C0 8A 46 04 0F B7 1C 45 ?? ?? ?? ?? 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B D7 8B 4D 08 8B 45 F8 E8 ?? ?? ?? ?? 6A 01 B1 02 8B D6 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 3B C3 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B C8 8B 55 FC 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 }
    condition:
        $c0
}

rule LockBox_TlbRsaKey
{   meta:
        author = "Maxx"
        description = "LockBox TlbRsaKey"
    strings:
        $c0 = { 53 56 84 D2 74 08 83 C4 F0 E8 ?? ?? ?? ?? 8B DA 8B F0 33 D2 8B C6 E8 ?? ?? ?? ?? 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 0C 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 10 8B C6 84 DB 74 0F E8 ?? ?? ?? ?? 64 8F 05 00 00 00 00 83 C4 0C 8B C6 5E 5B C3 }
    condition:
        $c0
}

rule BigDig_bpInit
{   meta:
        author = "Maxx"
        description = "BigDig bpInit"
    strings:
        $c0 = { 56 8B 74 24 0C 6A 04 56 E8 ?? ?? ?? ?? 8B C8 8B 44 24 10 83 C4 08 85 C9 89 08 75 04 33 C0 5E C3 89 70 08 C7 40 04 00 00 00 00 5E C3 }
    condition:
        $c0
}

rule BigDig_mpModExp
{   meta:
        author = "Maxx"
        description = "BigDig mpModExp"
    strings:
        $c0 = { 56 8B 74 24 18 85 F6 75 05 83 C8 FF 5E C3 53 55 8B 6C 24 18 57 56 55 E8 ?? ?? ?? ?? 8B D8 83 C4 08 BF 00 00 00 80 8B 44 9D FC 85 C7 75 04 D1 EF 75 F8 83 FF 01 75 08 BF 00 00 00 80 4B EB 02 D1 EF 8B 44 24 18 56 8B 74 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 4F 8D 6C 9D FC 8B 4C 24 24 8B 54 24 20 51 52 56 56 56 E8 ?? ?? ?? ?? 8B 45 00 83 C4 14 85 C7 74 19 8B 44 24 24 8B 4C 24 20 8B 54 24 18 50 51 52 56 56 E8 ?? ?? ?? ?? 83 C4 14 83 FF 01 75 0B 4B BF 00 00 00 80 83 ED 04 EB }
    condition:
        $c0
}

rule BigDig_mpModInv
{   meta:
        author = "Maxx"
        description = "BigDig mpModInv"
    strings:
        $c0 = { 81 EC 2C 07 00 00 8D 84 24 CC 00 00 00 53 56 8B B4 24 44 07 00 00 57 56 6A 01 50 E8 ?? ?? ?? ?? 8B 8C 24 4C 07 00 00 56 8D 94 24 80 02 00 00 51 52 E8 ?? ?? ?? ?? 8D 84 24 BC 01 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 64 07 00 00 56 8D 4C 24 30 53 51 E8 ?? ?? ?? ?? 8D 54 24 38 56 52 BF 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 34 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 78 02 00 00 56 8D 94 24 48 03 00 00 51 8D 84 24 18 04 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 BC 01 00 00 56 8D 94 }
    condition:
        $c0
}

rule BigDig_mpModMult
{   meta:
        author = "Maxx"
        description = "BigDig mpModMult"
    strings:
        $c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 98 01 00 00 8D 54 24 00 56 8B B4 24 B0 01 00 00 57 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 C0 01 00 00 8B 94 24 B4 01 00 00 8D 3C 36 56 50 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 57 50 E8 ?? ?? ?? ?? 83 C4 2C 33 C0 5F 5E 81 C4 98 01 00 00 C3 }
    condition:
        $c0
}

rule BigDig_mpModulo
{   meta:
        author = "Maxx"
        description = "BigDig mpModulo"
    strings:
        $c0 = { 8B 44 24 10 81 EC 30 03 00 00 8B 8C 24 38 03 00 00 8D 54 24 00 56 8B B4 24 40 03 00 00 57 8B BC 24 4C 03 00 00 57 50 56 51 8D 84 24 B0 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 94 24 54 03 00 00 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 CC 01 00 00 56 51 E8 ?? ?? ?? ?? 83 C4 34 33 C0 5F 5E 81 C4 30 03 00 00 C3 }
    condition:
        $c0
}

rule BigDig_spModExpB
{   meta:
        author = "Maxx"
        description = "BigDig spModExpB"
    strings:
        $c0 = { 53 8B 5C 24 10 55 56 BE 00 00 00 80 85 F3 75 04 D1 EE 75 F8 8B 6C 24 14 8B C5 D1 EE 89 44 24 18 74 48 57 8B 7C 24 20 EB 04 8B 44 24 1C 57 50 50 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 F3 74 14 8B 4C 24 1C 57 55 8D 54 24 24 51 52 E8 ?? ?? ?? ?? 83 C4 10 D1 EE 75 D0 8B 44 24 14 8B 4C 24 1C 5F 5E 89 08 5D 33 C0 5B C3 8B 54 24 10 5E 5D 5B 89 02 33 C0 C3 }
    condition:
        $c0
}

rule BigDig_spModInv
{   meta:
        author = "Maxx"
        description = "BigDig spModInv"
    strings:
        $c0 = { 51 8B 4C 24 10 55 56 BD 01 00 00 00 33 F6 57 8B 7C 24 18 89 6C 24 0C 85 C9 74 42 53 8B C7 33 D2 F7 F1 8B C7 8B F9 8B DA 33 D2 F7 F1 8B CB 0F AF C6 03 C5 8B EE 8B F0 8B 44 24 10 F7 D8 85 DB 89 44 24 10 75 D7 85 C0 5B 7D 13 8B 44 24 1C 8B 4C 24 14 2B C5 5F 89 01 5E 33 C0 5D 59 C3 8B 54 24 14 5F 5E 33 C0 89 2A 5D 59 C3 }
    condition:
        $c0
}

rule BigDig_spModMult
{   meta:
        author = "Maxx"
        description = "BigDig spModMult"
    strings:
        $c0 = { 8B 44 24 0C 8B 4C 24 08 83 EC 08 8D 54 24 00 50 51 52 E8 ?? ?? ?? ?? 8B 44 24 24 6A 02 8D 4C 24 10 50 51 E8 ?? ?? ?? ?? 8B 54 24 24 89 02 33 C0 83 C4 20 C3 }
    condition:
        $c0
}

rule CryptoPP_ApplyFunction
{   meta:
        author = "Maxx"
        description = "CryptoPP ApplyFunction"
    strings:
        $c0 = { 51 8D 41 E4 56 8B 74 24 0C 83 C1 F0 50 51 8B 4C 24 18 C7 44 24 0C 00 00 00 00 51 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5E 59 C2 08 00 }
        $c1 = { 51 53 56 8B F1 57 6A 00 C7 44 24 10 00 00 00 00 8B 46 04 8B 48 04 8B 5C 31 04 8D 7C 31 04 E8 ?? ?? ?? ?? 50 8B CF FF 53 10 8B 44 24 18 8D 56 08 83 C6 1C 52 56 8B 74 24 1C 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5F 5E 5B 59 C2 08 00 }
    condition:
        any of them
}

rule CryptoPP_RsaFunction
{   meta:
        author = "Maxx"
        description = "CryptoPP RsaFunction"
    strings:
        $c0 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 9C 00 00 00 8B 84 24 B0 00 00 00 53 55 56 33 ED 8B F1 57 3B C5 89 B4 24 A8 00 00 00 89 6C 24 10 BF 01 00 00 00 74 18 C7 06 ?? ?? ?? ?? C7 46 20 ?? ?? ?? ?? 89 7C 24 10 89 AC 24 B4 00 00 00 8D 4E 04 E8 ?? ?? ?? ?? 8D 4E 10 89 BC 24 B4 00 00 00 E8 ?? ?? ?? ?? 8B 06 BB ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 48 04 C7 04 31 ?? ?? ?? ?? 8B 16 8B 42 04 8B 54 24 10 83 CA 02 8D 48 E0 89 54 24 10 89 4C 30 FC 89 5C 24 18 89 7C }
        $c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 1C 53 8B 5C 24 1C 56 8B F1 57 33 C9 89 74 24 10 3B C1 89 4C 24 0C 74 7B C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 3B D9 75 06 89 4C 24 28 EB 0E 8B 43 04 8B 50 0C 8D 44 1A 04 89 44 24 28 8B 56 3C C7 44 24 0C 07 00 00 00 8B 42 04 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C C7 46 38 ?? ?? ?? ?? 8B 42 04 C7 44 30 3C }
        $c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 18 56 8B F1 57 85 C0 89 74 24 0C C7 44 24 08 00 00 00 00 74 63 C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 8B 46 3C C7 44 24 08 07 00 00 00 8B 48 04 C7 44 31 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 4E 3C C7 46 38 ?? ?? ?? ?? 8B 51 04 C7 44 32 3C ?? ?? ?? ?? 8B 46 3C 8B 48 08 C7 44 31 3C ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 8D 7E 04 6A 00 8B CF }
    condition:
        any of them
}

rule CryptoPP_Integer_constructor
{   meta:
        author = "Maxx"
        description = "CryptoPP Integer constructor"
    strings:
        $c0 = { 8B 44 24 08 56 83 F8 08 8B F1 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 4C 24 0C 89 46 04 C7 46 08 00 00 00 00 89 08 8B 0E 8B 46 04 83 C4 04 49 74 0F 57 8D 78 04 33 C0 F3 AB 8B C6 5F 5E C2 08 00 8B C6 5E C2 08 00 }
        $c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 89 74 24 04 C7 06 ?? ?? ?? ?? 6A 08 C7 44 24 14 00 00 00 00 C7 46 08 02 00 00 00 E8 ?? ?? ?? ?? 89 46 0C C7 46 10 00 00 00 00 C7 06 ?? ?? ?? ?? 8B 46 0C 83 C4 04 C7 40 04 00 00 00 00 8B 4E 0C 8B C6 5E C7 01 00 00 00 00 8B 4C 24 04 64 89 0D 00 00 00 00 83 C4 10 C3 }
        $c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 57 89 74 24 08 C7 06 ?? ?? ?? ?? 8B 7C 24 1C C7 44 24 14 00 00 00 00 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 85 D2 89 56 08 76 12 8D 04 95 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 04 EB 02 33 C0 89 46 0C 8B 4F 10 89 4E 10 }
        $c3 = { 56 57 8B 7C 24 0C 8B F1 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 16 89 46 04 8B 4F 08 83 C4 04 89 4E 08 8B 4F 04 85 D2 76 0D 2B C8 8B 3C 01 89 38 83 C0 04 4A 75 F5 8B C6 5F 5E C2 04 00 }
    condition:
        any of them
}

rule RijnDael_AES
{   meta:
        author = "_pusher_"
        description = "RijnDael AES"
        date = "2016-06"
    strings:
        $c0 = { A5 63 63 C6 84 7C 7C F8 }
    condition:
        $c0
}

rule RijnDael_AES_CHAR
{   meta:
        author = "_pusher_"
        description = "RijnDael AES (check2) [char]"
        date = "2016-06"
    strings:
        $c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
    condition:
        $c0
}

rule RijnDael_AES_CHAR_inv
{   meta:
        author = "_pusher_"
        description = "RijnDael AES S-inv [char]"
        //needs improvement
        date = "2016-07"
    strings:
        $c0 = { 48 38 47 00 88 17 33 D2 8A 56 0D 8A 92 48 38 47 00 88 57 01 33 D2 8A 56 0A 8A 92 48 38 47 00 88 57 02 33 D2 8A 56 07 8A 92 48 38 47 00 88 57 03 33 D2 8A 56 04 8A 92 }
    condition:
        $c0
}

rule RijnDael_AES_LONG
{   meta:
        author = "_pusher_"
        description = "RijnDael AES"
        date = "2016-06"
    strings:
        $c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
    condition:
        $c0
}

rule RijnDael_AES_LONG_inv
{   meta:
        author = "edeca"
        description = "RijnDael AES"
        date = "2019-10"
    strings:
        $c0 = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB 7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB }
    condition:
        $c0
}

rule RijnDael_AES_RCON
{   meta:
        author = "edeca"
        description = "RijnDael AES round constants"
        date = "2019-10"
    strings:
        $c0 = { 8D 01 02 04 08 10 20 40 80 1B 36 6C D8 AB 4D 9A }
    condition:
        $c0
}

rule RsaRef2_NN_modExp
{   meta:
        author = "Maxx"
        description = "RsaRef2 NN_modExp"
    strings:
        $c0 = { 81 EC 1C 02 00 00 53 55 56 8B B4 24 30 02 00 00 57 8B BC 24 44 02 00 00 57 8D 84 24 A4 00 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 4C 02 00 00 57 53 8D 8C 24 B4 00 00 00 56 8D 94 24 3C 01 00 00 51 52 E8 ?? ?? ?? ?? 57 53 8D 84 24 4C 01 00 00 56 8D 8C 24 D4 01 00 00 50 51 E8 ?? ?? ?? ?? 8D 54 24 50 57 52 E8 ?? ?? ?? ?? 8B 84 24 78 02 00 00 8B B4 24 74 02 00 00 50 56 C7 44 24 60 01 00 00 00 E8 ?? ?? ?? ?? 8D 48 FF 83 C4 44 8B E9 89 4C 24 18 85 ED 0F 8C AF 00 00 00 8D 34 AE 89 74 24 }
    condition:
        any of them
}

rule RsaRef2_NN_modInv
{   meta:
        author = "Maxx"
        description = "RsaRef2 NN_modInv"
    strings:
        $c0 = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 84 24 ?? 00 00 00 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 BC 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 4C 24 2C 53 51 E8 ?? ?? ?? ?? 8D 54 24 34 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 2C 01 }
    condition:
        $c0
}

rule RsaRef2_NN_modMult
{   meta:
        author = "Maxx"
        description = "RsaRef2 NN_modMult"
    strings:
        $c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 68 08 01 00 00 8D 4C 24 2C 6A 00 51 E8 ?? ?? ?? ?? 83 C4 30 5E 81 C4 08 01 00 00 C3 }
    condition:
        $c0
}

rule RsaRef2_RsaPrivateDecrypt
{   meta:
        author = "Maxx"
        description = "RsaRef2 RsaPrivateDecrypt"
    strings:
        $c0 = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8B 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6B 8A 4C 24 09 B8 02 00 00 00 3A C8 75 5E 8D 4E FF 3B C8 76 0D 8A 54 04 08 84 D2 74 05 40 3B C1 72 F3 40 3B C6 73 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A 8D 51 0B }
    condition:
        $c0
}

rule RsaRef2_RsaPrivateEncrypt
{   meta:
        author = "Maxx"
        description = "RsaRef2 RsaPrivateEncrypt"
    strings:
        $c0 = { 8B 44 24 14 8B 54 24 10 81 EC 80 00 00 00 8D 4A 0B 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 80 00 00 00 C3 8B CE B8 02 00 00 00 2B CA C6 44 24 04 00 49 C6 44 24 05 01 3B C8 76 23 53 55 8D 69 FE 57 8B CD 83 C8 FF 8B D9 8D 7C 24 12 C1 E9 02 F3 AB 8B CB 83 E1 03 F3 AA 8D 45 02 5F 5D 5B 52 8B 94 24 94 00 00 00 C6 44 04 08 00 8D 44 04 09 52 50 E8 ?? ?? ?? ?? 8B 8C 24 A4 00 00 00 8B 84 24 98 00 00 00 51 8B 8C 24 98 00 00 00 8D 54 24 14 56 52 50 51 E8 }
    condition:
        $c0
}

rule RsaRef2_RsaPublicDecrypt
{   meta:
        author = "Maxx"
        description = "RsaRef2 RsaPublicDecrypt"
    strings:
        $c0 = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8E 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6E 80 7C 24 09 01 75 67 B8 02 00 00 00 8D 4E FF 3B C8 76 0D B2 FF 38 54 04 08 75 05 40 3B C1 72 F5 8A 4C 04 08 40 84 C9 75 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A }
    condition:
        $c0
}

rule RsaRef2_RsaPublicEncrypt
{   meta:
        author = "Maxx"
        description = "RsaRef2 RsaPublicEncrypt"
    strings:
        $c0 = { 8B 44 24 14 81 EC 84 00 00 00 53 8B 9C 24 98 00 00 00 57 8B 38 83 C7 07 8D 4B 0B C1 EF 03 3B CF 76 0E 5F B8 06 04 00 00 5B 81 C4 84 00 00 00 C3 8B D7 55 2B D3 56 BE 02 00 00 00 C6 44 24 14 00 8D 6A FF C6 44 24 15 02 3B EE 76 28 8B 84 24 AC 00 00 00 8D 4C 24 13 50 6A 01 51 E8 ?? ?? ?? ?? 8A 44 24 1F 83 C4 0C 84 C0 74 E1 88 44 34 14 46 3B F5 72 D8 8B 94 24 A0 00 00 00 53 8D 44 34 19 52 50 C6 44 34 20 00 E8 ?? ?? ?? ?? 8B 8C 24 B4 00 00 00 8B 84 24 A8 00 00 00 51 8B 8C 24 A8 00 }
    condition:
        $c0
}

rule RsaEuro_NN_modInv
{   meta:
        author = "Maxx"
        description = "RsaEuro NN_modInv"
    strings:
        $c0 = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 44 24 0C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 7C 24 1C E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 8C 24 B0 00 00 00 53 51 E8 ?? ?? ?? ?? 8D 94 24 B8 00 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 F8 00 00 00 8D 84 24 ?? 00 00 00 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C }
    condition:
        $c0
}

rule RsaEuro_NN_modMult
{   meta:
        author = "Maxx"
        description = "RsaEuro NN_modMult"
    strings:
        $c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 83 C4 24 5E 81 C4 08 01 00 00 C3 }
    condition:
        $c0
}

rule Miracl_Big_constructor
{   meta:
        author = "Maxx"
        description = "Miracl Big constructor"
    strings:
        $c0 = { 56 8B F1 6A 00 E8 ?? ?? ?? ?? 83 C4 04 89 06 8B C6 5E C3 }
    condition:
        $c0
}

rule Miracl_mirvar
{   meta:
        author = "Maxx"
        description = "Miracl mirvar"
    strings:
        $c0 = { 56 E8 ?? ?? ?? ?? 8B 88 18 02 00 00 85 C9 74 04 33 C0 5E C3 8B 88 8C 00 00 00 85 C9 75 0E 6A 12 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5E C3 8B 80 38 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F0 83 C4 08 85 F6 75 02 5E C3 8D 46 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 08 85 C0 74 0A 56 50 E8 ?? ?? ?? ?? 83 C4 08 8B C6 5E C3 }
        $c1 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 2C 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 40 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 46 18 6A 01 8D 0C 85 0C 00 00 00 51 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B D0 8B C8 83 E2 03 2B CA 83 C1 08 89 08 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
        $c2 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 86 A4 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
    condition:
        any of them
}

rule Miracl_mirsys_init
{   meta:
        author = "Maxx"
        description = "Miracl mirsys init"
    strings:
        $c0 = { 53 55 57 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB A3 ?? ?? ?? ?? 3B C3 75 06 5F 5D 33 C0 5B C3 89 58 1C A1 ?? ?? ?? ?? BD 01 00 00 00 89 58 20 A1 ?? ?? ?? ?? 8B 50 1C 42 89 50 1C A1 ?? ?? ?? ?? 8B 48 1C C7 44 88 20 1D 00 00 00 8B 15 ?? ?? ?? ?? 89 9A 14 02 00 00 A1 ?? ?? ?? ?? 89 98 70 01 00 00 8B 0D ?? ?? ?? ?? 89 99 78 01 00 00 8B 15 ?? ?? ?? ?? 89 9A 98 01 00 00 A1 ?? ?? ?? ?? 89 58 14 8B 44 24 14 3B C5 0F 84 6C 05 00 00 3D 00 00 00 80 0F 87 61 05 00 00 50 E8 }
    condition:
        $c0
}

/* //gives many false positives sorry Storm Shadow
rule x509_public_key_infrastructure_cert
{   meta:
        desc = "X.509 PKI Certificate"
        ext = "crt"
    strings:
        $c0 = { 30 82 ?? ?? 30 82 ?? ?? }
    condition:
        $c0
}

rule pkcs8_private_key_information_syntax_standard
{   meta:
        desc = "Found PKCS #8: Private-Key"
        ext = "key"
    strings:
        $c0 = { 30 82 ?? ?? 02 01 00 }
    condition:
        $c0
}
*/

rule BASE64_table {
    meta:
        author = "_pusher_"
        description = "Look for Base64 table"
        date = "2015-07"
        version = "0.1"
    strings:
        $c0 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F }
    condition:
        $c0
}

rule Delphi_Random {
    meta:
        author = "_pusher_"
        description = "Look for Random function"
        date = "2015-08"
        version = "0.1"
    strings:
        $c0 = { 53 31 DB 69 93 ?? ?? ?? ?? 05 84 08 08 42 89 93 ?? ?? ?? ?? F7 E2 89 D0 5B C3 }
        //x64 rad
        $c1 = { 8B 05 ?? ?? ?? ?? 69 C0 05 84 08 08 83 C0 01 89 05 ?? ?? ?? ?? 8B C9 8B C0 48 0F AF C8 48 C1 E9 20 89 C8 C3 }
    condition:
        any of them
}

rule Delphi_RandomRange {
    meta:
        author = "_pusher_"
        description = "Look for RandomRange function"
        date = "2016-06"
        version = "0.1"
    strings:
        $c0 = { 56 8B F2 8B D8 3B F3 7D 0E 8B C3 2B C6 E8 ?? ?? ?? ?? 03 C6 5E 5B C3 8B C6 2B C3 E8 ?? ?? ?? ?? 03 C3 5E 5B C3 }
    condition:
        $c0
}

rule Delphi_FormShow {
    meta:
        author = "_pusher_"
        description = "Look for Form.Show function"
        date = "2016-06"
        version = "0.1"
    strings:
        $c0 = { 53 8B D8 B2 01 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
        //x64 rad
        $c1 = { 53 48 83 EC 20 48 89 CB 48 89 D9 B2 01 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
    condition:
        any of them
}

rule Delphi_CompareCall {
    meta:
        author = "_pusher_"
        description = "Look for Compare string function"
        date = "2016-07"
    strings:
        $c0 = { 53 56 57 89 C6 89 D7 39 D0 0F 84 8F 00 00 00 85 F6 74 68 85 FF 74 6B 8B 46 FC 8B 57 FC 29 D0 77 02 01 C2 52 C1 EA 02 74 26 8B 0E 8B 1F 39 D9 75 58 4A 74 15 8B 4E 04 8B 5F 04 39 D9 75 4B 83 C6 08 83 C7 08 4A 75 E2 EB 06 83 C6 04 83 C7 04 5A 83 E2 03 74 22 8B 0E 8B 1F 38 D9 75 41 4A 74 17 38 FD 75 3A 4A 74 10 81 E3 00 00 FF 00 81 E1 00 00 FF 00 39 D9 75 27 01 C0 EB 23 8B 57 FC 29 D0 EB 1C 8B 46 FC 29 D0 EB 15 5A 38 D9 75 10 38 FD 75 0C C1 E9 10 C1 EB 10 38 D9 75 02 38 FD 5F 5E 5B C3 }
        //newer delphi
        $c1 = { 39 D0 74 30 85 D0 74 22 8B 48 FC 3B 4A FC 75 24 01 C9 01 C8 01 CA F7 D9 53 8B 1C 01 3B 1C 11 75 07 83 C1 04 78 F3 31 C0 5B C3 }
        $c3 = { 39 D0 74 37 85 D0 74 38 80 78 F6 01 75 42 80 7A F6 01 75 3D 8B 48 FC 3B 4A FC 75 1F 53 8D 54 11 FC 8D 5C 01 FC F7 D9 8B 03 3B 02 75 0D 83 C1 04 79 0A 8B 04 19 3B 04 11 74 F3 5B C3 }
        //x64
        $c2 = { 41 56 41 55 57 56 53 48 83 EC 20 48 89 D3 48 3B CB 75 05 48 33 C0 EB 74 48 85 C9 75 07 8B 43 FC F7 D8 EB 68 48 85 DB 75 05 8B 41 FC EB 5E 8B 79 FC 44 8B 6B FC 89 FE 41 3B F5 7E 03 44 89 EE E8 ?? ?? ?? ?? 49 89 C6 48 89 D9 E8 ?? ?? ?? ?? 48 89 C1 85 F6 7E 30 41 0F B7 06 0F B7 11 2B C2 85 C0 75 29 83 FE 01 74 1E 41 0F B7 46 02 0F B7 51 02 2B C2 85 C0 75 15 49 83 C6 04 48 83 C1 04 83 EE 02 85 F6 7F D0 90 8B C7 41 2B C5 48 83 C4 20 5B 5E 5F 41 5D 41 5E C3 }
    condition:
        any of them
}

rule Delphi_Copy {
    meta:
        author = "_pusher_"
        description = "Look for Copy function"
        date = "2016-06"
        version = "0.1"
    strings:
        $c0 = { 53 85 C0 74 2D 8B 58 FC 85 DB 74 26 4A 7C 1B 39 DA 7D 1F 29 D3 85 C9 7C 19 39 D9 7F 11 01 C2 8B 44 24 08 E8 ?? ?? ?? ?? EB 11 31 D2 EB E5 89 D9 EB EB 8B 44 24 08 E8 ?? ?? ?? ?? 5B C2 04 00 }
        //x64 rad
        $c1 = { 53 48 83 EC 20 48 89 CB 44 89 C0 48 33 C9 48 85 D2 74 03 8B 4A FC 83 F8 01 7D 05 48 33 C0 EB 09 83 E8 01 3B C1 7E 02 89 C8 45 85 C9 7D 05 48 33 C9 EB 0A 2B C8 41 3B C9 7E 03 44 89 C9 49 89 D8 48 63 C0 48 8D 14 42 89 C8 4C 89 C1 41 89 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
    condition:
        any of them
}

rule Delphi_IntToStr {
    meta:
        author = "_pusher_"
        description = "Look for IntToStr function"
        date = "2016-04"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 81 C4 00 FF FF FF 53 56 8B F2 8B D8 FF 75 0C FF 75 08 8D 85 00 FF FF FF E8 ?? ?? ?? ?? 8D 95 00 FF FF FF 8B C6 E8 ?? ?? ?? ?? EB 0E 8B 0E 8B C6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 E8 ?? ?? ?? ?? 33 D2 8A D3 3B C2 72 E3 5E 5B 8B E5 5D C2 08 00 }
        //x64 rad
        $c1 = { 53 48 83 EC 20 48 89 CB 48 85 D2 7D 10 48 89 D9 48 F7 DA 41 B0 01 E8 ?? ?? ?? ?? EB 0B 48 89 D9 4D 33 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
    condition:
        any of them
}


rule Delphi_StrToInt {
    meta:
        author = "_pusher_"
        description = "Look for StrToInt function"
        date = "2016-06"
        version = "0.1"
    strings:
        $c0 = { 53 56 83 C4 F4 8B D8 8B D4 8B C3 E8 ?? ?? ?? ?? 8B F0 83 3C 24 00 74 19 89 5C 24 04 C6 44 24 08 0B 8D 54 24 04 A1 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? 8B C6 83 C4 0C 5E 5B C3 }
        //x64 rad
        $c1 = { 55 56 53 48 83 EC 40 48 8B EC 48 89 CB 48 89 D9 48 8D 55 3C E8 ?? ?? ?? ?? 89 C6 83 7D 3C 00 74 1B 48 89 5D 20 C6 45 28 11 48 8B 0D ?? ?? ?? ?? 48 8D 55 20 4D 33 C0 E8 ?? ?? ?? ?? 89 F0 48 8D 65 40 5B 5E 5D C3 }
    condition:
        any of them
}

rule Delphi_DecodeDate {
    meta:
        author = "_pusher_"
        description = "Look for DecodeDate (DecodeDateFully) function"
        date = "2016-06"
        version = "0.1"
    strings:
        $c0 = { 55 8B EC 83 C4 E8 53 56 89 4D F4 89 55 F8 89 45 FC 8B 5D 08 FF 75 10 FF 75 0C 8D 45 E8 E8 ?? ?? ?? ?? 8B 4D EC 85 C9 7F 24 8B 45 FC 66 C7 00 00 00 8B 45 F8 66 C7 00 00 00 8B 45 F4 66 C7 00 00 00 66 C7 03 00 00 33 D2 E9 F2 00 00 00 8B C1 BE 07 00 00 00 99 F7 FE 42 66 89 13 49 66 BB 01 00 81 F9 B1 3A 02 00 7C 13 81 E9 B1 3A 02 00 66 81 C3 90 01 81 F9 B1 3A 02 00 7D ED 8D 45 F2 50 8D 45 F0 66 BA AC 8E 91 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 AC 8E 66 6B 45 F0 64 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA B5 05 E8 ?? ?? ?? ?? 66 8B 45 F0 C1 E0 02 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA 6D 01 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 6D 01 66 03 5D F0 8B C3 E8 ?? ?? ?? ?? 8B D0 33 C0 8A C2 8D 04 40 8D 34 C5 ?? ?? ?? ?? 66 B8 01 00 0F B7 C8 66 8B 4C 4E FE 66 89 4D F0 66 8B 4D F2 66 3B 4D F0 72 0B 66 8B 4D F0 66 29 4D F2 40 EB DF 8B 4D FC 66 89 19 8B 4D F8 66 89 01 66 8B 45 F2 40 8B 4D F4 66 89 01 8B C2 5E 5B 8B E5 5D C2 0C 00 }
        //x64
        $c1 = { 55 41 55 57 56 53 48 83 EC 30 48 8B EC 48 89 D3 4C 89 C6 4C 89 CF E8 ?? ?? ?? ?? 48 8B C8 48 C1 E9 20 85 C9 7F 23 66 C7 03 00 00 66 C7 06 00 00 66 C7 07 00 00 48 8B 85 80 00 00 00 66 C7 00 00 00 48 33 C0 E9 19 01 00 00 4C 8B 85 80 00 00 00 41 C7 C1 07 00 00 00 8B C1 99 41 F7 F9 66 83 C2 01 66 41 89 10 83 E9 01 66 41 BD 01 00 81 F9 B1 3A 02 00 7C 14 81 E9 B1 3A 02 00 66 41 81 C5 90 01 81 F9 B1 3A 02 00 7D EC 90 66 BA AC 8E 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E AC 8E 66 6B 45 2C 64 66 44 03 E8 0F B7 4D 2E 66 BA B5 05 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 48 0F B7 45 2C 03 C0 03 C0 66 44 03 E8 0F B7 4D 2E 66 BA 6D 01 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E 6D 01 66 44 03 6D 2C 44 89 E9 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 0F B6 D0 48 8D 14 52 48 8D 14 D1 66 B9 01 00 4C 0F B7 C1 4E 0F B7 44 42 FE 66 44 89 45 2C 4C 0F B7 45 2E 66 44 3B 45 2C 72 10 4C 0F B7 45 2C 66 44 29 45 2E 66 }
    condition:
        any of them
}


rule Unknown_Random {
    meta:
        author = "_pusher_"
        description = "Look for Random function"
        date = "2016-07"
    strings:
        $c0 = { 55 8B EC 52 8B 45 08 69 15 ?? ?? ?? ?? 05 84 08 08 42 89 15 ?? ?? ?? ?? F7 E2 8B C2 5A C9 C2 04 00 }
    condition:
        $c0
}

rule VC6_Random {
    meta:
        author = "_pusher_"
        description = "Look for VC Random function"
        date = "2016-02"
    strings:
        $c0 = { A1 ?? ?? ?? ?? 69 C0 FD 43 03 00 05 C3 9E 26 00 A3 ?? ?? ?? ?? C1 F8 10 25 FF 7F 00 00 C3 }
    condition:
        $c0
}

rule VC8_Random {
    meta:
        author = "_pusher_"
        description = "Look for VC8 Random function"
        date = "2016-01"
        version = "0.2"
    strings:
        $c0 = { E8 ?? ?? ?? ?? 8B 48 14 69 C9 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 8B C1 C1 E8 10 25 FF 7F 00 00 C3 }
        $c1 = { E8 ?? ?? ?? ?? 69 48 14 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 C1 E9 10 81 E1 FF 7F 00 00 8B C1 C3 }
        $c2 = { A1 ?? ?? ?? ?? 69 C0 FD 43 03 00 05 C3 9E 26 00 A3 ?? ?? ?? ?? C1 F8 10 25 FF 7F 00 00 C3 }
    condition:
        any of ($c*)
}

rule DCP_RIJNDAEL_Init {
    meta:
        author = "_pusher_"
        description = "Look for DCP RijnDael Init"
        date = "2016-07"
    strings:
        $c0 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 ?? ?? ?? ?? 8B D7 8B 4D FC 8B C3 8B 38 FF 57 ?? 85 F6 75 25 8D 43 38 33 C9 BA 10 00 00 00 E8 ?? ?? ?? ?? 8D 4B 38 8D 53 38 8B C3 8B 30 FF 56 ?? 8B C3 8B 10 FF 52 ?? EB 16 8D 53 38 8B C6 B9 10 00 00 00 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 52 ?? 5F 5E 5B 59 5D C2 04 00 }
    condition:
        $c0
}

rule DCP_RIJNDAEL_EncryptECB {
    meta:
        author = "_pusher_"
        description = "Look for DCP RijnDael EncryptECB"
        date = "2016-07"
    strings:
        $c0 = { 53 56 57 55 83 C4 B4 89 0C 24 8D 74 24 08 8D 7C 24 28 80 78 30 00 75 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0A 89 0F 8B CA 83 C1 04 8B 09 8D 5F 04 89 0B 8B CA 83 C1 08 8B 09 8D 5F 08 89 0B 83 C2 0C 8B 12 8D 4F 0C 89 11 8B 50 58 83 EA 02 85 D2 0F 82 3B 01 00 00 42 89 54 24 04 33 D2 8B 0F 8B DA C1 E3 02 33 4C D8 5C 89 0E 8D 4F 04 8B 09 33 4C D8 60 8D 6E 04 89 4D 00 8D 4F 08 8B 09 33 4C D8 64 8D 6E 08 89 4D 00 8D 4F 0C 8B 09 33 4C D8 68 8D 5E 0C 89 0B 33 C9 8A 0E 8D 0C 8D }
    condition:
        $c0
}

rule DCP_BLOWFISH_Init {
    meta:
        author = "_pusher_"
        description = "Look for DCP Blowfish Init"
        date = "2016-07"
    strings:
        $c0 = { 53 56 57 55 8B F2 8B F8 8B CF B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8B C3 8B 10 FF 52 34 8B C6 E8 ?? ?? ?? ?? 50 8B C6 E8 ?? ?? ?? ?? 8B D0 8B C3 59 8B 30 FF 56 3C 8B 43 3C 85 C0 79 03 83 C0 07 C1 F8 03 E8 ?? ?? ?? ?? 8B F0 8B D6 8B C3 8B 08 FF 51 40 8B 47 40 8B 6B 3C 3B C5 7D 0F 6A 00 8B C8 8B D6 8B C7 8B 38 FF 57 30 EB 0D 6A 00 8B D6 8B CD 8B C7 8B 38 FF 57 30 8B 53 3C 85 D2 79 03 83 C2 07 C1 FA 03 8B C6 B9 FF 00 00 00 E8 ?? ?? ?? ?? 8B 53 3C 85 D2 79 03 83 C2 07 C1 FA 03 8B C6 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5D 5F 5E 5B C3 }
    condition:
        $c0
}


rule DCP_BLOWFISH_EncryptCBC {
    meta:
        author = "_pusher_"
        description = "Look for DCP Blowfish EncryptCBC"
        date = "2016-07"
    strings:
        $c0 = { 55 8B EC 83 C4 F0 53 56 57 89 4D F8 89 55 FC 8B D8 80 7B 34 00 75 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7D 08 85 FF 79 03 83 C7 07 C1 FF 03 85 FF 7E 56 BE 01 00 00 00 6A 08 8B 45 FC 8B D6 4A C1 E2 03 03 C2 8D 4D F0 8D 53 54 E8 ?? ?? ?? ?? 8D 4D F0 8D 55 F0 8B C3 E8 ?? ?? ?? ?? 8B 55 F8 8B C6 48 C1 E0 03 03 D0 8D 45 F0 B9 08 00 00 00 E8 ?? ?? ?? ?? 8D 53 54 8D 45 F0 B9 08 00 00 00 E8 ?? ?? ?? ?? 46 4F 75 AF 8B 75 08 81 E6 07 00 00 80 79 05 4E 83 CE F8 46 85 F6 74 26 8D 4D F0 8D 53 54 8B C3 E8 ?? ?? ?? ?? 56 8B 4D F8 03 4D 08 2B CE 8B 55 FC 03 55 08 2B D6 8D 45 F0 E8 ?? ?? ?? ?? 8D 45 F0 B9 FF 00 00 00 BA 08 00 00 00 E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C2 04 00 }
    condition:
        $c0
}

rule DCP_DES_Init {
    meta:
        author = "_pusher_"
        description = "Look for DCP Des Init"
        date = "2016-02"
    strings:
        $c0 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 FE F9 FF FF 8B D7 8B 4D FC 8B C3 8B 38 FF 57 5C 85 F6 75 25 8D 43 38 33 C9 BA 08 00 00 00 E8 F3 A9 FA FF 8D 4B 38 8D 53 38 8B C3 8B 30 FF 56 6C 8B C3 8B 10 FF 52 48 EB 16 8D 53 38 8B C6 B9 08 00 00 00 E8 6E A7 FA FF 8B C3 8B 10 FF 52 48 5F 5E 5B 59 5D C2 04 00 }
        $c1 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 EE D4 FF FF 8B D7 8B 4D FC 8B C3 8B 38 FF 57 74 85 F6 75 2B 8D 43 40 B9 FF 00 00 00 BA 08 00 00 00 E8 ?? ?? ?? ?? 8D 4B 40 8D 53 40 8B C3 8B 30 FF 96 84 00 00 00 8B C3 8B 10 FF 52 58 EB 16 8D 53 40 8B C6 B9 08 00 00 00 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 52 58 5F 5E 5B 59 5D C2 04 00 }
    condition:
        any of them
}

rule DCP_DES_EncryptECB {
    meta:
        author = "_pusher_"
        description = "Look for DCP Des EncryptECB"
        date = "2016-02"
    strings:
        $c0 = { 53 80 78 ?? 00 75 16 B9 ?? ?? ?? 00 B2 01 A1 ?? ?? ?? 00 E8 ?? ?? ?? FF E8 ?? ?? ?? FF 8D 58 ?? 53 E8 ?? ?? FF FF 5B C3 }
    condition:
        any of them
}

rule TEA_DELTA2 {
    meta:
        author = "_pusher_"
        description = "TEA DELTA"
        date = "2016-02"
    strings:
        $c0 = { 9E 37 79 B9 }
        $c1 = { 61 C8 86 47 }
    condition:
        any of them
}

rule TEA_DELTA {
    meta:
        author = "_pusher_"
        description = "TEA DELTA"
        date = "2016-02"
    strings:
        $c0 = { B9 79 37 9E }
        $c1 = { 47 86 C8 61 }
    condition:
        any of them
}

rule TEA_SUM {
    meta:
        author = "_pusher_"
        description = "TEA SUM"
        date = "2016-02"
    strings:
        $c0 = { 90 9B 77 E3 }
    condition:
        any of them
}

rule Sosemanuk
{
    /* Notes:
     *
     * - mul_a and mul_ia are commonly stored in a 4-byte value array, so
     *   look for a 4-byte little endian equivalant also
     *
     * - mul_a and mul_ia start with four zero bytes, which is a fairly common
     *   pattern in EXEs.  Including these bytes in the strings below is likely
     *   worse for scan performance than omitting them, but I'm leaving them in
     *   because findcrypt-yara leverages the yara API to map substring matches
     *   to binary offsets (and then into virtual addresses), and the virtual
     *   address for the start of these is likely to have more xrefs than the
     *   the virtual address of (matching_offset + 4).  If, instead, better
     *   performance is desired for your use case, just remove the zero bytes
     *   from the strings below.
     *
     * Reference:
     * - https://labs.sentinelone.com/enter-the-maze-demystifying-an-affiliate-involved-in-maze-snow/
     */
    strings:
        $mul_a_be = {00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 [992] B5 5B 4D DE 54 C4 82 CD DE CC 7A F8 3F 53 B5 EB}
        $mul_a_le = {00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A [992] DE 4D 5B B5 CD 82 C4 54 F8 7A CC DE EB B5 53 3F}
        $mul_ia_be = {00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE [992] 9E E2 65 1C 86 ED 25 D1 AE FC E5 2F B6 F3 A5 E2}
        $mul_ia_le = {00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 [992] 1C 65 E2 9E D1 25 ED 86 2F E5 FC AE E2 A5 F3 B6}

    condition:
        any of them
}

rule IP
{
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
    condition:
        $ip
}

rule maldoc_OLE_file_magic_number : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {D0 CF 11 E0}
    condition:
        $a
}

rule System_Tools
{
    meta:
        description = "Contains references to system / monitoring tools"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "wireshark.exe" nocase wide ascii
        $a1 = "ethereal.exe" nocase wide ascii
        $a2 = "netstat.exe" nocase wide ascii
        $a3 = /taskm(an|gr|on).exe/ nocase wide ascii
        $a4 = /regedit(32)?.exe/ nocase wide ascii
        $a5 = "sc.exe" nocase wide ascii
        $a6 = "procexp.exe" nocase wide ascii
        $a7 = "procmon.exe" nocase wide ascii
        $a8 = "netmon.exe" nocase wide ascii
        $a9 = "regmon.exe" nocase wide ascii
        $a10 = "filemon.exe" nocase wide ascii
        $a11 = "msconfig.exe" nocase wide ascii
        $a12 = "vssadmin.exe" nocase wide ascii
        $a13 = "bcdedit.exe" nocase wide ascii
        $a14 = "dumpcap.exe" nocase wide ascii
        $a15 = "tcpdump.exe" nocase wide ascii
        $a16 = "mshta.exe" nocase wide ascii    // Used by DUBNIUM to download files
        $a17 = "control.exe" nocase wide ascii  // Used by EquationGroup to launch DLLs
        $a18 = "regsvr32.exe" nocase wide ascii
        $a19 = "rundll32.exe" nocase wide ascii

    condition:
        any of them
}

rule Browsers
{
    meta:
        description = "Contains references to internet browsers"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $ie = "iexplore.exe" nocase wide ascii
        $ff = "firefox.exe" nocase wide ascii
        $ff_key = "key3.db"
        $ff_log = "signons.sqlite"
        $chrome = "chrome.exe" nocase wide ascii
        // TODO: Add user-agent strings
    condition:
        any of them
}

rule RE_Tools
{
    meta:
        description = "Contains references to debugging or reversing tools"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = /ida(q)?(64)?.exe/ nocase wide ascii
        $a1 = "ImmunityDebugger.exe" nocase wide ascii
        $a2 = "ollydbg.exe" nocase wide ascii
        $a3 = "lordpe.exe" nocase wide ascii
        $a4 = "peid.exe" nocase wide ascii
        $a5 = "windbg.exe" nocase wide ascii
    condition:
        any of them
}

rule Antivirus
{
    meta:
        description = "Contains references to security software"
        author = "Jerome Athias"
        source = "Metasploit's killav.rb script"

    strings:
        $a0 = "AAWTray.exe" nocase wide ascii
        $a1 = "Ad-Aware.exe" nocase wide ascii
        $a2 = "MSASCui.exe" nocase wide ascii
        $a3 = "_avp32.exe" nocase wide ascii
        $a4 = "_avpcc.exe" nocase wide ascii
        $a5 = "_avpm.exe" nocase wide ascii
        $a6 = "aAvgApi.exe" nocase wide ascii
        $a7 = "ackwin32.exe" nocase wide ascii
        $a8 = "adaware.exe" nocase wide ascii
        $a9 = "advxdwin.exe" nocase wide ascii
        $a10 = "agentsvr.exe" nocase wide ascii
        $a11 = "agentw.exe" nocase wide ascii
        $a12 = "alertsvc.exe" nocase wide ascii
        $a13 = "alevir.exe" nocase wide ascii
        $a14 = "alogserv.exe" nocase wide ascii
        $a15 = "amon9x.exe" nocase wide ascii
        $a16 = "anti-trojan.exe" nocase wide ascii
        $a17 = "antivirus.exe" nocase wide ascii
        $a18 = "ants.exe" nocase wide ascii
        $a19 = "apimonitor.exe" nocase wide ascii
        $a20 = "aplica32.exe" nocase wide ascii
        $a21 = "apvxdwin.exe" nocase wide ascii
        $a22 = "arr.exe" nocase wide ascii
        $a23 = "atcon.exe" nocase wide ascii
        $a24 = "atguard.exe" nocase wide ascii
        $a25 = "atro55en.exe" nocase wide ascii
        $a26 = "atupdater.exe" nocase wide ascii
        $a27 = "atwatch.exe" nocase wide ascii
        $a28 = "au.exe" nocase wide ascii
        $a29 = "aupdate.exe" nocase wide ascii
        $a31 = "autodown.exe" nocase wide ascii
        $a32 = "autotrace.exe" nocase wide ascii
        $a33 = "autoupdate.exe" nocase wide ascii
        $a34 = "avconsol.exe" nocase wide ascii
        $a35 = "ave32.exe" nocase wide ascii
        $a36 = "avgcc32.exe" nocase wide ascii
        $a37 = "avgctrl.exe" nocase wide ascii
        $a38 = "avgemc.exe" nocase wide ascii
        $a39 = "avgnt.exe" nocase wide ascii
        $a40 = "avgrsx.exe" nocase wide ascii
        $a41 = "avgserv.exe" nocase wide ascii
        $a42 = "avgserv9.exe" nocase wide ascii
        $a43 = /av(gui|guard|center|gtray|gidsagent|gwdsvc|grsa|gcsrva|gcsrvx).exe/ nocase wide ascii
        $a44 = "avgw.exe" nocase wide ascii
        $a45 = "avkpop.exe" nocase wide ascii
        $a46 = "avkserv.exe" nocase wide ascii
        $a47 = "avkservice.exe" nocase wide ascii
        $a48 = "avkwctl9.exe" nocase wide ascii
        $a49 = "avltmain.exe" nocase wide ascii
        $a50 = "avnt.exe" nocase wide ascii
        $a51 = "avp.exe" nocase wide ascii
        $a52 = "avp.exe" nocase wide ascii
        $a53 = "avp32.exe" nocase wide ascii
        $a54 = "avpcc.exe" nocase wide ascii
        $a55 = "avpdos32.exe" nocase wide ascii
        $a56 = "avpm.exe" nocase wide ascii
        $a57 = "avptc32.exe" nocase wide ascii
        $a58 = "avpupd.exe" nocase wide ascii
        $a59 = "avsched32.exe" nocase wide ascii
        $a60 = "avsynmgr.exe" nocase wide ascii
        $a61 = "avwin.exe" nocase wide ascii
        $a62 = "avwin95.exe" nocase wide ascii
        $a63 = "avwinnt.exe" nocase wide ascii
        $a64 = "avwupd.exe" nocase wide ascii
        $a65 = "avwupd32.exe" nocase wide ascii
        $a66 = "avwupsrv.exe" nocase wide ascii
        $a67 = "avxmonitor9x.exe" nocase wide ascii
        $a68 = "avxmonitornt.exe" nocase wide ascii
        $a69 = "avxquar.exe" nocase wide ascii
        $a73 = "beagle.exe" nocase wide ascii
        $a74 = "belt.exe" nocase wide ascii
        $a75 = "bidef.exe" nocase wide ascii
        $a76 = "bidserver.exe" nocase wide ascii
        $a77 = "bipcp.exe" nocase wide ascii
        $a79 = "bisp.exe" nocase wide ascii
        $a80 = "blackd.exe" nocase wide ascii
        $a81 = "blackice.exe" nocase wide ascii
        $a82 = "blink.exe" nocase wide ascii
        $a83 = "blss.exe" nocase wide ascii
        $a84 = "bootconf.exe" nocase wide ascii
        $a85 = "bootwarn.exe" nocase wide ascii
        $a86 = "borg2.exe" nocase wide ascii
        $a87 = "bpc.exe" nocase wide ascii
        $a89 = "bs120.exe" nocase wide ascii
        $a90 = "bundle.exe" nocase wide ascii
        $a91 = "bvt.exe" nocase wide ascii
        $a92 = "ccapp.exe" nocase wide ascii
        $a93 = "ccevtmgr.exe" nocase wide ascii
        $a94 = "ccpxysvc.exe" nocase wide ascii
        $a95 = "cdp.exe" nocase wide ascii
        $a96 = "cfd.exe" nocase wide ascii
        $a97 = "cfgwiz.exe" nocase wide ascii
        $a98 = "cfiadmin.exe" nocase wide ascii
        $a99 = "cfiaudit.exe" nocase wide ascii
        $a100 = "cfinet.exe" nocase wide ascii
        $a101 = "cfinet32.exe" nocase wide ascii
        $a102 = "claw95.exe" nocase wide ascii
        $a103 = "claw95cf.exe" nocase wide ascii
        $a104 = "clean.exe" nocase wide ascii
        $a105 = "cleaner.exe" nocase wide ascii
        $a106 = "cleaner3.exe" nocase wide ascii
        $a107 = "cleanpc.exe" nocase wide ascii
        $a108 = "click.exe" nocase wide ascii
        $a111 = "cmesys.exe" nocase wide ascii
        $a112 = "cmgrdian.exe" nocase wide ascii
        $a113 = "cmon016.exe" nocase wide ascii
        $a114 = "connectionmonitor.exe" nocase wide ascii
        $a115 = "cpd.exe" nocase wide ascii
        $a116 = "cpf9x206.exe" nocase wide ascii
        $a117 = "cpfnt206.exe" nocase wide ascii
        $a118 = "ctrl.exe" nocase wide ascii fullword
        $a119 = "cv.exe" nocase wide ascii
        $a120 = "cwnb181.exe" nocase wide ascii
        $a121 = "cwntdwmo.exe" nocase wide ascii
        $a123 = "dcomx.exe" nocase wide ascii
        $a124 = "defalert.exe" nocase wide ascii
        $a125 = "defscangui.exe" nocase wide ascii
        $a126 = "defwatch.exe" nocase wide ascii
        $a127 = "deputy.exe" nocase wide ascii
        $a129 = "dllcache.exe" nocase wide ascii
        $a130 = "dllreg.exe" nocase wide ascii
        $a132 = "dpf.exe" nocase wide ascii
        $a134 = "dpps2.exe" nocase wide ascii
        $a135 = "drwatson.exe" nocase wide ascii
        $a136 = "drweb32.exe" nocase wide ascii
        $a137 = "drwebupw.exe" nocase wide ascii
        $a138 = "dssagent.exe" nocase wide ascii
        $a139 = "dvp95.exe" nocase wide ascii
        $a140 = "dvp95_0.exe" nocase wide ascii
        $a141 = "ecengine.exe" nocase wide ascii
        $a142 = "efpeadm.exe" nocase wide ascii
        $a143 = "emsw.exe" nocase wide ascii
        $a145 = "esafe.exe" nocase wide ascii
        $a146 = "escanhnt.exe" nocase wide ascii
        $a147 = "escanv95.exe" nocase wide ascii
        $a148 = "espwatch.exe" nocase wide ascii
        $a150 = "etrustcipe.exe" nocase wide ascii
        $a151 = "evpn.exe" nocase wide ascii
        $a152 = "exantivirus-cnet.exe" nocase wide ascii
        $a153 = "exe.avxw.exe" nocase wide ascii
        $a154 = "expert.exe" nocase wide ascii
        $a156 = "f-agnt95.exe" nocase wide ascii
        $a157 = "f-prot.exe" nocase wide ascii
        $a158 = "f-prot95.exe" nocase wide ascii
        $a159 = "f-stopw.exe" nocase wide ascii
        $a160 = "fameh32.exe" nocase wide ascii
        $a161 = "fast.exe" nocase wide ascii
        $a162 = "fch32.exe" nocase wide ascii
        $a163 = "fih32.exe" nocase wide ascii
        $a164 = "findviru.exe" nocase wide ascii
        $a165 = "firewall.exe" nocase wide ascii
        $a166 = "fnrb32.exe" nocase wide ascii
        $a167 = "fp-win.exe" nocase wide ascii
        $a169 = "fprot.exe" nocase wide ascii
        $a170 = "frw.exe" nocase wide ascii
        $a171 = "fsaa.exe" nocase wide ascii
        $a172 = "fsav.exe" nocase wide ascii
        $a173 = "fsav32.exe" nocase wide ascii
        $a176 = "fsav95.exe" nocase wide ascii
        $a177 = "fsgk32.exe" nocase wide ascii
        $a178 = "fsm32.exe" nocase wide ascii
        $a179 = "fsma32.exe" nocase wide ascii
        $a180 = "fsmb32.exe" nocase wide ascii
        $a181 = "gator.exe" nocase wide ascii
        $a182 = "gbmenu.exe" nocase wide ascii
        $a183 = "gbpoll.exe" nocase wide ascii
        $a184 = "generics.exe" nocase wide ascii
        $a185 = "gmt.exe" nocase wide ascii
        $a186 = "guard.exe" nocase wide ascii
        $a187 = "guarddog.exe" nocase wide ascii
        $a189 = "hbinst.exe" nocase wide ascii
        $a190 = "hbsrv.exe" nocase wide ascii
        $a191 = "hotactio.exe" nocase wide ascii
        $a192 = "hotpatch.exe" nocase wide ascii
        $a193 = "htlog.exe" nocase wide ascii
        $a194 = "htpatch.exe" nocase wide ascii
        $a195 = "hwpe.exe" nocase wide ascii
        $a196 = "hxdl.exe" nocase wide ascii
        $a197 = "hxiul.exe" nocase wide ascii
        $a198 = "iamapp.exe" nocase wide ascii
        $a199 = "iamserv.exe" nocase wide ascii
        $a200 = "iamstats.exe" nocase wide ascii
        $a201 = "ibmasn.exe" nocase wide ascii
        $a202 = "ibmavsp.exe" nocase wide ascii
        $a203 = "icload95.exe" nocase wide ascii
        $a204 = "icloadnt.exe" nocase wide ascii
        $a205 = "icmon.exe" nocase wide ascii
        $a206 = "icsupp95.exe" nocase wide ascii
        $a207 = "icsuppnt.exe" nocase wide ascii
        $a209 = "iedll.exe" nocase wide ascii
        $a210 = "iedriver.exe" nocase wide ascii
        $a212 = "iface.exe" nocase wide ascii
        $a213 = "ifw2000.exe" nocase wide ascii
        $a214 = "inetlnfo.exe" nocase wide ascii
        $a215 = "infus.exe" nocase wide ascii
        $a216 = "infwin.exe" nocase wide ascii
        $a218 = "intdel.exe" nocase wide ascii
        $a219 = "intren.exe" nocase wide ascii
        $a220 = "iomon98.exe" nocase wide ascii
        $a221 = "istsvc.exe" nocase wide ascii
        $a222 = "jammer.exe" nocase wide ascii
        $a224 = "jedi.exe" nocase wide ascii
        $a227 = "kavpf.exe" nocase wide ascii
        $a228 = "kazza.exe" nocase wide ascii
        $a229 = "keenvalue.exe" nocase wide ascii
        $a236 = "ldnetmon.exe" nocase wide ascii
        $a237 = "ldpro.exe" nocase wide ascii
        $a238 = "ldpromenu.exe" nocase wide ascii
        $a239 = "ldscan.exe" nocase wide ascii
        $a240 = "lnetinfo.exe" nocase wide ascii
        $a242 = "localnet.exe" nocase wide ascii
        $a243 = "lockdown.exe" nocase wide ascii
        $a244 = "lockdown2000.exe" nocase wide ascii
        $a245 = "lookout.exe" nocase wide ascii
        $a248 = "luall.exe" nocase wide ascii
        $a249 = "luau.exe" nocase wide ascii
        $a250 = "lucomserver.exe" nocase wide ascii
        $a251 = "luinit.exe" nocase wide ascii
        $a252 = "luspt.exe" nocase wide ascii
        $a253 = "mapisvc32.exe" nocase wide ascii
        $a254 = "mcagent.exe" nocase wide ascii
        $a255 = "mcmnhdlr.exe" nocase wide ascii
        $a256 = "mcshield.exe" nocase wide ascii
        $a257 = "mctool.exe" nocase wide ascii
        $a258 = "mcupdate.exe" nocase wide ascii
        $a259 = "mcvsrte.exe" nocase wide ascii
        $a260 = "mcvsshld.exe" nocase wide ascii
        $a262 = "mfin32.exe" nocase wide ascii
        $a263 = "mfw2en.exe" nocase wide ascii
        $a265 = "mgavrtcl.exe" nocase wide ascii
        $a266 = "mgavrte.exe" nocase wide ascii
        $a267 = "mghtml.exe" nocase wide ascii
        $a268 = "mgui.exe" nocase wide ascii
        $a269 = "minilog.exe" nocase wide ascii
        $a270 = "mmod.exe" nocase wide ascii
        $a271 = "monitor.exe" nocase wide ascii
        $a272 = "moolive.exe" nocase wide ascii
        $a273 = "mostat.exe" nocase wide ascii
        $a274 = "mpfagent.exe" nocase wide ascii
        $a275 = "mpfservice.exe" nocase wide ascii
        $a276 = "mpftray.exe" nocase wide ascii
        $a277 = "mrflux.exe" nocase wide ascii
        $a278 = "msapp.exe" nocase wide ascii
        $a279 = "msbb.exe" nocase wide ascii
        $a280 = "msblast.exe" nocase wide ascii
        $a281 = "mscache.exe" nocase wide ascii
        $a282 = "msccn32.exe" nocase wide ascii
        $a283 = "mscman.exe" nocase wide ascii
        $a285 = "msdm.exe" nocase wide ascii
        $a286 = "msdos.exe" nocase wide ascii
        $a287 = "msiexec16.exe" nocase wide ascii
        $a288 = "msinfo32.exe" nocase wide ascii
        $a289 = "mslaugh.exe" nocase wide ascii
        $a290 = "msmgt.exe" nocase wide ascii
        $a291 = "msmsgri32.exe" nocase wide ascii
        $a292 = "mssmmc32.exe" nocase wide ascii
        $a293 = "mssys.exe" nocase wide ascii
        $a294 = "msvxd.exe" nocase wide ascii
        $a295 = "mu0311ad.exe" nocase wide ascii
        $a296 = "mwatch.exe" nocase wide ascii
        $a297 = "n32scanw.exe" nocase wide ascii
        $a298 = "nav.exe" nocase wide ascii
        $a300 = "navapsvc.exe" nocase wide ascii
        $a301 = "navapw32.exe" nocase wide ascii
        $a302 = "navdx.exe" nocase wide ascii
        $a303 = "navlu32.exe" nocase wide ascii
        $a304 = "navnt.exe" nocase wide ascii
        $a305 = "navstub.exe" nocase wide ascii
        $a306 = "navw32.exe" nocase wide ascii
        $a307 = "navwnt.exe" nocase wide ascii
        $a308 = "nc2000.exe" nocase wide ascii
        $a309 = "ncinst4.exe" nocase wide ascii
        $a310 = "ndd32.exe" nocase wide ascii
        $a311 = "neomonitor.exe" nocase wide ascii
        $a312 = "neowatchlog.exe" nocase wide ascii
        $a313 = "netarmor.exe" nocase wide ascii
        $a314 = "netd32.exe" nocase wide ascii
        $a315 = "netinfo.exe" nocase wide ascii
        $a317 = "netscanpro.exe" nocase wide ascii
        $a320 = "netutils.exe" nocase wide ascii
        $a321 = "nisserv.exe" nocase wide ascii
        $a322 = "nisum.exe" nocase wide ascii
        $a323 = "nmain.exe" nocase wide ascii
        $a324 = "nod32.exe" nocase wide ascii
        $a325 = "normist.exe" nocase wide ascii
        $a327 = "notstart.exe" nocase wide ascii
        $a329 = "npfmessenger.exe" nocase wide ascii
        $a330 = "nprotect.exe" nocase wide ascii
        $a331 = "npscheck.exe" nocase wide ascii
        $a332 = "npssvc.exe" nocase wide ascii
        $a333 = "nsched32.exe" nocase wide ascii
        $a334 = "nssys32.exe" nocase wide ascii
        $a335 = "nstask32.exe" nocase wide ascii
        $a336 = "nsupdate.exe" nocase wide ascii
        $a338 = "ntrtscan.exe" nocase wide ascii
        $a340 = "ntxconfig.exe" nocase wide ascii
        $a341 = "nui.exe" nocase wide ascii
        $a342 = "nupgrade.exe" nocase wide ascii
        $a343 = "nvarch16.exe" nocase wide ascii
        $a344 = "nvc95.exe" nocase wide ascii
        $a345 = "nvsvc32.exe" nocase wide ascii
        $a346 = "nwinst4.exe" nocase wide ascii
        $a347 = "nwservice.exe" nocase wide ascii
        $a348 = "nwtool16.exe" nocase wide ascii
        $a350 = "onsrvr.exe" nocase wide ascii
        $a351 = "optimize.exe" nocase wide ascii
        $a352 = "ostronet.exe" nocase wide ascii
        $a353 = "otfix.exe" nocase wide ascii
        $a354 = "outpost.exe" nocase wide ascii
        $a360 = "pavcl.exe" nocase wide ascii
        $a361 = "pavproxy.exe" nocase wide ascii
        $a362 = "pavsched.exe" nocase wide ascii
        $a363 = "pavw.exe" nocase wide ascii
        $a364 = "pccwin98.exe" nocase wide ascii
        $a365 = "pcfwallicon.exe" nocase wide ascii
        $a367 = "pcscan.exe" nocase wide ascii
        $a369 = "periscope.exe" nocase wide ascii
        $a370 = "persfw.exe" nocase wide ascii
        $a371 = "perswf.exe" nocase wide ascii
        $a372 = "pf2.exe" nocase wide ascii
        $a373 = "pfwadmin.exe" nocase wide ascii
        $a374 = "pgmonitr.exe" nocase wide ascii
        $a375 = "pingscan.exe" nocase wide ascii
        $a376 = "platin.exe" nocase wide ascii
        $a377 = "pop3trap.exe" nocase wide ascii
        $a378 = "poproxy.exe" nocase wide ascii
        $a379 = "popscan.exe" nocase wide ascii
        $a380 = "portdetective.exe" nocase wide ascii
        $a381 = "portmonitor.exe" nocase wide ascii
        $a382 = "powerscan.exe" nocase wide ascii
        $a383 = "ppinupdt.exe" nocase wide ascii
        $a384 = "pptbc.exe" nocase wide ascii
        $a385 = "ppvstop.exe" nocase wide ascii
        $a387 = "prmt.exe" nocase wide ascii
        $a388 = "prmvr.exe" nocase wide ascii
        $a389 = "procdump.exe" nocase wide ascii
        $a390 = "processmonitor.exe" nocase wide ascii
        $a392 = "programauditor.exe" nocase wide ascii
        $a393 = "proport.exe" nocase wide ascii
        $a394 = "protectx.exe" nocase wide ascii
        $a395 = "pspf.exe" nocase wide ascii
        $a396 = "purge.exe" nocase wide ascii
        $a397 = "qconsole.exe" nocase wide ascii
        $a398 = "qserver.exe" nocase wide ascii
        $a399 = "rapapp.exe" nocase wide ascii
        $a400 = "rav7.exe" nocase wide ascii
        $a401 = "rav7win.exe" nocase wide ascii
        $a404 = "rb32.exe" nocase wide ascii
        $a405 = "rcsync.exe" nocase wide ascii
        $a406 = "realmon.exe" nocase wide ascii
        $a407 = "reged.exe" nocase wide ascii
        $a410 = "rescue.exe" nocase wide ascii
        $a412 = "rrguard.exe" nocase wide ascii
        $a413 = "rshell.exe" nocase wide ascii
        $a414 = "rtvscan.exe" nocase wide ascii
        $a415 = "rtvscn95.exe" nocase wide ascii
        $a416 = "rulaunch.exe" nocase wide ascii
        $a421 = "safeweb.exe" nocase wide ascii
        $a422 = "sahagent.exe" nocase wide ascii
        $a424 = "savenow.exe" nocase wide ascii
        $a425 = "sbserv.exe" nocase wide ascii
        $a428 = "scan32.exe" nocase wide ascii
        $a430 = "scanpm.exe" nocase wide ascii
        $a431 = "scrscan.exe" nocase wide ascii
        $a435 = "sfc.exe" nocase wide ascii
        $a436 = "sgssfw32.exe" nocase wide ascii
        $a439 = "shn.exe" nocase wide ascii
        $a440 = "showbehind.exe" nocase wide ascii
        $a441 = "smc.exe" nocase wide ascii
        $a442 = "sms.exe" nocase wide ascii
        $a443 = "smss32.exe" nocase wide ascii
        $a445 = "sofi.exe" nocase wide ascii
        $a447 = "spf.exe" nocase wide ascii
        $a449 = "spoler.exe" nocase wide ascii
        $a450 = "spoolcv.exe" nocase wide ascii
        $a451 = "spoolsv32.exe" nocase wide ascii
        $a452 = "spyxx.exe" nocase wide ascii
        $a453 = "srexe.exe" nocase wide ascii
        $a454 = "srng.exe" nocase wide ascii
        $a455 = "ss3edit.exe" nocase wide ascii
        $a457 = "ssgrate.exe" nocase wide ascii
        $a458 = "st2.exe" nocase wide ascii fullword
        $a461 = "supftrl.exe" nocase wide ascii
        $a470 = "symproxysvc.exe" nocase wide ascii
        $a471 = "symtray.exe" nocase wide ascii
        $a472 = "sysedit.exe" nocase wide ascii
        $a480 = "taumon.exe" nocase wide ascii
        $a481 = "tbscan.exe" nocase wide ascii
        $a483 = "tca.exe" nocase wide ascii
        $a484 = "tcm.exe" nocase wide ascii
        $a488 = "teekids.exe" nocase wide ascii
        $a489 = "tfak.exe" nocase wide ascii
        $a490 = "tfak5.exe" nocase wide ascii
        $a491 = "tgbob.exe" nocase wide ascii
        $a492 = "titanin.exe" nocase wide ascii
        $a493 = "titaninxp.exe" nocase wide ascii
        $a496 = "trjscan.exe" nocase wide ascii
        $a500 = "tvmd.exe" nocase wide ascii
        $a501 = "tvtmd.exe" nocase wide ascii
        $a513 = "vet32.exe" nocase wide ascii
        $a514 = "vet95.exe" nocase wide ascii
        $a515 = "vettray.exe" nocase wide ascii
        $a517 = "vir-help.exe" nocase wide ascii
        $a519 = "vnlan300.exe" nocase wide ascii
        $a520 = "vnpc3000.exe" nocase wide ascii
        $a521 = "vpc32.exe" nocase wide ascii
        $a522 = "vpc42.exe" nocase wide ascii
        $a523 = "vpfw30s.exe" nocase wide ascii
        $a524 = "vptray.exe" nocase wide ascii
        $a525 = "vscan40.exe" nocase wide ascii
        $a527 = "vsched.exe" nocase wide ascii
        $a528 = "vsecomr.exe" nocase wide ascii
        $a529 = "vshwin32.exe" nocase wide ascii
        $a531 = "vsmain.exe" nocase wide ascii
        $a532 = "vsmon.exe" nocase wide ascii
        $a533 = "vsstat.exe" nocase wide ascii
        $a534 = "vswin9xe.exe" nocase wide ascii
        $a535 = "vswinntse.exe" nocase wide ascii
        $a536 = "vswinperse.exe" nocase wide ascii
        $a537 = "w32dsm89.exe" nocase wide ascii
        $a538 = "w9x.exe" nocase wide ascii
        $a541 = "webscanx.exe" nocase wide ascii
        $a543 = "wfindv32.exe" nocase wide ascii
        $a545 = "wimmun32.exe" nocase wide ascii
        $a566 = "wnad.exe" nocase wide ascii
        $a567 = "wnt.exe" nocase wide ascii
        $a568 = "wradmin.exe" nocase wide ascii
        $a569 = "wrctrl.exe" nocase wide ascii
        $a570 = "wsbgate.exe" nocase wide ascii
        $a573 = "wyvernworksfirewall.exe" nocase wide ascii
        $a575 = "zapro.exe" nocase wide ascii
        $a577 = "zatutor.exe" nocase wide ascii
        $a579 = "zonealarm.exe" nocase wide ascii
        // Strings from Dubnium below
        $a580 = "QQPCRTP.exe" nocase wide ascii
        $a581 = "QQPCTray.exe" nocase wide ascii
        $a582 = "ZhuDongFangYu.exe" nocase wide ascii
        $a583 = /360(tray|sd|rp).exe/ nocase wide ascii
        $a584 = /qh(safetray|watchdog|activedefense).exe/ nocase wide ascii
        $a585 = "McNASvc.exe" nocase wide ascii
        $a586 = "MpfSrv.exe" nocase wide ascii
        $a587 = "McProxy.exe" nocase wide ascii
        $a588 = "mcmscsvc.exe" nocase wide ascii
        $a589 = "McUICnt.exe" nocase wide ascii
        $a590 = /ui(WatchDog|seagnt|winmgr).exe/ nocase wide ascii
        $a591 = "ufseagnt.exe" nocase wide ascii
        $a592 = /core(serviceshell|frameworkhost).exe/ nocase wide ascii
        $a593 = /ay(agent|rtsrv|updsrv).aye/ nocase wide ascii
        $a594 = /avast(ui|svc).exe/ nocase wide ascii
        $a595 = /ms(seces|mpeng).exe/ nocase wide ascii
        $a596 = "afwserv.exe" nocase wide ascii
        $a597 = "FiddlerUser"

    condition:
        any of them
}

rule VM_Generic_Detection : AntiVM
{
    meta:
        description = "Tries to detect virtualized environments"
    strings:
        $a0 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $a1 = "HARDWARE\\Description\\System" nocase wide ascii
        $a2 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase wide ascii
        $a3 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
        $redpill = { 0F 01 0D 00 00 00 00 C3 } // Copied from the Cuckoo project

        // CLSIDs used to detect if speakers are present. Hoping this will not cause false positives.
        $teslacrypt1 = { D1 29 06 E3 E5 27 CE 11 87 5D 00 60 8C B7 80 66 } // CLSID_AudioRender
        $teslacrypt2 = { B3 EB 36 E4 4F 52 CE 11 9F 53 00 20 AF 0B A7 70 } // CLSID_FilterGraph

    condition:
        any of ($a*) or $redpill or all of ($teslacrypt*)
}

rule VMWare_Detection : AntiVM
{
    meta:
        description = "Looks for VMWare presence"
        author = "Cuckoo project"

    strings:
        $a0 = "VMXh"
        $a1 = "vmware" nocase wide ascii
        $vmware4 = "hgfs.sys" nocase wide ascii
        $vmware5 = "mhgfs.sys" nocase wide ascii
        $vmware6 = "prleth.sys" nocase wide ascii
        $vmware7 = "prlfs.sys" nocase wide ascii
        $vmware8 = "prlmouse.sys" nocase wide ascii
        $vmware9 = "prlvideo.sys" nocase wide ascii
        $vmware10 = "prl_pv32.sys" nocase wide ascii
        $vmware11 = "vpc-s3.sys" nocase wide ascii
        $vmware12 = "vmsrvc.sys" nocase wide ascii
        $vmware13 = "vmx86.sys" nocase wide ascii
        $vmware14 = "vmnet.sys" nocase wide ascii
        $vmware15 = "vmicheartbeat" nocase wide ascii
        $vmware16 = "vmicvss" nocase wide ascii
        $vmware17 = "vmicshutdown" nocase wide ascii
        $vmware18 = "vmicexchange" nocase wide ascii
        $vmware19 = "vmdebug" nocase wide ascii
        $vmware20 = "vmmouse" nocase wide ascii
        $vmware21 = "vmtools" nocase wide ascii
        $vmware22 = "VMMEMCTL" nocase wide ascii
        $vmware23 = "vmx86" nocase wide ascii

        // VMware MAC addresses
        $vmware_mac_1a = "00-05-69" wide ascii
        $vmware_mac_1b = "00:05:69" wide ascii
        $vmware_mac_1c = "000569" wide ascii
        $vmware_mac_2a = "00-50-56" wide ascii
        $vmware_mac_2b = "00:50:56" wide ascii
        $vmware_mac_2c = "005056" wide ascii
        $vmware_mac_3a = "00-0C-29" nocase wide ascii
        $vmware_mac_3b = "00:0C:29" nocase wide ascii
        $vmware_mac_3c = "000C29" nocase wide ascii
        $vmware_mac_4a = "00-1C-14" nocase wide ascii
        $vmware_mac_4b = "00:1C:14" nocase wide ascii
        $vmware_mac_4c = "001C14" nocase wide ascii

        // PCI Vendor IDs, from Hacking Team's leak
        $virtualbox_vid_1 = "VEN_15ad" nocase wide ascii

    condition:
        any of them
}

rule Sandboxie_Detection : AntiVM
{
    meta:
        description = "Looks for Sandboxie presence"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $sbie = "SbieDll.dll" nocase wide ascii
        $buster = /LOG_API(_VERBOSE)?.DLL/ nocase wide ascii
        $sbie_process_1 = "SbieSvc.exe" nocase wide ascii
        $sbie_process_2 = "SbieCtrl.exe" nocase wide ascii
        $sbie_process_3 = "SandboxieRpcSs.exe" nocase wide ascii
        $sbie_process_4 = "SandboxieDcomLaunch.exe" nocase wide ascii
        $sbie_process_5 = "SandboxieCrypto.exe" nocase wide ascii
        $sbie_process_6 = "SandboxieBITS.exe" nocase wide ascii
        $sbie_process_7 = "SandboxieWUAU.exe" nocase wide ascii

    condition:
        any of them
}

rule VirtualPC_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualPC presence"
        author = "Cuckoo project"

    strings:
        $a0 = {0F 3F 07 0B }
        $virtualpc1 = "vpcbus" nocase wide ascii
        $virtualpc2 = "vpc-s3" nocase wide ascii
        $virtualpc3 = "vpcuhub" nocase wide ascii
        $virtualpc4 = "msvmmouf" nocase wide ascii

    condition:
        any of them
}

rule VirtualBox_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualBox presence"
        author = "Cuckoo project"
    strings:
        $virtualbox1 = "VBoxHook.dll" nocase wide ascii
        $virtualbox2 = "VBoxService" nocase wide ascii
        $virtualbox3 = "VBoxTray" nocase wide ascii
        $virtualbox4 = "VBoxMouse" nocase wide ascii
        $virtualbox5 = "VBoxGuest" nocase wide ascii
        $virtualbox6 = "VBoxSF" nocase wide ascii
        $virtualbox7 = "VBoxGuestAdditions" nocase wide ascii
        $virtualbox8 = "VBOX HARDDISK" nocase wide ascii
        $virtualbox9 = "vboxservice" nocase wide ascii
        $virtualbox10 = "vboxtray" nocase wide ascii

        // MAC addresses
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

        // PCI Vendor IDs, from Hacking Team's leak
        $virtualbox_vid_1 = "VEN_80EE" nocase wide ascii

        // Registry keys
        $virtualbox_reg_1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
        $virtualbox_reg_2 = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\VBOX__/ nocase wide ascii

        // Other
        $virtualbox_files = /C:\\Windows\\System32\\drivers\\vbox.{15}\.(sys|dll)/ nocase wide ascii
        $virtualbox_services = "System\\ControlSet001\\Services\\VBox[A-Za-z]+" nocase wide ascii
        $virtualbox_pipe = /\\\\.\\pipe\\(VBoxTrayIPC|VBoxMiniRdDN)/ nocase wide ascii
        $virtualbox_window = /VBoxTrayToolWnd(Class)?/ nocase wide ascii
    condition:
        any of them
}

rule Parallels_Detection : AntiVM
{
    meta:
        description = "Looks for Parallels presence"
    strings:
        $a0 = "magi"
        $a1 = "c!nu"
        $a2 = "mber"

        // PCI Vendor IDs, from Hacking Team's leak
        $parallels_vid_1 = "VEN_80EE" nocase wide ascii
    condition:
        all of them
}

rule Qemu_Detection : AntiVM
{
    meta:
        description = "Looks for Qemu presence"
    strings:
        $a0 = "qemu" nocase wide ascii
    condition:
        any of them
}

rule Dropper_Strings
{
    meta:
        description = "May have dropper capabilities"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "CurrentVersion\\Run" nocase wide ascii
        $a1 = "CurrentControlSet\\Services" nocase wide ascii
        $a2 = "Programs\\Startup" nocase wide ascii
        $a3 = "%temp%" nocase wide ascii
        $a4 = "%allusersprofile%" nocase wide ascii
    condition:
        any of them
}

rule AutoIT_compiled_script
{
    meta:
        description = "Is an AutoIT compiled script"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "AutoIt Error" ascii wide
        $a1 = "reserved for AutoIt internal use" ascii wide
    condition:
        any of them
}

rule WMI_strings
{
    meta:
        description = "Accesses the WMI"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        // WMI namespaces which may be referenced in the ConnectServer call. All in the form of "ROOT\something"
        $a0 = /ROOT\\(CIMV2|AccessLogging|ADFS|aspnet|Cli|Hardware|interop|InventoryLogging|Microsoft.{10}|Policy|RSOP|SECURITY|ServiceModel|snmpStandardCimv2|subscription|virtualization|WebAdministration|WMI)/ nocase ascii wide
    condition:
        any of them
}

rule Obfuscated_Strings
{
    meta:
        description = "Contains obfuscated function names"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = { (46 | 66) 64 75 (51 | 71) 73 6E 62 (40 | 60) 65 65 73 64 72 72 }
        $a1 = { (45 | 65) 67 76 (52 | 72) 70 6D 61 (43 | 63) 66 66 70 67 71 71 }
        $a2 = { (44 | 64) 66 77 (53 | 73) 71 6C 60 (42 | 62) 67 67 71 66 70 70 }
        $a3 = { (43 | 63) 61 70 (54 | 74) 76 6B 67 (45 | 65) 60 60 76 61 77 77 }
        $a4 = { (42 | 62) 60 71 (55 | 75) 77 6A 66 (44 | 64) 61 61 77 60 76 76 }
        $a5 = { (41 | 61) 63 72 (56 | 76) 74 69 65 (47 | 67) 62 62 74 63 75 75 }
        $a6 = { (40 | 60) 62 73 (57 | 77) 75 68 64 (46 | 66) 63 63 75 62 74 74 }
        $a7 = { (4F | 6F) 6D 7C (58 | 78) 7A 67 6B (49 | 69) 6C 6C 7A 6D 7B 7B }
        $a8 = { (4E | 6E) 6C 7D (59 | 79) 7B 66 6A (48 | 68) 6D 6D 7B 6C 7A 7A }
        $a9 = { (4D | 6D) 6F 7E (5A | 7A) 78 65 69 (4B | 6B) 6E 6E 78 6F 79 79 }
        $a10 = { (4C | 6C) 6E 7F (5B | 7B) 79 64 68 (4A | 6A) 6F 6F 79 6E 78 78 }
        $a11 = { (4B | 6B) 69 78 (5C | 7C) 7E 63 6F (4D | 6D) 68 68 7E 69 7F 7F }
        $a12 = { (4A | 6A) 68 79 (5D | 7D) 7F 62 6E (4C | 6C) 69 69 7F 68 7E 7E }
        $a13 = { (49 | 69) 6B 7A (5E | 7E) 7C 61 6D (4F | 6F) 6A 6A 7C 6B 7D 7D }
        $a14 = { (48 | 68) 6A 7B (5F | 7F) 7D 60 6C (4E | 6E) 6B 6B 7D 6A 7C 7C }
        $a15 = { (57 | 77) 75 64 (40 | 60) 62 7F 73 (51 | 71) 74 74 62 75 63 63 }
        $a16 = { (56 | 76) 74 65 (41 | 61) 63 7E 72 (50 | 70) 75 75 63 74 62 62 }
        $a17 = { (55 | 75) 77 66 (42 | 62) 60 7D 71 (53 | 73) 76 76 60 77 61 61 }
        $a18 = { (54 | 74) 76 67 (43 | 63) 61 7C 70 (52 | 72) 77 77 61 76 60 60 }
        $a19 = { (53 | 73) 71 60 (44 | 64) 66 7B 77 (55 | 75) 70 70 66 71 67 67 }
        $a20 = { (52 | 72) 70 61 (45 | 65) 67 7A 76 (54 | 74) 71 71 67 70 66 66 }
        $a21 = { (51 | 71) 73 62 (46 | 66) 64 79 75 (57 | 77) 72 72 64 73 65 65 }
        $a22 = { (50 | 70) 72 63 (47 | 67) 65 78 74 (56 | 76) 73 73 65 72 64 64 }
        $a23 = { (5F | 7F) 7D 6C (48 | 68) 6A 77 7B (59 | 79) 7C 7C 6A 7D 6B 6B }
        $a24 = { (5E | 7E) 7C 6D (49 | 69) 6B 76 7A (58 | 78) 7D 7D 6B 7C 6A 6A }
        $a25 = { (5D | 7D) 7F 6E (4A | 6A) 68 75 79 (5B | 7B) 7E 7E 68 7F 69 69 }
        $a26 = { (5C | 7C) 7E 6F (4B | 6B) 69 74 78 (5A | 7A) 7F 7F 69 7E 68 68 }
        $a27 = { (5B | 7B) 79 68 (4C | 6C) 6E 73 7F (5D | 7D) 78 78 6E 79 6F 6F }
        $a28 = { (5A | 7A) 78 69 (4D | 6D) 6F 72 7E (5C | 7C) 79 79 6F 78 6E 6E }
        $a29 = { (59 | 79) 7B 6A (4E | 6E) 6C 71 7D (5F | 7F) 7A 7A 6C 7B 6D 6D }
        $a30 = { (58 | 78) 7A 6B (4F | 6F) 6D 70 7C (5E | 7E) 7B 7B 6D 7A 6C 6C }
        // XOR 0x20 removed because it toggles capitalization and causes [Gg]ET[Pp]ROC[Aa]DDRESS to match.
        $a32 = { (66 | 46) 44 55 (71 | 51) 53 4E 42 (60 | 40) 45 45 53 44 52 52 }
        $a33 = { (65 | 45) 47 56 (72 | 52) 50 4D 41 (63 | 43) 46 46 50 47 51 51 }
        $a34 = { (64 | 44) 46 57 (73 | 53) 51 4C 40 (62 | 42) 47 47 51 46 50 50 }
        $a35 = { (63 | 43) 41 50 (74 | 54) 56 4B 47 (65 | 45) 40 40 56 41 57 57 }
        $a36 = { (62 | 42) 40 51 (75 | 55) 57 4A 46 (64 | 44) 41 41 57 40 56 56 }
        $a37 = { (61 | 41) 43 52 (76 | 56) 54 49 45 (67 | 47) 42 42 54 43 55 55 }
        $a38 = { (60 | 40) 42 53 (77 | 57) 55 48 44 (66 | 46) 43 43 55 42 54 54 }
        $a39 = { (6F | 4F) 4D 5C (78 | 58) 5A 47 4B (69 | 49) 4C 4C 5A 4D 5B 5B }
        $a40 = { (6E | 4E) 4C 5D (79 | 59) 5B 46 4A (68 | 48) 4D 4D 5B 4C 5A 5A }
        $a41 = { (6D | 4D) 4F 5E (7A | 5A) 58 45 49 (6B | 4B) 4E 4E 58 4F 59 59 }
        $a42 = { (6C | 4C) 4E 5F (7B | 5B) 59 44 48 (6A | 4A) 4F 4F 59 4E 58 58 }
        $a43 = { (6B | 4B) 49 58 (7C | 5C) 5E 43 4F (6D | 4D) 48 48 5E 49 5F 5F }
        $a44 = { (6A | 4A) 48 59 (7D | 5D) 5F 42 4E (6C | 4C) 49 49 5F 48 5E 5E }
        $a45 = { (69 | 49) 4B 5A (7E | 5E) 5C 41 4D (6F | 4F) 4A 4A 5C 4B 5D 5D }
        $a46 = { (68 | 48) 4A 5B (7F | 5F) 5D 40 4C (6E | 4E) 4B 4B 5D 4A 5C 5C }
        $a47 = { (77 | 57) 55 44 (60 | 40) 42 5F 53 (71 | 51) 54 54 42 55 43 43 }
        $a48 = { (76 | 56) 54 45 (61 | 41) 43 5E 52 (70 | 50) 55 55 43 54 42 42 }
        $a49 = { (75 | 55) 57 46 (62 | 42) 40 5D 51 (73 | 53) 56 56 40 57 41 41 }
        $a50 = { (74 | 54) 56 47 (63 | 43) 41 5C 50 (72 | 52) 57 57 41 56 40 40 }
        $a51 = { (73 | 53) 51 40 (64 | 44) 46 5B 57 (75 | 55) 50 50 46 51 47 47 }
        $a52 = { (72 | 52) 50 41 (65 | 45) 47 5A 56 (74 | 54) 51 51 47 50 46 46 }
        $a53 = { (71 | 51) 53 42 (66 | 46) 44 59 55 (77 | 57) 52 52 44 53 45 45 }
        $a54 = { (70 | 50) 52 43 (67 | 47) 45 58 54 (76 | 56) 53 53 45 52 44 44 }
        $a55 = { (7F | 5F) 5D 4C (68 | 48) 4A 57 5B (79 | 59) 5C 5C 4A 5D 4B 4B }
        $a56 = { (7E | 5E) 5C 4D (69 | 49) 4B 56 5A (78 | 58) 5D 5D 4B 5C 4A 4A }
        $a57 = { (7D | 5D) 5F 4E (6A | 4A) 48 55 59 (7B | 5B) 5E 5E 48 5F 49 49 }
        $a58 = { (7C | 5C) 5E 4F (6B | 4B) 49 54 58 (7A | 5A) 5F 5F 49 5E 48 48 }
        $a59 = { (7B | 5B) 59 48 (6C | 4C) 4E 53 5F (7D | 5D) 58 58 4E 59 4F 4F }
        $a60 = { (7A | 5A) 58 49 (6D | 4D) 4F 52 5E (7C | 5C) 59 59 4F 58 4E 4E }
        $a61 = { (79 | 59) 5B 4A (6E | 4E) 4C 51 5D (7F | 5F) 5A 5A 4C 5B 4D 4D }
        $a62 = { (78 | 58) 5A 4B (6F | 4F) 4D 50 5C (7E | 5E) 5B 5B 4D 5A 4C 4C }
        $a63 = { (07 | 27) 25 34 (10 | 30) 32 2F 23 (01 | 21) 24 24 32 25 33 33 }
        $a64 = { (06 | 26) 24 35 (11 | 31) 33 2E 22 (00 | 20) 25 25 33 24 32 32 }
        $a65 = { (05 | 25) 27 36 (12 | 32) 30 2D 21 (03 | 23) 26 26 30 27 31 31 }
        $a66 = { (04 | 24) 26 37 (13 | 33) 31 2C 20 (02 | 22) 27 27 31 26 30 30 }
        $a67 = { (03 | 23) 21 30 (14 | 34) 36 2B 27 (05 | 25) 20 20 36 21 37 37 }
        $a68 = { (02 | 22) 20 31 (15 | 35) 37 2A 26 (04 | 24) 21 21 37 20 36 36 }
        $a69 = { (01 | 21) 23 32 (16 | 36) 34 29 25 (07 | 27) 22 22 34 23 35 35 }
        $a70 = { (00 | 20) 22 33 (17 | 37) 35 28 24 (06 | 26) 23 23 35 22 34 34 }
        $a71 = { (0F | 2F) 2D 3C (18 | 38) 3A 27 2B (09 | 29) 2C 2C 3A 2D 3B 3B }
        $a72 = { (0E | 2E) 2C 3D (19 | 39) 3B 26 2A (08 | 28) 2D 2D 3B 2C 3A 3A }
        $a73 = { (0D | 2D) 2F 3E (1A | 3A) 38 25 29 (0B | 2B) 2E 2E 38 2F 39 39 }
        $a74 = { (0C | 2C) 2E 3F (1B | 3B) 39 24 28 (0A | 2A) 2F 2F 39 2E 38 38 }
        $a75 = { (0B | 2B) 29 38 (1C | 3C) 3E 23 2F (0D | 2D) 28 28 3E 29 3F 3F }
        $a76 = { (0A | 2A) 28 39 (1D | 3D) 3F 22 2E (0C | 2C) 29 29 3F 28 3E 3E }
        $a77 = { (09 | 29) 2B 3A (1E | 3E) 3C 21 2D (0F | 2F) 2A 2A 3C 2B 3D 3D }
        $a78 = { (08 | 28) 2A 3B (1F | 3F) 3D 20 2C (0E | 2E) 2B 2B 3D 2A 3C 3C }
        $a79 = { (17 | 37) 35 24 (00 | 20) 22 3F 33 (11 | 31) 34 34 22 35 23 23 }
        $a80 = { (16 | 36) 34 25 (01 | 21) 23 3E 32 (10 | 30) 35 35 23 34 22 22 }
        $a81 = { (15 | 35) 37 26 (02 | 22) 20 3D 31 (13 | 33) 36 36 20 37 21 21 }
        $a82 = { (14 | 34) 36 27 (03 | 23) 21 3C 30 (12 | 32) 37 37 21 36 20 20 }
        $a83 = { (13 | 33) 31 20 (04 | 24) 26 3B 37 (15 | 35) 30 30 26 31 27 27 }
        $a84 = { (12 | 32) 30 21 (05 | 25) 27 3A 36 (14 | 34) 31 31 27 30 26 26 }
        $a85 = { (11 | 31) 33 22 (06 | 26) 24 39 35 (17 | 37) 32 32 24 33 25 25 }
        $a86 = { (10 | 30) 32 23 (07 | 27) 25 38 34 (16 | 36) 33 33 25 32 24 24 }
        $a87 = { (1F | 3F) 3D 2C (08 | 28) 2A 37 3B (19 | 39) 3C 3C 2A 3D 2B 2B }
        $a88 = { (1E | 3E) 3C 2D (09 | 29) 2B 36 3A (18 | 38) 3D 3D 2B 3C 2A 2A }
        $a89 = { (1D | 3D) 3F 2E (0A | 2A) 28 35 39 (1B | 3B) 3E 3E 28 3F 29 29 }
        $a90 = { (1C | 3C) 3E 2F (0B | 2B) 29 34 38 (1A | 3A) 3F 3F 29 3E 28 28 }
        $a91 = { (1B | 3B) 39 28 (0C | 2C) 2E 33 3F (1D | 3D) 38 38 2E 39 2F 2F }
        $a92 = { (1A | 3A) 38 29 (0D | 2D) 2F 32 3E (1C | 3C) 39 39 2F 38 2E 2E }
        $a93 = { (19 | 39) 3B 2A (0E | 2E) 2C 31 3D (1F | 3F) 3A 3A 2C 3B 2D 2D }
        $a94 = { (18 | 38) 3A 2B (0F | 2F) 2D 30 3C (1E | 3E) 3B 3B 2D 3A 2C 2C }
        $a95 = { (27 | 07) 05 14 (30 | 10) 12 0F 03 (21 | 01) 04 04 12 05 13 13 }
        $a96 = { (26 | 06) 04 15 (31 | 11) 13 0E 02 (20 | 00) 05 05 13 04 12 12 }
        $a97 = { (25 | 05) 07 16 (32 | 12) 10 0D 01 (23 | 03) 06 06 10 07 11 11 }
        $a98 = { (24 | 04) 06 17 (33 | 13) 11 0C 00 (22 | 02) 07 07 11 06 10 10 }
        $a99 = { (23 | 03) 01 10 (34 | 14) 16 0B 07 (25 | 05) 00 00 16 01 17 17 }
        $a100 = { (22 | 02) 00 11 (35 | 15) 17 0A 06 (24 | 04) 01 01 17 00 16 16 }
        $a101 = { (21 | 01) 03 12 (36 | 16) 14 09 05 (27 | 07) 02 02 14 03 15 15 }
        $a102 = { (20 | 00) 02 13 (37 | 17) 15 08 04 (26 | 06) 03 03 15 02 14 14 }
        $a103 = { (2F | 0F) 0D 1C (38 | 18) 1A 07 0B (29 | 09) 0C 0C 1A 0D 1B 1B }
        $a104 = { (2E | 0E) 0C 1D (39 | 19) 1B 06 0A (28 | 08) 0D 0D 1B 0C 1A 1A }
        $a105 = { (2D | 0D) 0F 1E (3A | 1A) 18 05 09 (2B | 0B) 0E 0E 18 0F 19 19 }
        $a106 = { (2C | 0C) 0E 1F (3B | 1B) 19 04 08 (2A | 0A) 0F 0F 19 0E 18 18 }
        $a107 = { (2B | 0B) 09 18 (3C | 1C) 1E 03 0F (2D | 0D) 08 08 1E 09 1F 1F }
        $a108 = { (2A | 0A) 08 19 (3D | 1D) 1F 02 0E (2C | 0C) 09 09 1F 08 1E 1E }
        $a109 = { (29 | 09) 0B 1A (3E | 1E) 1C 01 0D (2F | 0F) 0A 0A 1C 0B 1D 1D }
        $a110 = { (28 | 08) 0A 1B (3F | 1F) 1D 00 0C (2E | 0E) 0B 0B 1D 0A 1C 1C }
        $a111 = { (37 | 17) 15 04 (20 | 00) 02 1F 13 (31 | 11) 14 14 02 15 03 03 }
        $a112 = { (36 | 16) 14 05 (21 | 01) 03 1E 12 (30 | 10) 15 15 03 14 02 02 }
        $a113 = { (35 | 15) 17 06 (22 | 02) 00 1D 11 (33 | 13) 16 16 00 17 01 01 }
        $a114 = { (34 | 14) 16 07 (23 | 03) 01 1C 10 (32 | 12) 17 17 01 16 00 00 }
        $a115 = { (33 | 13) 11 00 (24 | 04) 06 1B 17 (35 | 15) 10 10 06 11 07 07 }
        $a116 = { (32 | 12) 10 01 (25 | 05) 07 1A 16 (34 | 14) 11 11 07 10 06 06 }
        $a117 = { (31 | 11) 13 02 (26 | 06) 04 19 15 (37 | 17) 12 12 04 13 05 05 }
        $a118 = { (30 | 10) 12 03 (27 | 07) 05 18 14 (36 | 16) 13 13 05 12 04 04 }
        $a119 = { (3F | 1F) 1D 0C (28 | 08) 0A 17 1B (39 | 19) 1C 1C 0A 1D 0B 0B }
        $a120 = { (3E | 1E) 1C 0D (29 | 09) 0B 16 1A (38 | 18) 1D 1D 0B 1C 0A 0A }
        $a121 = { (3D | 1D) 1F 0E (2A | 0A) 08 15 19 (3B | 1B) 1E 1E 08 1F 09 09 }
        $a122 = { (3C | 1C) 1E 0F (2B | 0B) 09 14 18 (3A | 1A) 1F 1F 09 1E 08 08 }
        $a123 = { (3B | 1B) 19 08 (2C | 0C) 0E 13 1F (3D | 1D) 18 18 0E 19 0F 0F }
        $a124 = { (3A | 1A) 18 09 (2D | 0D) 0F 12 1E (3C | 1C) 19 19 0F 18 0E 0E }
        $a125 = { (39 | 19) 1B 0A (2E | 0E) 0C 11 1D (3F | 1F) 1A 1A 0C 1B 0D 0D }
        $a126 = { (38 | 18) 1A 0B (2F | 0F) 0D 10 1C (3E | 1E) 1B 1B 0D 1A 0C 0C }
        $a127 = { (C7 | E7) E5 F4 (D0 | F0) F2 EF E3 (C1 | E1) E4 E4 F2 E5 F3 F3 }
        $a128 = { (C6 | E6) E4 F5 (D1 | F1) F3 EE E2 (C0 | E0) E5 E5 F3 E4 F2 F2 }
        $a129 = { (C5 | E5) E7 F6 (D2 | F2) F0 ED E1 (C3 | E3) E6 E6 F0 E7 F1 F1 }
        $a130 = { (C4 | E4) E6 F7 (D3 | F3) F1 EC E0 (C2 | E2) E7 E7 F1 E6 F0 F0 }
        $a131 = { (C3 | E3) E1 F0 (D4 | F4) F6 EB E7 (C5 | E5) E0 E0 F6 E1 F7 F7 }
        $a132 = { (C2 | E2) E0 F1 (D5 | F5) F7 EA E6 (C4 | E4) E1 E1 F7 E0 F6 F6 }
        $a133 = { (C1 | E1) E3 F2 (D6 | F6) F4 E9 E5 (C7 | E7) E2 E2 F4 E3 F5 F5 }
        $a134 = { (C0 | E0) E2 F3 (D7 | F7) F5 E8 E4 (C6 | E6) E3 E3 F5 E2 F4 F4 }
        $a135 = { (CF | EF) ED FC (D8 | F8) FA E7 EB (C9 | E9) EC EC FA ED FB FB }
        $a136 = { (CE | EE) EC FD (D9 | F9) FB E6 EA (C8 | E8) ED ED FB EC FA FA }
        $a137 = { (CD | ED) EF FE (DA | FA) F8 E5 E9 (CB | EB) EE EE F8 EF F9 F9 }
        $a138 = { (CC | EC) EE FF (DB | FB) F9 E4 E8 (CA | EA) EF EF F9 EE F8 F8 }
        $a139 = { (CB | EB) E9 F8 (DC | FC) FE E3 EF (CD | ED) E8 E8 FE E9 FF FF }
        $a140 = { (CA | EA) E8 F9 (DD | FD) FF E2 EE (CC | EC) E9 E9 FF E8 FE FE }
        $a141 = { (C9 | E9) EB FA (DE | FE) FC E1 ED (CF | EF) EA EA FC EB FD FD }
        $a142 = { (C8 | E8) EA FB (DF | FF) FD E0 EC (CE | EE) EB EB FD EA FC FC }
        $a143 = { (D7 | F7) F5 E4 (C0 | E0) E2 FF F3 (D1 | F1) F4 F4 E2 F5 E3 E3 }
        $a144 = { (D6 | F6) F4 E5 (C1 | E1) E3 FE F2 (D0 | F0) F5 F5 E3 F4 E2 E2 }
        $a145 = { (D5 | F5) F7 E6 (C2 | E2) E0 FD F1 (D3 | F3) F6 F6 E0 F7 E1 E1 }
        $a146 = { (D4 | F4) F6 E7 (C3 | E3) E1 FC F0 (D2 | F2) F7 F7 E1 F6 E0 E0 }
        $a147 = { (D3 | F3) F1 E0 (C4 | E4) E6 FB F7 (D5 | F5) F0 F0 E6 F1 E7 E7 }
        $a148 = { (D2 | F2) F0 E1 (C5 | E5) E7 FA F6 (D4 | F4) F1 F1 E7 F0 E6 E6 }
        $a149 = { (D1 | F1) F3 E2 (C6 | E6) E4 F9 F5 (D7 | F7) F2 F2 E4 F3 E5 E5 }
        $a150 = { (D0 | F0) F2 E3 (C7 | E7) E5 F8 F4 (D6 | F6) F3 F3 E5 F2 E4 E4 }
        $a151 = { (DF | FF) FD EC (C8 | E8) EA F7 FB (D9 | F9) FC FC EA FD EB EB }
        $a152 = { (DE | FE) FC ED (C9 | E9) EB F6 FA (D8 | F8) FD FD EB FC EA EA }
        $a153 = { (DD | FD) FF EE (CA | EA) E8 F5 F9 (DB | FB) FE FE E8 FF E9 E9 }
        $a154 = { (DC | FC) FE EF (CB | EB) E9 F4 F8 (DA | FA) FF FF E9 FE E8 E8 }
        $a155 = { (DB | FB) F9 E8 (CC | EC) EE F3 FF (DD | FD) F8 F8 EE F9 EF EF }
        $a156 = { (DA | FA) F8 E9 (CD | ED) EF F2 FE (DC | FC) F9 F9 EF F8 EE EE }
        $a157 = { (D9 | F9) FB EA (CE | EE) EC F1 FD (DF | FF) FA FA EC FB ED ED }
        $a158 = { (D8 | F8) FA EB (CF | EF) ED F0 FC (DE | FE) FB FB ED FA EC EC }
        $a159 = { (E7 | C7) C5 D4 (F0 | D0) D2 CF C3 (E1 | C1) C4 C4 D2 C5 D3 D3 }
        $a160 = { (E6 | C6) C4 D5 (F1 | D1) D3 CE C2 (E0 | C0) C5 C5 D3 C4 D2 D2 }
        $a161 = { (E5 | C5) C7 D6 (F2 | D2) D0 CD C1 (E3 | C3) C6 C6 D0 C7 D1 D1 }
        $a162 = { (E4 | C4) C6 D7 (F3 | D3) D1 CC C0 (E2 | C2) C7 C7 D1 C6 D0 D0 }
        $a163 = { (E3 | C3) C1 D0 (F4 | D4) D6 CB C7 (E5 | C5) C0 C0 D6 C1 D7 D7 }
        $a164 = { (E2 | C2) C0 D1 (F5 | D5) D7 CA C6 (E4 | C4) C1 C1 D7 C0 D6 D6 }
        $a165 = { (E1 | C1) C3 D2 (F6 | D6) D4 C9 C5 (E7 | C7) C2 C2 D4 C3 D5 D5 }
        $a166 = { (E0 | C0) C2 D3 (F7 | D7) D5 C8 C4 (E6 | C6) C3 C3 D5 C2 D4 D4 }
        $a167 = { (EF | CF) CD DC (F8 | D8) DA C7 CB (E9 | C9) CC CC DA CD DB DB }
        $a168 = { (EE | CE) CC DD (F9 | D9) DB C6 CA (E8 | C8) CD CD DB CC DA DA }
        $a169 = { (ED | CD) CF DE (FA | DA) D8 C5 C9 (EB | CB) CE CE D8 CF D9 D9 }
        $a170 = { (EC | CC) CE DF (FB | DB) D9 C4 C8 (EA | CA) CF CF D9 CE D8 D8 }
        $a171 = { (EB | CB) C9 D8 (FC | DC) DE C3 CF (ED | CD) C8 C8 DE C9 DF DF }
        $a172 = { (EA | CA) C8 D9 (FD | DD) DF C2 CE (EC | CC) C9 C9 DF C8 DE DE }
        $a173 = { (E9 | C9) CB DA (FE | DE) DC C1 CD (EF | CF) CA CA DC CB DD DD }
        $a174 = { (E8 | C8) CA DB (FF | DF) DD C0 CC (EE | CE) CB CB DD CA DC DC }
        $a175 = { (F7 | D7) D5 C4 (E0 | C0) C2 DF D3 (F1 | D1) D4 D4 C2 D5 C3 C3 }
        $a176 = { (F6 | D6) D4 C5 (E1 | C1) C3 DE D2 (F0 | D0) D5 D5 C3 D4 C2 C2 }
        $a177 = { (F5 | D5) D7 C6 (E2 | C2) C0 DD D1 (F3 | D3) D6 D6 C0 D7 C1 C1 }
        $a178 = { (F4 | D4) D6 C7 (E3 | C3) C1 DC D0 (F2 | D2) D7 D7 C1 D6 C0 C0 }
        $a179 = { (F3 | D3) D1 C0 (E4 | C4) C6 DB D7 (F5 | D5) D0 D0 C6 D1 C7 C7 }
        $a180 = { (F2 | D2) D0 C1 (E5 | C5) C7 DA D6 (F4 | D4) D1 D1 C7 D0 C6 C6 }
        $a181 = { (F1 | D1) D3 C2 (E6 | C6) C4 D9 D5 (F7 | D7) D2 D2 C4 D3 C5 C5 }
        $a182 = { (F0 | D0) D2 C3 (E7 | C7) C5 D8 D4 (F6 | D6) D3 D3 C5 D2 C4 C4 }
        $a183 = { (FF | DF) DD CC (E8 | C8) CA D7 DB (F9 | D9) DC DC CA DD CB CB }
        $a184 = { (FE | DE) DC CD (E9 | C9) CB D6 DA (F8 | D8) DD DD CB DC CA CA }
        $a185 = { (FD | DD) DF CE (EA | CA) C8 D5 D9 (FB | DB) DE DE C8 DF C9 C9 }
        $a186 = { (FC | DC) DE CF (EB | CB) C9 D4 D8 (FA | DA) DF DF C9 DE C8 C8 }
        $a187 = { (FB | DB) D9 C8 (EC | CC) CE D3 DF (FD | DD) D8 D8 CE D9 CF CF }
        $a188 = { (FA | DA) D8 C9 (ED | CD) CF D2 DE (FC | DC) D9 D9 CF D8 CE CE }
        $a189 = { (F9 | D9) DB CA (EE | CE) CC D1 DD (FF | DF) DA DA CC DB CD CD }
        $a190 = { (F8 | D8) DA CB (EF | CF) CD D0 DC (FE | DE) DB DB CD DA CC CC }
        $a191 = { (87 | A7) A5 B4 (90 | B0) B2 AF A3 (81 | A1) A4 A4 B2 A5 B3 B3 }
        $a192 = { (86 | A6) A4 B5 (91 | B1) B3 AE A2 (80 | A0) A5 A5 B3 A4 B2 B2 }
        $a193 = { (85 | A5) A7 B6 (92 | B2) B0 AD A1 (83 | A3) A6 A6 B0 A7 B1 B1 }
        $a194 = { (84 | A4) A6 B7 (93 | B3) B1 AC A0 (82 | A2) A7 A7 B1 A6 B0 B0 }
        $a195 = { (83 | A3) A1 B0 (94 | B4) B6 AB A7 (85 | A5) A0 A0 B6 A1 B7 B7 }
        $a196 = { (82 | A2) A0 B1 (95 | B5) B7 AA A6 (84 | A4) A1 A1 B7 A0 B6 B6 }
        $a197 = { (81 | A1) A3 B2 (96 | B6) B4 A9 A5 (87 | A7) A2 A2 B4 A3 B5 B5 }
        $a198 = { (80 | A0) A2 B3 (97 | B7) B5 A8 A4 (86 | A6) A3 A3 B5 A2 B4 B4 }
        $a199 = { (8F | AF) AD BC (98 | B8) BA A7 AB (89 | A9) AC AC BA AD BB BB }
        $a200 = { (8E | AE) AC BD (99 | B9) BB A6 AA (88 | A8) AD AD BB AC BA BA }
        $a201 = { (8D | AD) AF BE (9A | BA) B8 A5 A9 (8B | AB) AE AE B8 AF B9 B9 }
        $a202 = { (8C | AC) AE BF (9B | BB) B9 A4 A8 (8A | AA) AF AF B9 AE B8 B8 }
        $a203 = { (8B | AB) A9 B8 (9C | BC) BE A3 AF (8D | AD) A8 A8 BE A9 BF BF }
        $a204 = { (8A | AA) A8 B9 (9D | BD) BF A2 AE (8C | AC) A9 A9 BF A8 BE BE }
        $a205 = { (89 | A9) AB BA (9E | BE) BC A1 AD (8F | AF) AA AA BC AB BD BD }
        $a206 = { (88 | A8) AA BB (9F | BF) BD A0 AC (8E | AE) AB AB BD AA BC BC }
        $a207 = { (97 | B7) B5 A4 (80 | A0) A2 BF B3 (91 | B1) B4 B4 A2 B5 A3 A3 }
        $a208 = { (96 | B6) B4 A5 (81 | A1) A3 BE B2 (90 | B0) B5 B5 A3 B4 A2 A2 }
        $a209 = { (95 | B5) B7 A6 (82 | A2) A0 BD B1 (93 | B3) B6 B6 A0 B7 A1 A1 }
        $a210 = { (94 | B4) B6 A7 (83 | A3) A1 BC B0 (92 | B2) B7 B7 A1 B6 A0 A0 }
        $a211 = { (93 | B3) B1 A0 (84 | A4) A6 BB B7 (95 | B5) B0 B0 A6 B1 A7 A7 }
        $a212 = { (92 | B2) B0 A1 (85 | A5) A7 BA B6 (94 | B4) B1 B1 A7 B0 A6 A6 }
        $a213 = { (91 | B1) B3 A2 (86 | A6) A4 B9 B5 (97 | B7) B2 B2 A4 B3 A5 A5 }
        $a214 = { (90 | B0) B2 A3 (87 | A7) A5 B8 B4 (96 | B6) B3 B3 A5 B2 A4 A4 }
        $a215 = { (9F | BF) BD AC (88 | A8) AA B7 BB (99 | B9) BC BC AA BD AB AB }
        $a216 = { (9E | BE) BC AD (89 | A9) AB B6 BA (98 | B8) BD BD AB BC AA AA }
        $a217 = { (9D | BD) BF AE (8A | AA) A8 B5 B9 (9B | BB) BE BE A8 BF A9 A9 }
        $a218 = { (9C | BC) BE AF (8B | AB) A9 B4 B8 (9A | BA) BF BF A9 BE A8 A8 }
        $a219 = { (9B | BB) B9 A8 (8C | AC) AE B3 BF (9D | BD) B8 B8 AE B9 AF AF }
        $a220 = { (9A | BA) B8 A9 (8D | AD) AF B2 BE (9C | BC) B9 B9 AF B8 AE AE }
        $a221 = { (99 | B9) BB AA (8E | AE) AC B1 BD (9F | BF) BA BA AC BB AD AD }
        $a222 = { (98 | B8) BA AB (8F | AF) AD B0 BC (9E | BE) BB BB AD BA AC AC }
        $a223 = { (A7 | 87) 85 94 (B0 | 90) 92 8F 83 (A1 | 81) 84 84 92 85 93 93 }
        $a224 = { (A6 | 86) 84 95 (B1 | 91) 93 8E 82 (A0 | 80) 85 85 93 84 92 92 }
        $a225 = { (A5 | 85) 87 96 (B2 | 92) 90 8D 81 (A3 | 83) 86 86 90 87 91 91 }
        $a226 = { (A4 | 84) 86 97 (B3 | 93) 91 8C 80 (A2 | 82) 87 87 91 86 90 90 }
        $a227 = { (A3 | 83) 81 90 (B4 | 94) 96 8B 87 (A5 | 85) 80 80 96 81 97 97 }
        $a228 = { (A2 | 82) 80 91 (B5 | 95) 97 8A 86 (A4 | 84) 81 81 97 80 96 96 }
        $a229 = { (A1 | 81) 83 92 (B6 | 96) 94 89 85 (A7 | 87) 82 82 94 83 95 95 }
        $a230 = { (A0 | 80) 82 93 (B7 | 97) 95 88 84 (A6 | 86) 83 83 95 82 94 94 }
        $a231 = { (AF | 8F) 8D 9C (B8 | 98) 9A 87 8B (A9 | 89) 8C 8C 9A 8D 9B 9B }
        $a232 = { (AE | 8E) 8C 9D (B9 | 99) 9B 86 8A (A8 | 88) 8D 8D 9B 8C 9A 9A }
        $a233 = { (AD | 8D) 8F 9E (BA | 9A) 98 85 89 (AB | 8B) 8E 8E 98 8F 99 99 }
        $a234 = { (AC | 8C) 8E 9F (BB | 9B) 99 84 88 (AA | 8A) 8F 8F 99 8E 98 98 }
        $a235 = { (AB | 8B) 89 98 (BC | 9C) 9E 83 8F (AD | 8D) 88 88 9E 89 9F 9F }
        $a236 = { (AA | 8A) 88 99 (BD | 9D) 9F 82 8E (AC | 8C) 89 89 9F 88 9E 9E }
        $a237 = { (A9 | 89) 8B 9A (BE | 9E) 9C 81 8D (AF | 8F) 8A 8A 9C 8B 9D 9D }
        $a238 = { (A8 | 88) 8A 9B (BF | 9F) 9D 80 8C (AE | 8E) 8B 8B 9D 8A 9C 9C }
        $a239 = { (B7 | 97) 95 84 (A0 | 80) 82 9F 93 (B1 | 91) 94 94 82 95 83 83 }
        $a240 = { (B6 | 96) 94 85 (A1 | 81) 83 9E 92 (B0 | 90) 95 95 83 94 82 82 }
        $a241 = { (B5 | 95) 97 86 (A2 | 82) 80 9D 91 (B3 | 93) 96 96 80 97 81 81 }
        $a242 = { (B4 | 94) 96 87 (A3 | 83) 81 9C 90 (B2 | 92) 97 97 81 96 80 80 }
        $a243 = { (B3 | 93) 91 80 (A4 | 84) 86 9B 97 (B5 | 95) 90 90 86 91 87 87 }
        $a244 = { (B2 | 92) 90 81 (A5 | 85) 87 9A 96 (B4 | 94) 91 91 87 90 86 86 }
        $a245 = { (B1 | 91) 93 82 (A6 | 86) 84 99 95 (B7 | 97) 92 92 84 93 85 85 }
        $a246 = { (B0 | 90) 92 83 (A7 | 87) 85 98 94 (B6 | 96) 93 93 85 92 84 84 }
        $a247 = { (BF | 9F) 9D 8C (A8 | 88) 8A 97 9B (B9 | 99) 9C 9C 8A 9D 8B 8B }
        $a248 = { (BE | 9E) 9C 8D (A9 | 89) 8B 96 9A (B8 | 98) 9D 9D 8B 9C 8A 8A }
        $a249 = { (BD | 9D) 9F 8E (AA | 8A) 88 95 99 (BB | 9B) 9E 9E 88 9F 89 89 }
        $a250 = { (BC | 9C) 9E 8F (AB | 8B) 89 94 98 (BA | 9A) 9F 9F 89 9E 88 88 }
        $a251 = { (BB | 9B) 99 88 (AC | 8C) 8E 93 9F (BD | 9D) 98 98 8E 99 8F 8F }
        $a252 = { (BA | 9A) 98 89 (AD | 8D) 8F 92 9E (BC | 9C) 99 99 8F 98 8E 8E }
        $a253 = { (B9 | 99) 9B 8A (AE | 8E) 8C 91 9D (BF | 9F) 9A 9A 8C 9B 8D 8D }
        $a254 = { (4D | 6D) 6E 60 65 (4D | 6D) 68 63 73 60 73 78 }  // "LoadLibrary" XOR 0x01
        $a255 = { (4E | 6E) 6D 63 66 (4E | 6E) 6B 60 70 63 70 7B }  // "LoadLibrary" XOR 0x02
        $a256 = { (4F | 6F) 6C 62 67 (4F | 6F) 6A 61 71 62 71 7A }  // etc...
        $a257 = { (48 | 68) 6B 65 60 (48 | 68) 6D 66 76 65 76 7D }
        $a258 = { (49 | 69) 6A 64 61 (49 | 69) 6C 67 77 64 77 7C }
        $a259 = { (4A | 6A) 69 67 62 (4A | 6A) 6F 64 74 67 74 7F }
        $a260 = { (4B | 6B) 68 66 63 (4B | 6B) 6E 65 75 66 75 7E }
        $a261 = { (44 | 64) 67 69 6C (44 | 64) 61 6A 7A 69 7A 71 }
        $a262 = { (45 | 65) 66 68 6D (45 | 65) 60 6B 7B 68 7B 70 }
        $a263 = { (46 | 66) 65 6B 6E (46 | 66) 63 68 78 6B 78 73 }
        $a264 = { (47 | 67) 64 6A 6F (47 | 67) 62 69 79 6A 79 72 }
        $a265 = { (40 | 60) 63 6D 68 (40 | 60) 65 6E 7E 6D 7E 75 }
        $a266 = { (41 | 61) 62 6C 69 (41 | 61) 64 6F 7F 6C 7F 74 }
        $a267 = { (42 | 62) 61 6F 6A (42 | 62) 67 6C 7C 6F 7C 77 }
        $a268 = { (43 | 63) 60 6E 6B (43 | 63) 66 6D 7D 6E 7D 76 }
        $a269 = { (5C | 7C) 7F 71 74 (5C | 7C) 79 72 62 71 62 69 }
        $a270 = { (5D | 7D) 7E 70 75 (5D | 7D) 78 73 63 70 63 68 }
        $a271 = { (5E | 7E) 7D 73 76 (5E | 7E) 7B 70 60 73 60 6B }
        $a272 = { (5F | 7F) 7C 72 77 (5F | 7F) 7A 71 61 72 61 6A }
        $a273 = { (58 | 78) 7B 75 70 (58 | 78) 7D 76 66 75 66 6D }
        $a274 = { (59 | 79) 7A 74 71 (59 | 79) 7C 77 67 74 67 6C }
        $a275 = { (5A | 7A) 79 77 72 (5A | 7A) 7F 74 64 77 64 6F }
        $a276 = { (5B | 7B) 78 76 73 (5B | 7B) 7E 75 65 76 65 6E }
        $a277 = { (54 | 74) 77 79 7C (54 | 74) 71 7A 6A 79 6A 61 }
        $a278 = { (55 | 75) 76 78 7D (55 | 75) 70 7B 6B 78 6B 60 }
        $a279 = { (56 | 76) 75 7B 7E (56 | 76) 73 78 68 7B 68 63 }
        $a280 = { (57 | 77) 74 7A 7F (57 | 77) 72 79 69 7A 69 62 }
        $a281 = { (50 | 70) 73 7D 78 (50 | 70) 75 7E 6E 7D 6E 65 }
        $a282 = { (51 | 71) 72 7C 79 (51 | 71) 74 7F 6F 7C 6F 64 }
        $a283 = { (52 | 72) 71 7F 7A (52 | 72) 77 7C 6C 7F 6C 67 }
        $a284 = { (53 | 73) 70 7E 7B (53 | 73) 76 7D 6D 7E 6D 66 }
        // XOR 0x20 removed because it toggles capitalization and causes [lL]OAD[Ll]IBRARY to match.
        $a286 = { (6D | 4D) 4E 40 45 (6D | 4D) 48 43 53 40 53 58 }
        $a287 = { (6E | 4E) 4D 43 46 (6E | 4E) 4B 40 50 43 50 5B }
        $a288 = { (6F | 4F) 4C 42 47 (6F | 4F) 4A 41 51 42 51 5A }
        $a289 = { (68 | 48) 4B 45 40 (68 | 48) 4D 46 56 45 56 5D }
        $a290 = { (69 | 49) 4A 44 41 (69 | 49) 4C 47 57 44 57 5C }
        $a291 = { (6A | 4A) 49 47 42 (6A | 4A) 4F 44 54 47 54 5F }
        $a292 = { (6B | 4B) 48 46 43 (6B | 4B) 4E 45 55 46 55 5E }
        $a293 = { (64 | 44) 47 49 4C (64 | 44) 41 4A 5A 49 5A 51 }
        $a294 = { (65 | 45) 46 48 4D (65 | 45) 40 4B 5B 48 5B 50 }
        $a295 = { (66 | 46) 45 4B 4E (66 | 46) 43 48 58 4B 58 53 }
        $a296 = { (67 | 47) 44 4A 4F (67 | 47) 42 49 59 4A 59 52 }
        $a297 = { (60 | 40) 43 4D 48 (60 | 40) 45 4E 5E 4D 5E 55 }
        $a298 = { (61 | 41) 42 4C 49 (61 | 41) 44 4F 5F 4C 5F 54 }
        $a299 = { (62 | 42) 41 4F 4A (62 | 42) 47 4C 5C 4F 5C 57 }
        $a300 = { (63 | 43) 40 4E 4B (63 | 43) 46 4D 5D 4E 5D 56 }
        $a301 = { (7C | 5C) 5F 51 54 (7C | 5C) 59 52 42 51 42 49 }
        $a302 = { (7D | 5D) 5E 50 55 (7D | 5D) 58 53 43 50 43 48 }
        $a303 = { (7E | 5E) 5D 53 56 (7E | 5E) 5B 50 40 53 40 4B }
        $a304 = { (7F | 5F) 5C 52 57 (7F | 5F) 5A 51 41 52 41 4A }
        $a305 = { (78 | 58) 5B 55 50 (78 | 58) 5D 56 46 55 46 4D }
        $a306 = { (79 | 59) 5A 54 51 (79 | 59) 5C 57 47 54 47 4C }
        $a307 = { (7A | 5A) 59 57 52 (7A | 5A) 5F 54 44 57 44 4F }
        $a308 = { (7B | 5B) 58 56 53 (7B | 5B) 5E 55 45 56 45 4E }
        $a309 = { (74 | 54) 57 59 5C (74 | 54) 51 5A 4A 59 4A 41 }
        $a310 = { (75 | 55) 56 58 5D (75 | 55) 50 5B 4B 58 4B 40 }
        $a311 = { (76 | 56) 55 5B 5E (76 | 56) 53 58 48 5B 48 43 }
        $a312 = { (77 | 57) 54 5A 5F (77 | 57) 52 59 49 5A 49 42 }
        $a313 = { (70 | 50) 53 5D 58 (70 | 50) 55 5E 4E 5D 4E 45 }
        $a314 = { (71 | 51) 52 5C 59 (71 | 51) 54 5F 4F 5C 4F 44 }
        $a315 = { (72 | 52) 51 5F 5A (72 | 52) 57 5C 4C 5F 4C 47 }
        $a316 = { (73 | 53) 50 5E 5B (73 | 53) 56 5D 4D 5E 4D 46 }
        $a317 = { (0C | 2C) 2F 21 24 (0C | 2C) 29 22 32 21 32 39 }
        $a318 = { (0D | 2D) 2E 20 25 (0D | 2D) 28 23 33 20 33 38 }
        $a319 = { (0E | 2E) 2D 23 26 (0E | 2E) 2B 20 30 23 30 3B }
        $a320 = { (0F | 2F) 2C 22 27 (0F | 2F) 2A 21 31 22 31 3A }
        $a321 = { (08 | 28) 2B 25 20 (08 | 28) 2D 26 36 25 36 3D }
        $a322 = { (09 | 29) 2A 24 21 (09 | 29) 2C 27 37 24 37 3C }
        $a323 = { (0A | 2A) 29 27 22 (0A | 2A) 2F 24 34 27 34 3F }
        $a324 = { (0B | 2B) 28 26 23 (0B | 2B) 2E 25 35 26 35 3E }
        $a325 = { (04 | 24) 27 29 2C (04 | 24) 21 2A 3A 29 3A 31 }
        $a326 = { (05 | 25) 26 28 2D (05 | 25) 20 2B 3B 28 3B 30 }
        $a327 = { (06 | 26) 25 2B 2E (06 | 26) 23 28 38 2B 38 33 }
        $a328 = { (07 | 27) 24 2A 2F (07 | 27) 22 29 39 2A 39 32 }
        $a329 = { (00 | 20) 23 2D 28 (00 | 20) 25 2E 3E 2D 3E 35 }
        $a330 = { (01 | 21) 22 2C 29 (01 | 21) 24 2F 3F 2C 3F 34 }
        $a331 = { (02 | 22) 21 2F 2A (02 | 22) 27 2C 3C 2F 3C 37 }
        $a332 = { (03 | 23) 20 2E 2B (03 | 23) 26 2D 3D 2E 3D 36 }
        $a333 = { (1C | 3C) 3F 31 34 (1C | 3C) 39 32 22 31 22 29 }
        $a334 = { (1D | 3D) 3E 30 35 (1D | 3D) 38 33 23 30 23 28 }
        $a335 = { (1E | 3E) 3D 33 36 (1E | 3E) 3B 30 20 33 20 2B }
        $a336 = { (1F | 3F) 3C 32 37 (1F | 3F) 3A 31 21 32 21 2A }
        $a337 = { (18 | 38) 3B 35 30 (18 | 38) 3D 36 26 35 26 2D }
        $a338 = { (19 | 39) 3A 34 31 (19 | 39) 3C 37 27 34 27 2C }
        $a339 = { (1A | 3A) 39 37 32 (1A | 3A) 3F 34 24 37 24 2F }
        $a340 = { (1B | 3B) 38 36 33 (1B | 3B) 3E 35 25 36 25 2E }
        $a341 = { (14 | 34) 37 39 3C (14 | 34) 31 3A 2A 39 2A 21 }
        $a342 = { (15 | 35) 36 38 3D (15 | 35) 30 3B 2B 38 2B 20 }
        $a343 = { (16 | 36) 35 3B 3E (16 | 36) 33 38 28 3B 28 23 }
        $a344 = { (17 | 37) 34 3A 3F (17 | 37) 32 39 29 3A 29 22 }
        $a345 = { (10 | 30) 33 3D 38 (10 | 30) 35 3E 2E 3D 2E 25 }
        $a346 = { (11 | 31) 32 3C 39 (11 | 31) 34 3F 2F 3C 2F 24 }
        $a347 = { (12 | 32) 31 3F 3A (12 | 32) 37 3C 2C 3F 2C 27 }
        $a348 = { (13 | 33) 30 3E 3B (13 | 33) 36 3D 2D 3E 2D 26 }
        $a349 = { (2C | 0C) 0F 01 04 (2C | 0C) 09 02 12 01 12 19 }
        $a350 = { (2D | 0D) 0E 00 05 (2D | 0D) 08 03 13 00 13 18 }
        $a351 = { (2E | 0E) 0D 03 06 (2E | 0E) 0B 00 10 03 10 1B }
        $a352 = { (2F | 0F) 0C 02 07 (2F | 0F) 0A 01 11 02 11 1A }
        $a353 = { (28 | 08) 0B 05 00 (28 | 08) 0D 06 16 05 16 1D }
        $a354 = { (29 | 09) 0A 04 01 (29 | 09) 0C 07 17 04 17 1C }
        $a355 = { (2A | 0A) 09 07 02 (2A | 0A) 0F 04 14 07 14 1F }
        $a356 = { (2B | 0B) 08 06 03 (2B | 0B) 0E 05 15 06 15 1E }
        $a357 = { (24 | 04) 07 09 0C (24 | 04) 01 0A 1A 09 1A 11 }
        $a358 = { (25 | 05) 06 08 0D (25 | 05) 00 0B 1B 08 1B 10 }
        $a359 = { (26 | 06) 05 0B 0E (26 | 06) 03 08 18 0B 18 13 }
        $a360 = { (27 | 07) 04 0A 0F (27 | 07) 02 09 19 0A 19 12 }
        $a361 = { (20 | 00) 03 0D 08 (20 | 00) 05 0E 1E 0D 1E 15 }
        $a362 = { (21 | 01) 02 0C 09 (21 | 01) 04 0F 1F 0C 1F 14 }
        $a363 = { (22 | 02) 01 0F 0A (22 | 02) 07 0C 1C 0F 1C 17 }
        $a364 = { (23 | 03) 00 0E 0B (23 | 03) 06 0D 1D 0E 1D 16 }
        $a365 = { (3C | 1C) 1F 11 14 (3C | 1C) 19 12 02 11 02 09 }
        $a366 = { (3D | 1D) 1E 10 15 (3D | 1D) 18 13 03 10 03 08 }
        $a367 = { (3E | 1E) 1D 13 16 (3E | 1E) 1B 10 00 13 00 0B }
        $a368 = { (3F | 1F) 1C 12 17 (3F | 1F) 1A 11 01 12 01 0A }
        $a369 = { (38 | 18) 1B 15 10 (38 | 18) 1D 16 06 15 06 0D }
        $a370 = { (39 | 19) 1A 14 11 (39 | 19) 1C 17 07 14 07 0C }
        $a371 = { (3A | 1A) 19 17 12 (3A | 1A) 1F 14 04 17 04 0F }
        $a372 = { (3B | 1B) 18 16 13 (3B | 1B) 1E 15 05 16 05 0E }
        $a373 = { (34 | 14) 17 19 1C (34 | 14) 11 1A 0A 19 0A 01 }
        $a374 = { (35 | 15) 16 18 1D (35 | 15) 10 1B 0B 18 0B 00 }
        $a375 = { (36 | 16) 15 1B 1E (36 | 16) 13 18 08 1B 08 03 }
        $a376 = { (37 | 17) 14 1A 1F (37 | 17) 12 19 09 1A 09 02 }
        $a377 = { (30 | 10) 13 1D 18 (30 | 10) 15 1E 0E 1D 0E 05 }
        $a378 = { (31 | 11) 12 1C 19 (31 | 11) 14 1F 0F 1C 0F 04 }
        $a379 = { (32 | 12) 11 1F 1A (32 | 12) 17 1C 0C 1F 0C 07 }
        $a380 = { (33 | 13) 10 1E 1B (33 | 13) 16 1D 0D 1E 0D 06 }
        $a381 = { (CC | EC) EF E1 E4 (CC | EC) E9 E2 F2 E1 F2 F9 }
        $a382 = { (CD | ED) EE E0 E5 (CD | ED) E8 E3 F3 E0 F3 F8 }
        $a383 = { (CE | EE) ED E3 E6 (CE | EE) EB E0 F0 E3 F0 FB }
        $a384 = { (CF | EF) EC E2 E7 (CF | EF) EA E1 F1 E2 F1 FA }
        $a385 = { (C8 | E8) EB E5 E0 (C8 | E8) ED E6 F6 E5 F6 FD }
        $a386 = { (C9 | E9) EA E4 E1 (C9 | E9) EC E7 F7 E4 F7 FC }
        $a387 = { (CA | EA) E9 E7 E2 (CA | EA) EF E4 F4 E7 F4 FF }
        $a388 = { (CB | EB) E8 E6 E3 (CB | EB) EE E5 F5 E6 F5 FE }
        $a389 = { (C4 | E4) E7 E9 EC (C4 | E4) E1 EA FA E9 FA F1 }
        $a390 = { (C5 | E5) E6 E8 ED (C5 | E5) E0 EB FB E8 FB F0 }
        $a391 = { (C6 | E6) E5 EB EE (C6 | E6) E3 E8 F8 EB F8 F3 }
        $a392 = { (C7 | E7) E4 EA EF (C7 | E7) E2 E9 F9 EA F9 F2 }
        $a393 = { (C0 | E0) E3 ED E8 (C0 | E0) E5 EE FE ED FE F5 }
        $a394 = { (C1 | E1) E2 EC E9 (C1 | E1) E4 EF FF EC FF F4 }
        $a395 = { (C2 | E2) E1 EF EA (C2 | E2) E7 EC FC EF FC F7 }
        $a396 = { (C3 | E3) E0 EE EB (C3 | E3) E6 ED FD EE FD F6 }
        $a397 = { (DC | FC) FF F1 F4 (DC | FC) F9 F2 E2 F1 E2 E9 }
        $a398 = { (DD | FD) FE F0 F5 (DD | FD) F8 F3 E3 F0 E3 E8 }
        $a399 = { (DE | FE) FD F3 F6 (DE | FE) FB F0 E0 F3 E0 EB }
        $a400 = { (DF | FF) FC F2 F7 (DF | FF) FA F1 E1 F2 E1 EA }
        $a401 = { (D8 | F8) FB F5 F0 (D8 | F8) FD F6 E6 F5 E6 ED }
        $a402 = { (D9 | F9) FA F4 F1 (D9 | F9) FC F7 E7 F4 E7 EC }
        $a403 = { (DA | FA) F9 F7 F2 (DA | FA) FF F4 E4 F7 E4 EF }
        $a404 = { (DB | FB) F8 F6 F3 (DB | FB) FE F5 E5 F6 E5 EE }
        $a405 = { (D4 | F4) F7 F9 FC (D4 | F4) F1 FA EA F9 EA E1 }
        $a406 = { (D5 | F5) F6 F8 FD (D5 | F5) F0 FB EB F8 EB E0 }
        $a407 = { (D6 | F6) F5 FB FE (D6 | F6) F3 F8 E8 FB E8 E3 }
        $a408 = { (D7 | F7) F4 FA FF (D7 | F7) F2 F9 E9 FA E9 E2 }
        $a409 = { (D0 | F0) F3 FD F8 (D0 | F0) F5 FE EE FD EE E5 }
        $a410 = { (D1 | F1) F2 FC F9 (D1 | F1) F4 FF EF FC EF E4 }
        $a411 = { (D2 | F2) F1 FF FA (D2 | F2) F7 FC EC FF EC E7 }
        $a412 = { (D3 | F3) F0 FE FB (D3 | F3) F6 FD ED FE ED E6 }
        $a413 = { (EC | CC) CF C1 C4 (EC | CC) C9 C2 D2 C1 D2 D9 }
        $a414 = { (ED | CD) CE C0 C5 (ED | CD) C8 C3 D3 C0 D3 D8 }
        $a415 = { (EE | CE) CD C3 C6 (EE | CE) CB C0 D0 C3 D0 DB }
        $a416 = { (EF | CF) CC C2 C7 (EF | CF) CA C1 D1 C2 D1 DA }
        $a417 = { (E8 | C8) CB C5 C0 (E8 | C8) CD C6 D6 C5 D6 DD }
        $a418 = { (E9 | C9) CA C4 C1 (E9 | C9) CC C7 D7 C4 D7 DC }
        $a419 = { (EA | CA) C9 C7 C2 (EA | CA) CF C4 D4 C7 D4 DF }
        $a420 = { (EB | CB) C8 C6 C3 (EB | CB) CE C5 D5 C6 D5 DE }
        $a421 = { (E4 | C4) C7 C9 CC (E4 | C4) C1 CA DA C9 DA D1 }
        $a422 = { (E5 | C5) C6 C8 CD (E5 | C5) C0 CB DB C8 DB D0 }
        $a423 = { (E6 | C6) C5 CB CE (E6 | C6) C3 C8 D8 CB D8 D3 }
        $a424 = { (E7 | C7) C4 CA CF (E7 | C7) C2 C9 D9 CA D9 D2 }
        $a425 = { (E0 | C0) C3 CD C8 (E0 | C0) C5 CE DE CD DE D5 }
        $a426 = { (E1 | C1) C2 CC C9 (E1 | C1) C4 CF DF CC DF D4 }
        $a427 = { (E2 | C2) C1 CF CA (E2 | C2) C7 CC DC CF DC D7 }
        $a428 = { (E3 | C3) C0 CE CB (E3 | C3) C6 CD DD CE DD D6 }
        $a429 = { (FC | DC) DF D1 D4 (FC | DC) D9 D2 C2 D1 C2 C9 }
        $a430 = { (FD | DD) DE D0 D5 (FD | DD) D8 D3 C3 D0 C3 C8 }
        $a431 = { (FE | DE) DD D3 D6 (FE | DE) DB D0 C0 D3 C0 CB }
        $a432 = { (FF | DF) DC D2 D7 (FF | DF) DA D1 C1 D2 C1 CA }
        $a433 = { (F8 | D8) DB D5 D0 (F8 | D8) DD D6 C6 D5 C6 CD }
        $a434 = { (F9 | D9) DA D4 D1 (F9 | D9) DC D7 C7 D4 C7 CC }
        $a435 = { (FA | DA) D9 D7 D2 (FA | DA) DF D4 C4 D7 C4 CF }
        $a436 = { (FB | DB) D8 D6 D3 (FB | DB) DE D5 C5 D6 C5 CE }
        $a437 = { (F4 | D4) D7 D9 DC (F4 | D4) D1 DA CA D9 CA C1 }
        $a438 = { (F5 | D5) D6 D8 DD (F5 | D5) D0 DB CB D8 CB C0 }
        $a439 = { (F6 | D6) D5 DB DE (F6 | D6) D3 D8 C8 DB C8 C3 }
        $a440 = { (F7 | D7) D4 DA DF (F7 | D7) D2 D9 C9 DA C9 C2 }
        $a441 = { (F0 | D0) D3 DD D8 (F0 | D0) D5 DE CE DD CE C5 }
        $a442 = { (F1 | D1) D2 DC D9 (F1 | D1) D4 DF CF DC CF C4 }
        $a443 = { (F2 | D2) D1 DF DA (F2 | D2) D7 DC CC DF CC C7 }
        $a444 = { (F3 | D3) D0 DE DB (F3 | D3) D6 DD CD DE CD C6 }
        $a445 = { (8C | AC) AF A1 A4 (8C | AC) A9 A2 B2 A1 B2 B9 }
        $a446 = { (8D | AD) AE A0 A5 (8D | AD) A8 A3 B3 A0 B3 B8 }
        $a447 = { (8E | AE) AD A3 A6 (8E | AE) AB A0 B0 A3 B0 BB }
        $a448 = { (8F | AF) AC A2 A7 (8F | AF) AA A1 B1 A2 B1 BA }
        $a449 = { (88 | A8) AB A5 A0 (88 | A8) AD A6 B6 A5 B6 BD }
        $a450 = { (89 | A9) AA A4 A1 (89 | A9) AC A7 B7 A4 B7 BC }
        $a451 = { (8A | AA) A9 A7 A2 (8A | AA) AF A4 B4 A7 B4 BF }
        $a452 = { (8B | AB) A8 A6 A3 (8B | AB) AE A5 B5 A6 B5 BE }
        $a453 = { (84 | A4) A7 A9 AC (84 | A4) A1 AA BA A9 BA B1 }
        $a454 = { (85 | A5) A6 A8 AD (85 | A5) A0 AB BB A8 BB B0 }
        $a455 = { (86 | A6) A5 AB AE (86 | A6) A3 A8 B8 AB B8 B3 }
        $a456 = { (87 | A7) A4 AA AF (87 | A7) A2 A9 B9 AA B9 B2 }
        $a457 = { (80 | A0) A3 AD A8 (80 | A0) A5 AE BE AD BE B5 }
        $a458 = { (81 | A1) A2 AC A9 (81 | A1) A4 AF BF AC BF B4 }
        $a459 = { (82 | A2) A1 AF AA (82 | A2) A7 AC BC AF BC B7 }
        $a460 = { (83 | A3) A0 AE AB (83 | A3) A6 AD BD AE BD B6 }
        $a461 = { (9C | BC) BF B1 B4 (9C | BC) B9 B2 A2 B1 A2 A9 }
        $a462 = { (9D | BD) BE B0 B5 (9D | BD) B8 B3 A3 B0 A3 A8 }
        $a463 = { (9E | BE) BD B3 B6 (9E | BE) BB B0 A0 B3 A0 AB }
        $a464 = { (9F | BF) BC B2 B7 (9F | BF) BA B1 A1 B2 A1 AA }
        $a465 = { (98 | B8) BB B5 B0 (98 | B8) BD B6 A6 B5 A6 AD }
        $a466 = { (99 | B9) BA B4 B1 (99 | B9) BC B7 A7 B4 A7 AC }
        $a467 = { (9A | BA) B9 B7 B2 (9A | BA) BF B4 A4 B7 A4 AF }
        $a468 = { (9B | BB) B8 B6 B3 (9B | BB) BE B5 A5 B6 A5 AE }
        $a469 = { (94 | B4) B7 B9 BC (94 | B4) B1 BA AA B9 AA A1 }
        $a470 = { (95 | B5) B6 B8 BD (95 | B5) B0 BB AB B8 AB A0 }
        $a471 = { (96 | B6) B5 BB BE (96 | B6) B3 B8 A8 BB A8 A3 }
        $a472 = { (97 | B7) B4 BA BF (97 | B7) B2 B9 A9 BA A9 A2 }
        $a473 = { (90 | B0) B3 BD B8 (90 | B0) B5 BE AE BD AE A5 }
        $a474 = { (91 | B1) B2 BC B9 (91 | B1) B4 BF AF BC AF A4 }
        $a475 = { (92 | B2) B1 BF BA (92 | B2) B7 BC AC BF AC A7 }
        $a476 = { (93 | B3) B0 BE BB (93 | B3) B6 BD AD BE AD A6 }
        $a477 = { (AC | 8C) 8F 81 84 (AC | 8C) 89 82 92 81 92 99 }
        $a478 = { (AD | 8D) 8E 80 85 (AD | 8D) 88 83 93 80 93 98 }
        $a479 = { (AE | 8E) 8D 83 86 (AE | 8E) 8B 80 90 83 90 9B }
        $a480 = { (AF | 8F) 8C 82 87 (AF | 8F) 8A 81 91 82 91 9A }
        $a481 = { (A8 | 88) 8B 85 80 (A8 | 88) 8D 86 96 85 96 9D }
        $a482 = { (A9 | 89) 8A 84 81 (A9 | 89) 8C 87 97 84 97 9C }
        $a483 = { (AA | 8A) 89 87 82 (AA | 8A) 8F 84 94 87 94 9F }
        $a484 = { (AB | 8B) 88 86 83 (AB | 8B) 8E 85 95 86 95 9E }
        $a485 = { (A4 | 84) 87 89 8C (A4 | 84) 81 8A 9A 89 9A 91 }
        $a486 = { (A5 | 85) 86 88 8D (A5 | 85) 80 8B 9B 88 9B 90 }
        $a487 = { (A6 | 86) 85 8B 8E (A6 | 86) 83 88 98 8B 98 93 }
        $a488 = { (A7 | 87) 84 8A 8F (A7 | 87) 82 89 99 8A 99 92 }
        $a489 = { (A0 | 80) 83 8D 88 (A0 | 80) 85 8E 9E 8D 9E 95 }
        $a490 = { (A1 | 81) 82 8C 89 (A1 | 81) 84 8F 9F 8C 9F 94 }
        $a491 = { (A2 | 82) 81 8F 8A (A2 | 82) 87 8C 9C 8F 9C 97 }
        $a492 = { (A3 | 83) 80 8E 8B (A3 | 83) 86 8D 9D 8E 9D 96 }
        $a493 = { (BC | 9C) 9F 91 94 (BC | 9C) 99 92 82 91 82 89 }
        $a494 = { (BD | 9D) 9E 90 95 (BD | 9D) 98 93 83 90 83 88 }
        $a495 = { (BE | 9E) 9D 93 96 (BE | 9E) 9B 90 80 93 80 8B }
        $a496 = { (BF | 9F) 9C 92 97 (BF | 9F) 9A 91 81 92 81 8A }
        $a497 = { (B8 | 98) 9B 95 90 (B8 | 98) 9D 96 86 95 86 8D }
        $a498 = { (B9 | 99) 9A 94 91 (B9 | 99) 9C 97 87 94 87 8C }
        $a499 = { (BA | 9A) 99 97 92 (BA | 9A) 9F 94 84 97 84 8F }
        $a500 = { (BB | 9B) 98 96 93 (BB | 9B) 9E 95 85 96 85 8E }
        $a501 = { (B4 | 94) 97 99 9C (B4 | 94) 91 9A 8A 99 8A 81 }
        $a502 = { (B5 | 95) 96 98 9D (B5 | 95) 90 9B 8B 98 8B 80 }
        $a503 = { (B6 | 96) 95 9B 9E (B6 | 96) 93 98 88 9B 88 83 }
        $a504 = { (B7 | 97) 94 9A 9F (B7 | 97) 92 99 89 9A 89 82 }
        $a505 = { (B0 | 90) 93 9D 98 (B0 | 90) 95 9E 8E 9D 8E 85 }
        $a506 = { (B1 | 91) 92 9C 99 (B1 | 91) 94 9F 8F 9C 8F 84 }
        $a507 = { (B2 | 92) 91 9F 9A (B2 | 92) 97 9C 8C 9F 8C 87 }
    condition:
        any of them
}

rule Xored_PE
{
    meta:
        description = "Contains a XORed PE executable"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a0 = { 55 69 68 72 21 71 73 6E 66 73 60 6C 21 62 60 6F 6F 6E 75 21 63 64 21 73 74 6F 21 68 6F 21 45 4E 52 21 6C 6E 65 64 2F }
        $a1 = { 56 6A 6B 71 22 72 70 6D 65 70 63 6F 22 61 63 6C 6C 6D 76 22 60 67 22 70 77 6C 22 6B 6C 22 46 4D 51 22 6F 6D 66 67 2C }
        $a2 = { 57 6B 6A 70 23 73 71 6C 64 71 62 6E 23 60 62 6D 6D 6C 77 23 61 66 23 71 76 6D 23 6A 6D 23 47 4C 50 23 6E 6C 67 66 2D }
        $a3 = { 50 6C 6D 77 24 74 76 6B 63 76 65 69 24 67 65 6A 6A 6B 70 24 66 61 24 76 71 6A 24 6D 6A 24 40 4B 57 24 69 6B 60 61 2A }
        $a4 = { 51 6D 6C 76 25 75 77 6A 62 77 64 68 25 66 64 6B 6B 6A 71 25 67 60 25 77 70 6B 25 6C 6B 25 41 4A 56 25 68 6A 61 60 2B }
        $a5 = { 52 6E 6F 75 26 76 74 69 61 74 67 6B 26 65 67 68 68 69 72 26 64 63 26 74 73 68 26 6F 68 26 42 49 55 26 6B 69 62 63 28 }
        $a6 = { 53 6F 6E 74 27 77 75 68 60 75 66 6A 27 64 66 69 69 68 73 27 65 62 27 75 72 69 27 6E 69 27 43 48 54 27 6A 68 63 62 29 }
        $a7 = { 5C 60 61 7B 28 78 7A 67 6F 7A 69 65 28 6B 69 66 66 67 7C 28 6A 6D 28 7A 7D 66 28 61 66 28 4C 47 5B 28 65 67 6C 6D 26 }
        $a8 = { 5D 61 60 7A 29 79 7B 66 6E 7B 68 64 29 6A 68 67 67 66 7D 29 6B 6C 29 7B 7C 67 29 60 67 29 4D 46 5A 29 64 66 6D 6C 27 }
        $a9 = { 5E 62 63 79 2A 7A 78 65 6D 78 6B 67 2A 69 6B 64 64 65 7E 2A 68 6F 2A 78 7F 64 2A 63 64 2A 4E 45 59 2A 67 65 6E 6F 24 }
        $a10 = { 5F 63 62 78 2B 7B 79 64 6C 79 6A 66 2B 68 6A 65 65 64 7F 2B 69 6E 2B 79 7E 65 2B 62 65 2B 4F 44 58 2B 66 64 6F 6E 25 }
        $a11 = { 58 64 65 7F 2C 7C 7E 63 6B 7E 6D 61 2C 6F 6D 62 62 63 78 2C 6E 69 2C 7E 79 62 2C 65 62 2C 48 43 5F 2C 61 63 68 69 22 }
        $a12 = { 59 65 64 7E 2D 7D 7F 62 6A 7F 6C 60 2D 6E 6C 63 63 62 79 2D 6F 68 2D 7F 78 63 2D 64 63 2D 49 42 5E 2D 60 62 69 68 23 }
        $a13 = { 5A 66 67 7D 2E 7E 7C 61 69 7C 6F 63 2E 6D 6F 60 60 61 7A 2E 6C 6B 2E 7C 7B 60 2E 67 60 2E 4A 41 5D 2E 63 61 6A 6B 20 }
        $a14 = { 5B 67 66 7C 2F 7F 7D 60 68 7D 6E 62 2F 6C 6E 61 61 60 7B 2F 6D 6A 2F 7D 7A 61 2F 66 61 2F 4B 40 5C 2F 62 60 6B 6A 21 }
        $a15 = { 44 78 79 63 30 60 62 7F 77 62 71 7D 30 73 71 7E 7E 7F 64 30 72 75 30 62 65 7E 30 79 7E 30 54 5F 43 30 7D 7F 74 75 3E }
        $a16 = { 45 79 78 62 31 61 63 7E 76 63 70 7C 31 72 70 7F 7F 7E 65 31 73 74 31 63 64 7F 31 78 7F 31 55 5E 42 31 7C 7E 75 74 3F }
        $a17 = { 46 7A 7B 61 32 62 60 7D 75 60 73 7F 32 71 73 7C 7C 7D 66 32 70 77 32 60 67 7C 32 7B 7C 32 56 5D 41 32 7F 7D 76 77 3C }
        $a18 = { 47 7B 7A 60 33 63 61 7C 74 61 72 7E 33 70 72 7D 7D 7C 67 33 71 76 33 61 66 7D 33 7A 7D 33 57 5C 40 33 7E 7C 77 76 3D }
        $a19 = { 40 7C 7D 67 34 64 66 7B 73 66 75 79 34 77 75 7A 7A 7B 60 34 76 71 34 66 61 7A 34 7D 7A 34 50 5B 47 34 79 7B 70 71 3A }
        $a20 = { 41 7D 7C 66 35 65 67 7A 72 67 74 78 35 76 74 7B 7B 7A 61 35 77 70 35 67 60 7B 35 7C 7B 35 51 5A 46 35 78 7A 71 70 3B }
        $a21 = { 42 7E 7F 65 36 66 64 79 71 64 77 7B 36 75 77 78 78 79 62 36 74 73 36 64 63 78 36 7F 78 36 52 59 45 36 7B 79 72 73 38 }
        $a22 = { 43 7F 7E 64 37 67 65 78 70 65 76 7A 37 74 76 79 79 78 63 37 75 72 37 65 62 79 37 7E 79 37 53 58 44 37 7A 78 73 72 39 }
        $a23 = { 4C 70 71 6B 38 68 6A 77 7F 6A 79 75 38 7B 79 76 76 77 6C 38 7A 7D 38 6A 6D 76 38 71 76 38 5C 57 4B 38 75 77 7C 7D 36 }
        $a24 = { 4D 71 70 6A 39 69 6B 76 7E 6B 78 74 39 7A 78 77 77 76 6D 39 7B 7C 39 6B 6C 77 39 70 77 39 5D 56 4A 39 74 76 7D 7C 37 }
        $a25 = { 4E 72 73 69 3A 6A 68 75 7D 68 7B 77 3A 79 7B 74 74 75 6E 3A 78 7F 3A 68 6F 74 3A 73 74 3A 5E 55 49 3A 77 75 7E 7F 34 }
        $a26 = { 4F 73 72 68 3B 6B 69 74 7C 69 7A 76 3B 78 7A 75 75 74 6F 3B 79 7E 3B 69 6E 75 3B 72 75 3B 5F 54 48 3B 76 74 7F 7E 35 }
        $a27 = { 48 74 75 6F 3C 6C 6E 73 7B 6E 7D 71 3C 7F 7D 72 72 73 68 3C 7E 79 3C 6E 69 72 3C 75 72 3C 58 53 4F 3C 71 73 78 79 32 }
        $a28 = { 49 75 74 6E 3D 6D 6F 72 7A 6F 7C 70 3D 7E 7C 73 73 72 69 3D 7F 78 3D 6F 68 73 3D 74 73 3D 59 52 4E 3D 70 72 79 78 33 }
        $a29 = { 4A 76 77 6D 3E 6E 6C 71 79 6C 7F 73 3E 7D 7F 70 70 71 6A 3E 7C 7B 3E 6C 6B 70 3E 77 70 3E 5A 51 4D 3E 73 71 7A 7B 30 }
        $a30 = { 4B 77 76 6C 3F 6F 6D 70 78 6D 7E 72 3F 7C 7E 71 71 70 6B 3F 7D 7A 3F 6D 6A 71 3F 76 71 3F 5B 50 4C 3F 72 70 7B 7A 31 }
        $a32 = { 75 49 48 52 01 51 53 4E 46 53 40 4C 01 42 40 4F 4F 4E 55 01 43 44 01 53 54 4F 01 48 4F 01 65 6E 72 01 4C 4E 45 44 0F }
        $a33 = { 76 4A 4B 51 02 52 50 4D 45 50 43 4F 02 41 43 4C 4C 4D 56 02 40 47 02 50 57 4C 02 4B 4C 02 66 6D 71 02 4F 4D 46 47 0C }
        $a34 = { 77 4B 4A 50 03 53 51 4C 44 51 42 4E 03 40 42 4D 4D 4C 57 03 41 46 03 51 56 4D 03 4A 4D 03 67 6C 70 03 4E 4C 47 46 0D }
        $a35 = { 70 4C 4D 57 04 54 56 4B 43 56 45 49 04 47 45 4A 4A 4B 50 04 46 41 04 56 51 4A 04 4D 4A 04 60 6B 77 04 49 4B 40 41 0A }
        $a36 = { 71 4D 4C 56 05 55 57 4A 42 57 44 48 05 46 44 4B 4B 4A 51 05 47 40 05 57 50 4B 05 4C 4B 05 61 6A 76 05 48 4A 41 40 0B }
        $a37 = { 72 4E 4F 55 06 56 54 49 41 54 47 4B 06 45 47 48 48 49 52 06 44 43 06 54 53 48 06 4F 48 06 62 69 75 06 4B 49 42 43 08 }
        $a38 = { 73 4F 4E 54 07 57 55 48 40 55 46 4A 07 44 46 49 49 48 53 07 45 42 07 55 52 49 07 4E 49 07 63 68 74 07 4A 48 43 42 09 }
        $a39 = { 7C 40 41 5B 08 58 5A 47 4F 5A 49 45 08 4B 49 46 46 47 5C 08 4A 4D 08 5A 5D 46 08 41 46 08 6C 67 7B 08 45 47 4C 4D 06 }
        $a40 = { 7D 41 40 5A 09 59 5B 46 4E 5B 48 44 09 4A 48 47 47 46 5D 09 4B 4C 09 5B 5C 47 09 40 47 09 6D 66 7A 09 44 46 4D 4C 07 }
        $a41 = { 7E 42 43 59 0A 5A 58 45 4D 58 4B 47 0A 49 4B 44 44 45 5E 0A 48 4F 0A 58 5F 44 0A 43 44 0A 6E 65 79 0A 47 45 4E 4F 04 }
        $a42 = { 7F 43 42 58 0B 5B 59 44 4C 59 4A 46 0B 48 4A 45 45 44 5F 0B 49 4E 0B 59 5E 45 0B 42 45 0B 6F 64 78 0B 46 44 4F 4E 05 }
        $a43 = { 78 44 45 5F 0C 5C 5E 43 4B 5E 4D 41 0C 4F 4D 42 42 43 58 0C 4E 49 0C 5E 59 42 0C 45 42 0C 68 63 7F 0C 41 43 48 49 02 }
        $a44 = { 79 45 44 5E 0D 5D 5F 42 4A 5F 4C 40 0D 4E 4C 43 43 42 59 0D 4F 48 0D 5F 58 43 0D 44 43 0D 69 62 7E 0D 40 42 49 48 03 }
        $a45 = { 7A 46 47 5D 0E 5E 5C 41 49 5C 4F 43 0E 4D 4F 40 40 41 5A 0E 4C 4B 0E 5C 5B 40 0E 47 40 0E 6A 61 7D 0E 43 41 4A 4B 00 }
        $a46 = { 7B 47 46 5C 0F 5F 5D 40 48 5D 4E 42 0F 4C 4E 41 41 40 5B 0F 4D 4A 0F 5D 5A 41 0F 46 41 0F 6B 60 7C 0F 42 40 4B 4A 01 }
        $a47 = { 64 58 59 43 10 40 42 5F 57 42 51 5D 10 53 51 5E 5E 5F 44 10 52 55 10 42 45 5E 10 59 5E 10 74 7F 63 10 5D 5F 54 55 1E }
        $a48 = { 65 59 58 42 11 41 43 5E 56 43 50 5C 11 52 50 5F 5F 5E 45 11 53 54 11 43 44 5F 11 58 5F 11 75 7E 62 11 5C 5E 55 54 1F }
        $a49 = { 66 5A 5B 41 12 42 40 5D 55 40 53 5F 12 51 53 5C 5C 5D 46 12 50 57 12 40 47 5C 12 5B 5C 12 76 7D 61 12 5F 5D 56 57 1C }
        $a50 = { 67 5B 5A 40 13 43 41 5C 54 41 52 5E 13 50 52 5D 5D 5C 47 13 51 56 13 41 46 5D 13 5A 5D 13 77 7C 60 13 5E 5C 57 56 1D }
        $a51 = { 60 5C 5D 47 14 44 46 5B 53 46 55 59 14 57 55 5A 5A 5B 40 14 56 51 14 46 41 5A 14 5D 5A 14 70 7B 67 14 59 5B 50 51 1A }
        $a52 = { 61 5D 5C 46 15 45 47 5A 52 47 54 58 15 56 54 5B 5B 5A 41 15 57 50 15 47 40 5B 15 5C 5B 15 71 7A 66 15 58 5A 51 50 1B }
        $a53 = { 62 5E 5F 45 16 46 44 59 51 44 57 5B 16 55 57 58 58 59 42 16 54 53 16 44 43 58 16 5F 58 16 72 79 65 16 5B 59 52 53 18 }
        $a54 = { 63 5F 5E 44 17 47 45 58 50 45 56 5A 17 54 56 59 59 58 43 17 55 52 17 45 42 59 17 5E 59 17 73 78 64 17 5A 58 53 52 19 }
        $a55 = { 6C 50 51 4B 18 48 4A 57 5F 4A 59 55 18 5B 59 56 56 57 4C 18 5A 5D 18 4A 4D 56 18 51 56 18 7C 77 6B 18 55 57 5C 5D 16 }
        $a56 = { 6D 51 50 4A 19 49 4B 56 5E 4B 58 54 19 5A 58 57 57 56 4D 19 5B 5C 19 4B 4C 57 19 50 57 19 7D 76 6A 19 54 56 5D 5C 17 }
        $a57 = { 6E 52 53 49 1A 4A 48 55 5D 48 5B 57 1A 59 5B 54 54 55 4E 1A 58 5F 1A 48 4F 54 1A 53 54 1A 7E 75 69 1A 57 55 5E 5F 14 }
        $a58 = { 6F 53 52 48 1B 4B 49 54 5C 49 5A 56 1B 58 5A 55 55 54 4F 1B 59 5E 1B 49 4E 55 1B 52 55 1B 7F 74 68 1B 56 54 5F 5E 15 }
        $a59 = { 68 54 55 4F 1C 4C 4E 53 5B 4E 5D 51 1C 5F 5D 52 52 53 48 1C 5E 59 1C 4E 49 52 1C 55 52 1C 78 73 6F 1C 51 53 58 59 12 }
        $a60 = { 69 55 54 4E 1D 4D 4F 52 5A 4F 5C 50 1D 5E 5C 53 53 52 49 1D 5F 58 1D 4F 48 53 1D 54 53 1D 79 72 6E 1D 50 52 59 58 13 }
        $a61 = { 6A 56 57 4D 1E 4E 4C 51 59 4C 5F 53 1E 5D 5F 50 50 51 4A 1E 5C 5B 1E 4C 4B 50 1E 57 50 1E 7A 71 6D 1E 53 51 5A 5B 10 }
        $a62 = { 6B 57 56 4C 1F 4F 4D 50 58 4D 5E 52 1F 5C 5E 51 51 50 4B 1F 5D 5A 1F 4D 4A 51 1F 56 51 1F 7B 70 6C 1F 52 50 5B 5A 11 }
        $a63 = { 14 28 29 33 60 30 32 2F 27 32 21 2D 60 23 21 2E 2E 2F 34 60 22 25 60 32 35 2E 60 29 2E 60 04 0F 13 60 2D 2F 24 25 6E }
        $a64 = { 15 29 28 32 61 31 33 2E 26 33 20 2C 61 22 20 2F 2F 2E 35 61 23 24 61 33 34 2F 61 28 2F 61 05 0E 12 61 2C 2E 25 24 6F }
        $a65 = { 16 2A 2B 31 62 32 30 2D 25 30 23 2F 62 21 23 2C 2C 2D 36 62 20 27 62 30 37 2C 62 2B 2C 62 06 0D 11 62 2F 2D 26 27 6C }
        $a66 = { 17 2B 2A 30 63 33 31 2C 24 31 22 2E 63 20 22 2D 2D 2C 37 63 21 26 63 31 36 2D 63 2A 2D 63 07 0C 10 63 2E 2C 27 26 6D }
        $a67 = { 10 2C 2D 37 64 34 36 2B 23 36 25 29 64 27 25 2A 2A 2B 30 64 26 21 64 36 31 2A 64 2D 2A 64 00 0B 17 64 29 2B 20 21 6A }
        $a68 = { 11 2D 2C 36 65 35 37 2A 22 37 24 28 65 26 24 2B 2B 2A 31 65 27 20 65 37 30 2B 65 2C 2B 65 01 0A 16 65 28 2A 21 20 6B }
        $a69 = { 12 2E 2F 35 66 36 34 29 21 34 27 2B 66 25 27 28 28 29 32 66 24 23 66 34 33 28 66 2F 28 66 02 09 15 66 2B 29 22 23 68 }
        $a70 = { 13 2F 2E 34 67 37 35 28 20 35 26 2A 67 24 26 29 29 28 33 67 25 22 67 35 32 29 67 2E 29 67 03 08 14 67 2A 28 23 22 69 }
        $a71 = { 1C 20 21 3B 68 38 3A 27 2F 3A 29 25 68 2B 29 26 26 27 3C 68 2A 2D 68 3A 3D 26 68 21 26 68 0C 07 1B 68 25 27 2C 2D 66 }
        $a72 = { 1D 21 20 3A 69 39 3B 26 2E 3B 28 24 69 2A 28 27 27 26 3D 69 2B 2C 69 3B 3C 27 69 20 27 69 0D 06 1A 69 24 26 2D 2C 67 }
        $a73 = { 1E 22 23 39 6A 3A 38 25 2D 38 2B 27 6A 29 2B 24 24 25 3E 6A 28 2F 6A 38 3F 24 6A 23 24 6A 0E 05 19 6A 27 25 2E 2F 64 }
        $a74 = { 1F 23 22 38 6B 3B 39 24 2C 39 2A 26 6B 28 2A 25 25 24 3F 6B 29 2E 6B 39 3E 25 6B 22 25 6B 0F 04 18 6B 26 24 2F 2E 65 }
        $a75 = { 18 24 25 3F 6C 3C 3E 23 2B 3E 2D 21 6C 2F 2D 22 22 23 38 6C 2E 29 6C 3E 39 22 6C 25 22 6C 08 03 1F 6C 21 23 28 29 62 }
        $a76 = { 19 25 24 3E 6D 3D 3F 22 2A 3F 2C 20 6D 2E 2C 23 23 22 39 6D 2F 28 6D 3F 38 23 6D 24 23 6D 09 02 1E 6D 20 22 29 28 63 }
        $a77 = { 1A 26 27 3D 6E 3E 3C 21 29 3C 2F 23 6E 2D 2F 20 20 21 3A 6E 2C 2B 6E 3C 3B 20 6E 27 20 6E 0A 01 1D 6E 23 21 2A 2B 60 }
        $a78 = { 1B 27 26 3C 6F 3F 3D 20 28 3D 2E 22 6F 2C 2E 21 21 20 3B 6F 2D 2A 6F 3D 3A 21 6F 26 21 6F 0B 00 1C 6F 22 20 2B 2A 61 }
        $a79 = { 04 38 39 23 70 20 22 3F 37 22 31 3D 70 33 31 3E 3E 3F 24 70 32 35 70 22 25 3E 70 39 3E 70 14 1F 03 70 3D 3F 34 35 7E }
        $a80 = { 05 39 38 22 71 21 23 3E 36 23 30 3C 71 32 30 3F 3F 3E 25 71 33 34 71 23 24 3F 71 38 3F 71 15 1E 02 71 3C 3E 35 34 7F }
        $a81 = { 06 3A 3B 21 72 22 20 3D 35 20 33 3F 72 31 33 3C 3C 3D 26 72 30 37 72 20 27 3C 72 3B 3C 72 16 1D 01 72 3F 3D 36 37 7C }
        $a82 = { 07 3B 3A 20 73 23 21 3C 34 21 32 3E 73 30 32 3D 3D 3C 27 73 31 36 73 21 26 3D 73 3A 3D 73 17 1C 00 73 3E 3C 37 36 7D }
        $a83 = { 00 3C 3D 27 74 24 26 3B 33 26 35 39 74 37 35 3A 3A 3B 20 74 36 31 74 26 21 3A 74 3D 3A 74 10 1B 07 74 39 3B 30 31 7A }
        $a84 = { 01 3D 3C 26 75 25 27 3A 32 27 34 38 75 36 34 3B 3B 3A 21 75 37 30 75 27 20 3B 75 3C 3B 75 11 1A 06 75 38 3A 31 30 7B }
        $a85 = { 02 3E 3F 25 76 26 24 39 31 24 37 3B 76 35 37 38 38 39 22 76 34 33 76 24 23 38 76 3F 38 76 12 19 05 76 3B 39 32 33 78 }
        $a86 = { 03 3F 3E 24 77 27 25 38 30 25 36 3A 77 34 36 39 39 38 23 77 35 32 77 25 22 39 77 3E 39 77 13 18 04 77 3A 38 33 32 79 }
        $a87 = { 0C 30 31 2B 78 28 2A 37 3F 2A 39 35 78 3B 39 36 36 37 2C 78 3A 3D 78 2A 2D 36 78 31 36 78 1C 17 0B 78 35 37 3C 3D 76 }
        $a88 = { 0D 31 30 2A 79 29 2B 36 3E 2B 38 34 79 3A 38 37 37 36 2D 79 3B 3C 79 2B 2C 37 79 30 37 79 1D 16 0A 79 34 36 3D 3C 77 }
        $a89 = { 0E 32 33 29 7A 2A 28 35 3D 28 3B 37 7A 39 3B 34 34 35 2E 7A 38 3F 7A 28 2F 34 7A 33 34 7A 1E 15 09 7A 37 35 3E 3F 74 }
        $a90 = { 0F 33 32 28 7B 2B 29 34 3C 29 3A 36 7B 38 3A 35 35 34 2F 7B 39 3E 7B 29 2E 35 7B 32 35 7B 1F 14 08 7B 36 34 3F 3E 75 }
        $a91 = { 08 34 35 2F 7C 2C 2E 33 3B 2E 3D 31 7C 3F 3D 32 32 33 28 7C 3E 39 7C 2E 29 32 7C 35 32 7C 18 13 0F 7C 31 33 38 39 72 }
        $a92 = { 09 35 34 2E 7D 2D 2F 32 3A 2F 3C 30 7D 3E 3C 33 33 32 29 7D 3F 38 7D 2F 28 33 7D 34 33 7D 19 12 0E 7D 30 32 39 38 73 }
        $a93 = { 0A 36 37 2D 7E 2E 2C 31 39 2C 3F 33 7E 3D 3F 30 30 31 2A 7E 3C 3B 7E 2C 2B 30 7E 37 30 7E 1A 11 0D 7E 33 31 3A 3B 70 }
        $a94 = { 0B 37 36 2C 7F 2F 2D 30 38 2D 3E 32 7F 3C 3E 31 31 30 2B 7F 3D 3A 7F 2D 2A 31 7F 36 31 7F 1B 10 0C 7F 32 30 3B 3A 71 }
        $a95 = { 34 08 09 13 40 10 12 0F 07 12 01 0D 40 03 01 0E 0E 0F 14 40 02 05 40 12 15 0E 40 09 0E 40 24 2F 33 40 0D 0F 04 05 4E }
        $a96 = { 35 09 08 12 41 11 13 0E 06 13 00 0C 41 02 00 0F 0F 0E 15 41 03 04 41 13 14 0F 41 08 0F 41 25 2E 32 41 0C 0E 05 04 4F }
        $a97 = { 36 0A 0B 11 42 12 10 0D 05 10 03 0F 42 01 03 0C 0C 0D 16 42 00 07 42 10 17 0C 42 0B 0C 42 26 2D 31 42 0F 0D 06 07 4C }
        $a98 = { 37 0B 0A 10 43 13 11 0C 04 11 02 0E 43 00 02 0D 0D 0C 17 43 01 06 43 11 16 0D 43 0A 0D 43 27 2C 30 43 0E 0C 07 06 4D }
        $a99 = { 30 0C 0D 17 44 14 16 0B 03 16 05 09 44 07 05 0A 0A 0B 10 44 06 01 44 16 11 0A 44 0D 0A 44 20 2B 37 44 09 0B 00 01 4A }
        $a100 = { 31 0D 0C 16 45 15 17 0A 02 17 04 08 45 06 04 0B 0B 0A 11 45 07 00 45 17 10 0B 45 0C 0B 45 21 2A 36 45 08 0A 01 00 4B }
        $a101 = { 32 0E 0F 15 46 16 14 09 01 14 07 0B 46 05 07 08 08 09 12 46 04 03 46 14 13 08 46 0F 08 46 22 29 35 46 0B 09 02 03 48 }
        $a102 = { 33 0F 0E 14 47 17 15 08 00 15 06 0A 47 04 06 09 09 08 13 47 05 02 47 15 12 09 47 0E 09 47 23 28 34 47 0A 08 03 02 49 }
        $a103 = { 3C 00 01 1B 48 18 1A 07 0F 1A 09 05 48 0B 09 06 06 07 1C 48 0A 0D 48 1A 1D 06 48 01 06 48 2C 27 3B 48 05 07 0C 0D 46 }
        $a104 = { 3D 01 00 1A 49 19 1B 06 0E 1B 08 04 49 0A 08 07 07 06 1D 49 0B 0C 49 1B 1C 07 49 00 07 49 2D 26 3A 49 04 06 0D 0C 47 }
        $a105 = { 3E 02 03 19 4A 1A 18 05 0D 18 0B 07 4A 09 0B 04 04 05 1E 4A 08 0F 4A 18 1F 04 4A 03 04 4A 2E 25 39 4A 07 05 0E 0F 44 }
        $a106 = { 3F 03 02 18 4B 1B 19 04 0C 19 0A 06 4B 08 0A 05 05 04 1F 4B 09 0E 4B 19 1E 05 4B 02 05 4B 2F 24 38 4B 06 04 0F 0E 45 }
        $a107 = { 38 04 05 1F 4C 1C 1E 03 0B 1E 0D 01 4C 0F 0D 02 02 03 18 4C 0E 09 4C 1E 19 02 4C 05 02 4C 28 23 3F 4C 01 03 08 09 42 }
        $a108 = { 39 05 04 1E 4D 1D 1F 02 0A 1F 0C 00 4D 0E 0C 03 03 02 19 4D 0F 08 4D 1F 18 03 4D 04 03 4D 29 22 3E 4D 00 02 09 08 43 }
        $a109 = { 3A 06 07 1D 4E 1E 1C 01 09 1C 0F 03 4E 0D 0F 00 00 01 1A 4E 0C 0B 4E 1C 1B 00 4E 07 00 4E 2A 21 3D 4E 03 01 0A 0B 40 }
        $a110 = { 3B 07 06 1C 4F 1F 1D 00 08 1D 0E 02 4F 0C 0E 01 01 00 1B 4F 0D 0A 4F 1D 1A 01 4F 06 01 4F 2B 20 3C 4F 02 00 0B 0A 41 }
        $a111 = { 24 18 19 03 50 00 02 1F 17 02 11 1D 50 13 11 1E 1E 1F 04 50 12 15 50 02 05 1E 50 19 1E 50 34 3F 23 50 1D 1F 14 15 5E }
        $a112 = { 25 19 18 02 51 01 03 1E 16 03 10 1C 51 12 10 1F 1F 1E 05 51 13 14 51 03 04 1F 51 18 1F 51 35 3E 22 51 1C 1E 15 14 5F }
        $a113 = { 26 1A 1B 01 52 02 00 1D 15 00 13 1F 52 11 13 1C 1C 1D 06 52 10 17 52 00 07 1C 52 1B 1C 52 36 3D 21 52 1F 1D 16 17 5C }
        $a114 = { 27 1B 1A 00 53 03 01 1C 14 01 12 1E 53 10 12 1D 1D 1C 07 53 11 16 53 01 06 1D 53 1A 1D 53 37 3C 20 53 1E 1C 17 16 5D }
        $a115 = { 20 1C 1D 07 54 04 06 1B 13 06 15 19 54 17 15 1A 1A 1B 00 54 16 11 54 06 01 1A 54 1D 1A 54 30 3B 27 54 19 1B 10 11 5A }
        $a116 = { 21 1D 1C 06 55 05 07 1A 12 07 14 18 55 16 14 1B 1B 1A 01 55 17 10 55 07 00 1B 55 1C 1B 55 31 3A 26 55 18 1A 11 10 5B }
        $a117 = { 22 1E 1F 05 56 06 04 19 11 04 17 1B 56 15 17 18 18 19 02 56 14 13 56 04 03 18 56 1F 18 56 32 39 25 56 1B 19 12 13 58 }
        $a118 = { 23 1F 1E 04 57 07 05 18 10 05 16 1A 57 14 16 19 19 18 03 57 15 12 57 05 02 19 57 1E 19 57 33 38 24 57 1A 18 13 12 59 }
        $a119 = { 2C 10 11 0B 58 08 0A 17 1F 0A 19 15 58 1B 19 16 16 17 0C 58 1A 1D 58 0A 0D 16 58 11 16 58 3C 37 2B 58 15 17 1C 1D 56 }
        $a120 = { 2D 11 10 0A 59 09 0B 16 1E 0B 18 14 59 1A 18 17 17 16 0D 59 1B 1C 59 0B 0C 17 59 10 17 59 3D 36 2A 59 14 16 1D 1C 57 }
        $a121 = { 2E 12 13 09 5A 0A 08 15 1D 08 1B 17 5A 19 1B 14 14 15 0E 5A 18 1F 5A 08 0F 14 5A 13 14 5A 3E 35 29 5A 17 15 1E 1F 54 }
        $a122 = { 2F 13 12 08 5B 0B 09 14 1C 09 1A 16 5B 18 1A 15 15 14 0F 5B 19 1E 5B 09 0E 15 5B 12 15 5B 3F 34 28 5B 16 14 1F 1E 55 }
        $a123 = { 28 14 15 0F 5C 0C 0E 13 1B 0E 1D 11 5C 1F 1D 12 12 13 08 5C 1E 19 5C 0E 09 12 5C 15 12 5C 38 33 2F 5C 11 13 18 19 52 }
        $a124 = { 29 15 14 0E 5D 0D 0F 12 1A 0F 1C 10 5D 1E 1C 13 13 12 09 5D 1F 18 5D 0F 08 13 5D 14 13 5D 39 32 2E 5D 10 12 19 18 53 }
        $a125 = { 2A 16 17 0D 5E 0E 0C 11 19 0C 1F 13 5E 1D 1F 10 10 11 0A 5E 1C 1B 5E 0C 0B 10 5E 17 10 5E 3A 31 2D 5E 13 11 1A 1B 50 }
        $a126 = { 2B 17 16 0C 5F 0F 0D 10 18 0D 1E 12 5F 1C 1E 11 11 10 0B 5F 1D 1A 5F 0D 0A 11 5F 16 11 5F 3B 30 2C 5F 12 10 1B 1A 51 }
        $a127 = { D4 E8 E9 F3 A0 F0 F2 EF E7 F2 E1 ED A0 E3 E1 EE EE EF F4 A0 E2 E5 A0 F2 F5 EE A0 E9 EE A0 C4 CF D3 A0 ED EF E4 E5 AE }
        $a128 = { D5 E9 E8 F2 A1 F1 F3 EE E6 F3 E0 EC A1 E2 E0 EF EF EE F5 A1 E3 E4 A1 F3 F4 EF A1 E8 EF A1 C5 CE D2 A1 EC EE E5 E4 AF }
        $a129 = { D6 EA EB F1 A2 F2 F0 ED E5 F0 E3 EF A2 E1 E3 EC EC ED F6 A2 E0 E7 A2 F0 F7 EC A2 EB EC A2 C6 CD D1 A2 EF ED E6 E7 AC }
        $a130 = { D7 EB EA F0 A3 F3 F1 EC E4 F1 E2 EE A3 E0 E2 ED ED EC F7 A3 E1 E6 A3 F1 F6 ED A3 EA ED A3 C7 CC D0 A3 EE EC E7 E6 AD }
        $a131 = { D0 EC ED F7 A4 F4 F6 EB E3 F6 E5 E9 A4 E7 E5 EA EA EB F0 A4 E6 E1 A4 F6 F1 EA A4 ED EA A4 C0 CB D7 A4 E9 EB E0 E1 AA }
        $a132 = { D1 ED EC F6 A5 F5 F7 EA E2 F7 E4 E8 A5 E6 E4 EB EB EA F1 A5 E7 E0 A5 F7 F0 EB A5 EC EB A5 C1 CA D6 A5 E8 EA E1 E0 AB }
        $a133 = { D2 EE EF F5 A6 F6 F4 E9 E1 F4 E7 EB A6 E5 E7 E8 E8 E9 F2 A6 E4 E3 A6 F4 F3 E8 A6 EF E8 A6 C2 C9 D5 A6 EB E9 E2 E3 A8 }
        $a134 = { D3 EF EE F4 A7 F7 F5 E8 E0 F5 E6 EA A7 E4 E6 E9 E9 E8 F3 A7 E5 E2 A7 F5 F2 E9 A7 EE E9 A7 C3 C8 D4 A7 EA E8 E3 E2 A9 }
        $a135 = { DC E0 E1 FB A8 F8 FA E7 EF FA E9 E5 A8 EB E9 E6 E6 E7 FC A8 EA ED A8 FA FD E6 A8 E1 E6 A8 CC C7 DB A8 E5 E7 EC ED A6 }
        $a136 = { DD E1 E0 FA A9 F9 FB E6 EE FB E8 E4 A9 EA E8 E7 E7 E6 FD A9 EB EC A9 FB FC E7 A9 E0 E7 A9 CD C6 DA A9 E4 E6 ED EC A7 }
        $a137 = { DE E2 E3 F9 AA FA F8 E5 ED F8 EB E7 AA E9 EB E4 E4 E5 FE AA E8 EF AA F8 FF E4 AA E3 E4 AA CE C5 D9 AA E7 E5 EE EF A4 }
        $a138 = { DF E3 E2 F8 AB FB F9 E4 EC F9 EA E6 AB E8 EA E5 E5 E4 FF AB E9 EE AB F9 FE E5 AB E2 E5 AB CF C4 D8 AB E6 E4 EF EE A5 }
        $a139 = { D8 E4 E5 FF AC FC FE E3 EB FE ED E1 AC EF ED E2 E2 E3 F8 AC EE E9 AC FE F9 E2 AC E5 E2 AC C8 C3 DF AC E1 E3 E8 E9 A2 }
        $a140 = { D9 E5 E4 FE AD FD FF E2 EA FF EC E0 AD EE EC E3 E3 E2 F9 AD EF E8 AD FF F8 E3 AD E4 E3 AD C9 C2 DE AD E0 E2 E9 E8 A3 }
        $a141 = { DA E6 E7 FD AE FE FC E1 E9 FC EF E3 AE ED EF E0 E0 E1 FA AE EC EB AE FC FB E0 AE E7 E0 AE CA C1 DD AE E3 E1 EA EB A0 }
        $a142 = { DB E7 E6 FC AF FF FD E0 E8 FD EE E2 AF EC EE E1 E1 E0 FB AF ED EA AF FD FA E1 AF E6 E1 AF CB C0 DC AF E2 E0 EB EA A1 }
        $a143 = { C4 F8 F9 E3 B0 E0 E2 FF F7 E2 F1 FD B0 F3 F1 FE FE FF E4 B0 F2 F5 B0 E2 E5 FE B0 F9 FE B0 D4 DF C3 B0 FD FF F4 F5 BE }
        $a144 = { C5 F9 F8 E2 B1 E1 E3 FE F6 E3 F0 FC B1 F2 F0 FF FF FE E5 B1 F3 F4 B1 E3 E4 FF B1 F8 FF B1 D5 DE C2 B1 FC FE F5 F4 BF }
        $a145 = { C6 FA FB E1 B2 E2 E0 FD F5 E0 F3 FF B2 F1 F3 FC FC FD E6 B2 F0 F7 B2 E0 E7 FC B2 FB FC B2 D6 DD C1 B2 FF FD F6 F7 BC }
        $a146 = { C7 FB FA E0 B3 E3 E1 FC F4 E1 F2 FE B3 F0 F2 FD FD FC E7 B3 F1 F6 B3 E1 E6 FD B3 FA FD B3 D7 DC C0 B3 FE FC F7 F6 BD }
        $a147 = { C0 FC FD E7 B4 E4 E6 FB F3 E6 F5 F9 B4 F7 F5 FA FA FB E0 B4 F6 F1 B4 E6 E1 FA B4 FD FA B4 D0 DB C7 B4 F9 FB F0 F1 BA }
        $a148 = { C1 FD FC E6 B5 E5 E7 FA F2 E7 F4 F8 B5 F6 F4 FB FB FA E1 B5 F7 F0 B5 E7 E0 FB B5 FC FB B5 D1 DA C6 B5 F8 FA F1 F0 BB }
        $a149 = { C2 FE FF E5 B6 E6 E4 F9 F1 E4 F7 FB B6 F5 F7 F8 F8 F9 E2 B6 F4 F3 B6 E4 E3 F8 B6 FF F8 B6 D2 D9 C5 B6 FB F9 F2 F3 B8 }
        $a150 = { C3 FF FE E4 B7 E7 E5 F8 F0 E5 F6 FA B7 F4 F6 F9 F9 F8 E3 B7 F5 F2 B7 E5 E2 F9 B7 FE F9 B7 D3 D8 C4 B7 FA F8 F3 F2 B9 }
        $a151 = { CC F0 F1 EB B8 E8 EA F7 FF EA F9 F5 B8 FB F9 F6 F6 F7 EC B8 FA FD B8 EA ED F6 B8 F1 F6 B8 DC D7 CB B8 F5 F7 FC FD B6 }
        $a152 = { CD F1 F0 EA B9 E9 EB F6 FE EB F8 F4 B9 FA F8 F7 F7 F6 ED B9 FB FC B9 EB EC F7 B9 F0 F7 B9 DD D6 CA B9 F4 F6 FD FC B7 }
        $a153 = { CE F2 F3 E9 BA EA E8 F5 FD E8 FB F7 BA F9 FB F4 F4 F5 EE BA F8 FF BA E8 EF F4 BA F3 F4 BA DE D5 C9 BA F7 F5 FE FF B4 }
        $a154 = { CF F3 F2 E8 BB EB E9 F4 FC E9 FA F6 BB F8 FA F5 F5 F4 EF BB F9 FE BB E9 EE F5 BB F2 F5 BB DF D4 C8 BB F6 F4 FF FE B5 }
        $a155 = { C8 F4 F5 EF BC EC EE F3 FB EE FD F1 BC FF FD F2 F2 F3 E8 BC FE F9 BC EE E9 F2 BC F5 F2 BC D8 D3 CF BC F1 F3 F8 F9 B2 }
        $a156 = { C9 F5 F4 EE BD ED EF F2 FA EF FC F0 BD FE FC F3 F3 F2 E9 BD FF F8 BD EF E8 F3 BD F4 F3 BD D9 D2 CE BD F0 F2 F9 F8 B3 }
        $a157 = { CA F6 F7 ED BE EE EC F1 F9 EC FF F3 BE FD FF F0 F0 F1 EA BE FC FB BE EC EB F0 BE F7 F0 BE DA D1 CD BE F3 F1 FA FB B0 }
        $a158 = { CB F7 F6 EC BF EF ED F0 F8 ED FE F2 BF FC FE F1 F1 F0 EB BF FD FA BF ED EA F1 BF F6 F1 BF DB D0 CC BF F2 F0 FB FA B1 }
        $a159 = { F4 C8 C9 D3 80 D0 D2 CF C7 D2 C1 CD 80 C3 C1 CE CE CF D4 80 C2 C5 80 D2 D5 CE 80 C9 CE 80 E4 EF F3 80 CD CF C4 C5 8E }
        $a160 = { F5 C9 C8 D2 81 D1 D3 CE C6 D3 C0 CC 81 C2 C0 CF CF CE D5 81 C3 C4 81 D3 D4 CF 81 C8 CF 81 E5 EE F2 81 CC CE C5 C4 8F }
        $a161 = { F6 CA CB D1 82 D2 D0 CD C5 D0 C3 CF 82 C1 C3 CC CC CD D6 82 C0 C7 82 D0 D7 CC 82 CB CC 82 E6 ED F1 82 CF CD C6 C7 8C }
        $a162 = { F7 CB CA D0 83 D3 D1 CC C4 D1 C2 CE 83 C0 C2 CD CD CC D7 83 C1 C6 83 D1 D6 CD 83 CA CD 83 E7 EC F0 83 CE CC C7 C6 8D }
        $a163 = { F0 CC CD D7 84 D4 D6 CB C3 D6 C5 C9 84 C7 C5 CA CA CB D0 84 C6 C1 84 D6 D1 CA 84 CD CA 84 E0 EB F7 84 C9 CB C0 C1 8A }
        $a164 = { F1 CD CC D6 85 D5 D7 CA C2 D7 C4 C8 85 C6 C4 CB CB CA D1 85 C7 C0 85 D7 D0 CB 85 CC CB 85 E1 EA F6 85 C8 CA C1 C0 8B }
        $a165 = { F2 CE CF D5 86 D6 D4 C9 C1 D4 C7 CB 86 C5 C7 C8 C8 C9 D2 86 C4 C3 86 D4 D3 C8 86 CF C8 86 E2 E9 F5 86 CB C9 C2 C3 88 }
        $a166 = { F3 CF CE D4 87 D7 D5 C8 C0 D5 C6 CA 87 C4 C6 C9 C9 C8 D3 87 C5 C2 87 D5 D2 C9 87 CE C9 87 E3 E8 F4 87 CA C8 C3 C2 89 }
        $a167 = { FC C0 C1 DB 88 D8 DA C7 CF DA C9 C5 88 CB C9 C6 C6 C7 DC 88 CA CD 88 DA DD C6 88 C1 C6 88 EC E7 FB 88 C5 C7 CC CD 86 }
        $a168 = { FD C1 C0 DA 89 D9 DB C6 CE DB C8 C4 89 CA C8 C7 C7 C6 DD 89 CB CC 89 DB DC C7 89 C0 C7 89 ED E6 FA 89 C4 C6 CD CC 87 }
        $a169 = { FE C2 C3 D9 8A DA D8 C5 CD D8 CB C7 8A C9 CB C4 C4 C5 DE 8A C8 CF 8A D8 DF C4 8A C3 C4 8A EE E5 F9 8A C7 C5 CE CF 84 }
        $a170 = { FF C3 C2 D8 8B DB D9 C4 CC D9 CA C6 8B C8 CA C5 C5 C4 DF 8B C9 CE 8B D9 DE C5 8B C2 C5 8B EF E4 F8 8B C6 C4 CF CE 85 }
        $a171 = { F8 C4 C5 DF 8C DC DE C3 CB DE CD C1 8C CF CD C2 C2 C3 D8 8C CE C9 8C DE D9 C2 8C C5 C2 8C E8 E3 FF 8C C1 C3 C8 C9 82 }
        $a172 = { F9 C5 C4 DE 8D DD DF C2 CA DF CC C0 8D CE CC C3 C3 C2 D9 8D CF C8 8D DF D8 C3 8D C4 C3 8D E9 E2 FE 8D C0 C2 C9 C8 83 }
        $a173 = { FA C6 C7 DD 8E DE DC C1 C9 DC CF C3 8E CD CF C0 C0 C1 DA 8E CC CB 8E DC DB C0 8E C7 C0 8E EA E1 FD 8E C3 C1 CA CB 80 }
        $a174 = { FB C7 C6 DC 8F DF DD C0 C8 DD CE C2 8F CC CE C1 C1 C0 DB 8F CD CA 8F DD DA C1 8F C6 C1 8F EB E0 FC 8F C2 C0 CB CA 81 }
        $a175 = { E4 D8 D9 C3 90 C0 C2 DF D7 C2 D1 DD 90 D3 D1 DE DE DF C4 90 D2 D5 90 C2 C5 DE 90 D9 DE 90 F4 FF E3 90 DD DF D4 D5 9E }
        $a176 = { E5 D9 D8 C2 91 C1 C3 DE D6 C3 D0 DC 91 D2 D0 DF DF DE C5 91 D3 D4 91 C3 C4 DF 91 D8 DF 91 F5 FE E2 91 DC DE D5 D4 9F }
        $a177 = { E6 DA DB C1 92 C2 C0 DD D5 C0 D3 DF 92 D1 D3 DC DC DD C6 92 D0 D7 92 C0 C7 DC 92 DB DC 92 F6 FD E1 92 DF DD D6 D7 9C }
        $a178 = { E7 DB DA C0 93 C3 C1 DC D4 C1 D2 DE 93 D0 D2 DD DD DC C7 93 D1 D6 93 C1 C6 DD 93 DA DD 93 F7 FC E0 93 DE DC D7 D6 9D }
        $a179 = { E0 DC DD C7 94 C4 C6 DB D3 C6 D5 D9 94 D7 D5 DA DA DB C0 94 D6 D1 94 C6 C1 DA 94 DD DA 94 F0 FB E7 94 D9 DB D0 D1 9A }
        $a180 = { E1 DD DC C6 95 C5 C7 DA D2 C7 D4 D8 95 D6 D4 DB DB DA C1 95 D7 D0 95 C7 C0 DB 95 DC DB 95 F1 FA E6 95 D8 DA D1 D0 9B }
        $a181 = { E2 DE DF C5 96 C6 C4 D9 D1 C4 D7 DB 96 D5 D7 D8 D8 D9 C2 96 D4 D3 96 C4 C3 D8 96 DF D8 96 F2 F9 E5 96 DB D9 D2 D3 98 }
        $a182 = { E3 DF DE C4 97 C7 C5 D8 D0 C5 D6 DA 97 D4 D6 D9 D9 D8 C3 97 D5 D2 97 C5 C2 D9 97 DE D9 97 F3 F8 E4 97 DA D8 D3 D2 99 }
        $a183 = { EC D0 D1 CB 98 C8 CA D7 DF CA D9 D5 98 DB D9 D6 D6 D7 CC 98 DA DD 98 CA CD D6 98 D1 D6 98 FC F7 EB 98 D5 D7 DC DD 96 }
        $a184 = { ED D1 D0 CA 99 C9 CB D6 DE CB D8 D4 99 DA D8 D7 D7 D6 CD 99 DB DC 99 CB CC D7 99 D0 D7 99 FD F6 EA 99 D4 D6 DD DC 97 }
        $a185 = { EE D2 D3 C9 9A CA C8 D5 DD C8 DB D7 9A D9 DB D4 D4 D5 CE 9A D8 DF 9A C8 CF D4 9A D3 D4 9A FE F5 E9 9A D7 D5 DE DF 94 }
        $a186 = { EF D3 D2 C8 9B CB C9 D4 DC C9 DA D6 9B D8 DA D5 D5 D4 CF 9B D9 DE 9B C9 CE D5 9B D2 D5 9B FF F4 E8 9B D6 D4 DF DE 95 }
        $a187 = { E8 D4 D5 CF 9C CC CE D3 DB CE DD D1 9C DF DD D2 D2 D3 C8 9C DE D9 9C CE C9 D2 9C D5 D2 9C F8 F3 EF 9C D1 D3 D8 D9 92 }
        $a188 = { E9 D5 D4 CE 9D CD CF D2 DA CF DC D0 9D DE DC D3 D3 D2 C9 9D DF D8 9D CF C8 D3 9D D4 D3 9D F9 F2 EE 9D D0 D2 D9 D8 93 }
        $a189 = { EA D6 D7 CD 9E CE CC D1 D9 CC DF D3 9E DD DF D0 D0 D1 CA 9E DC DB 9E CC CB D0 9E D7 D0 9E FA F1 ED 9E D3 D1 DA DB 90 }
        $a190 = { EB D7 D6 CC 9F CF CD D0 D8 CD DE D2 9F DC DE D1 D1 D0 CB 9F DD DA 9F CD CA D1 9F D6 D1 9F FB F0 EC 9F D2 D0 DB DA 91 }
        $a191 = { 94 A8 A9 B3 E0 B0 B2 AF A7 B2 A1 AD E0 A3 A1 AE AE AF B4 E0 A2 A5 E0 B2 B5 AE E0 A9 AE E0 84 8F 93 E0 AD AF A4 A5 EE }
        $a192 = { 95 A9 A8 B2 E1 B1 B3 AE A6 B3 A0 AC E1 A2 A0 AF AF AE B5 E1 A3 A4 E1 B3 B4 AF E1 A8 AF E1 85 8E 92 E1 AC AE A5 A4 EF }
        $a193 = { 96 AA AB B1 E2 B2 B0 AD A5 B0 A3 AF E2 A1 A3 AC AC AD B6 E2 A0 A7 E2 B0 B7 AC E2 AB AC E2 86 8D 91 E2 AF AD A6 A7 EC }
        $a194 = { 97 AB AA B0 E3 B3 B1 AC A4 B1 A2 AE E3 A0 A2 AD AD AC B7 E3 A1 A6 E3 B1 B6 AD E3 AA AD E3 87 8C 90 E3 AE AC A7 A6 ED }
        $a195 = { 90 AC AD B7 E4 B4 B6 AB A3 B6 A5 A9 E4 A7 A5 AA AA AB B0 E4 A6 A1 E4 B6 B1 AA E4 AD AA E4 80 8B 97 E4 A9 AB A0 A1 EA }
        $a196 = { 91 AD AC B6 E5 B5 B7 AA A2 B7 A4 A8 E5 A6 A4 AB AB AA B1 E5 A7 A0 E5 B7 B0 AB E5 AC AB E5 81 8A 96 E5 A8 AA A1 A0 EB }
        $a197 = { 92 AE AF B5 E6 B6 B4 A9 A1 B4 A7 AB E6 A5 A7 A8 A8 A9 B2 E6 A4 A3 E6 B4 B3 A8 E6 AF A8 E6 82 89 95 E6 AB A9 A2 A3 E8 }
        $a198 = { 93 AF AE B4 E7 B7 B5 A8 A0 B5 A6 AA E7 A4 A6 A9 A9 A8 B3 E7 A5 A2 E7 B5 B2 A9 E7 AE A9 E7 83 88 94 E7 AA A8 A3 A2 E9 }
        $a199 = { 9C A0 A1 BB E8 B8 BA A7 AF BA A9 A5 E8 AB A9 A6 A6 A7 BC E8 AA AD E8 BA BD A6 E8 A1 A6 E8 8C 87 9B E8 A5 A7 AC AD E6 }
        $a200 = { 9D A1 A0 BA E9 B9 BB A6 AE BB A8 A4 E9 AA A8 A7 A7 A6 BD E9 AB AC E9 BB BC A7 E9 A0 A7 E9 8D 86 9A E9 A4 A6 AD AC E7 }
        $a201 = { 9E A2 A3 B9 EA BA B8 A5 AD B8 AB A7 EA A9 AB A4 A4 A5 BE EA A8 AF EA B8 BF A4 EA A3 A4 EA 8E 85 99 EA A7 A5 AE AF E4 }
        $a202 = { 9F A3 A2 B8 EB BB B9 A4 AC B9 AA A6 EB A8 AA A5 A5 A4 BF EB A9 AE EB B9 BE A5 EB A2 A5 EB 8F 84 98 EB A6 A4 AF AE E5 }
        $a203 = { 98 A4 A5 BF EC BC BE A3 AB BE AD A1 EC AF AD A2 A2 A3 B8 EC AE A9 EC BE B9 A2 EC A5 A2 EC 88 83 9F EC A1 A3 A8 A9 E2 }
        $a204 = { 99 A5 A4 BE ED BD BF A2 AA BF AC A0 ED AE AC A3 A3 A2 B9 ED AF A8 ED BF B8 A3 ED A4 A3 ED 89 82 9E ED A0 A2 A9 A8 E3 }
        $a205 = { 9A A6 A7 BD EE BE BC A1 A9 BC AF A3 EE AD AF A0 A0 A1 BA EE AC AB EE BC BB A0 EE A7 A0 EE 8A 81 9D EE A3 A1 AA AB E0 }
        $a206 = { 9B A7 A6 BC EF BF BD A0 A8 BD AE A2 EF AC AE A1 A1 A0 BB EF AD AA EF BD BA A1 EF A6 A1 EF 8B 80 9C EF A2 A0 AB AA E1 }
        $a207 = { 84 B8 B9 A3 F0 A0 A2 BF B7 A2 B1 BD F0 B3 B1 BE BE BF A4 F0 B2 B5 F0 A2 A5 BE F0 B9 BE F0 94 9F 83 F0 BD BF B4 B5 FE }
        $a208 = { 85 B9 B8 A2 F1 A1 A3 BE B6 A3 B0 BC F1 B2 B0 BF BF BE A5 F1 B3 B4 F1 A3 A4 BF F1 B8 BF F1 95 9E 82 F1 BC BE B5 B4 FF }
        $a209 = { 86 BA BB A1 F2 A2 A0 BD B5 A0 B3 BF F2 B1 B3 BC BC BD A6 F2 B0 B7 F2 A0 A7 BC F2 BB BC F2 96 9D 81 F2 BF BD B6 B7 FC }
        $a210 = { 87 BB BA A0 F3 A3 A1 BC B4 A1 B2 BE F3 B0 B2 BD BD BC A7 F3 B1 B6 F3 A1 A6 BD F3 BA BD F3 97 9C 80 F3 BE BC B7 B6 FD }
        $a211 = { 80 BC BD A7 F4 A4 A6 BB B3 A6 B5 B9 F4 B7 B5 BA BA BB A0 F4 B6 B1 F4 A6 A1 BA F4 BD BA F4 90 9B 87 F4 B9 BB B0 B1 FA }
        $a212 = { 81 BD BC A6 F5 A5 A7 BA B2 A7 B4 B8 F5 B6 B4 BB BB BA A1 F5 B7 B0 F5 A7 A0 BB F5 BC BB F5 91 9A 86 F5 B8 BA B1 B0 FB }
        $a213 = { 82 BE BF A5 F6 A6 A4 B9 B1 A4 B7 BB F6 B5 B7 B8 B8 B9 A2 F6 B4 B3 F6 A4 A3 B8 F6 BF B8 F6 92 99 85 F6 BB B9 B2 B3 F8 }
        $a214 = { 83 BF BE A4 F7 A7 A5 B8 B0 A5 B6 BA F7 B4 B6 B9 B9 B8 A3 F7 B5 B2 F7 A5 A2 B9 F7 BE B9 F7 93 98 84 F7 BA B8 B3 B2 F9 }
        $a215 = { 8C B0 B1 AB F8 A8 AA B7 BF AA B9 B5 F8 BB B9 B6 B6 B7 AC F8 BA BD F8 AA AD B6 F8 B1 B6 F8 9C 97 8B F8 B5 B7 BC BD F6 }
        $a216 = { 8D B1 B0 AA F9 A9 AB B6 BE AB B8 B4 F9 BA B8 B7 B7 B6 AD F9 BB BC F9 AB AC B7 F9 B0 B7 F9 9D 96 8A F9 B4 B6 BD BC F7 }
        $a217 = { 8E B2 B3 A9 FA AA A8 B5 BD A8 BB B7 FA B9 BB B4 B4 B5 AE FA B8 BF FA A8 AF B4 FA B3 B4 FA 9E 95 89 FA B7 B5 BE BF F4 }
        $a218 = { 8F B3 B2 A8 FB AB A9 B4 BC A9 BA B6 FB B8 BA B5 B5 B4 AF FB B9 BE FB A9 AE B5 FB B2 B5 FB 9F 94 88 FB B6 B4 BF BE F5 }
        $a219 = { 88 B4 B5 AF FC AC AE B3 BB AE BD B1 FC BF BD B2 B2 B3 A8 FC BE B9 FC AE A9 B2 FC B5 B2 FC 98 93 8F FC B1 B3 B8 B9 F2 }
        $a220 = { 89 B5 B4 AE FD AD AF B2 BA AF BC B0 FD BE BC B3 B3 B2 A9 FD BF B8 FD AF A8 B3 FD B4 B3 FD 99 92 8E FD B0 B2 B9 B8 F3 }
        $a221 = { 8A B6 B7 AD FE AE AC B1 B9 AC BF B3 FE BD BF B0 B0 B1 AA FE BC BB FE AC AB B0 FE B7 B0 FE 9A 91 8D FE B3 B1 BA BB F0 }
        $a222 = { 8B B7 B6 AC FF AF AD B0 B8 AD BE B2 FF BC BE B1 B1 B0 AB FF BD BA FF AD AA B1 FF B6 B1 FF 9B 90 8C FF B2 B0 BB BA F1 }
        $a223 = { B4 88 89 93 C0 90 92 8F 87 92 81 8D C0 83 81 8E 8E 8F 94 C0 82 85 C0 92 95 8E C0 89 8E C0 A4 AF B3 C0 8D 8F 84 85 CE }
        $a224 = { B5 89 88 92 C1 91 93 8E 86 93 80 8C C1 82 80 8F 8F 8E 95 C1 83 84 C1 93 94 8F C1 88 8F C1 A5 AE B2 C1 8C 8E 85 84 CF }
        $a225 = { B6 8A 8B 91 C2 92 90 8D 85 90 83 8F C2 81 83 8C 8C 8D 96 C2 80 87 C2 90 97 8C C2 8B 8C C2 A6 AD B1 C2 8F 8D 86 87 CC }
        $a226 = { B7 8B 8A 90 C3 93 91 8C 84 91 82 8E C3 80 82 8D 8D 8C 97 C3 81 86 C3 91 96 8D C3 8A 8D C3 A7 AC B0 C3 8E 8C 87 86 CD }
        $a227 = { B0 8C 8D 97 C4 94 96 8B 83 96 85 89 C4 87 85 8A 8A 8B 90 C4 86 81 C4 96 91 8A C4 8D 8A C4 A0 AB B7 C4 89 8B 80 81 CA }
        $a228 = { B1 8D 8C 96 C5 95 97 8A 82 97 84 88 C5 86 84 8B 8B 8A 91 C5 87 80 C5 97 90 8B C5 8C 8B C5 A1 AA B6 C5 88 8A 81 80 CB }
        $a229 = { B2 8E 8F 95 C6 96 94 89 81 94 87 8B C6 85 87 88 88 89 92 C6 84 83 C6 94 93 88 C6 8F 88 C6 A2 A9 B5 C6 8B 89 82 83 C8 }
        $a230 = { B3 8F 8E 94 C7 97 95 88 80 95 86 8A C7 84 86 89 89 88 93 C7 85 82 C7 95 92 89 C7 8E 89 C7 A3 A8 B4 C7 8A 88 83 82 C9 }
        $a231 = { BC 80 81 9B C8 98 9A 87 8F 9A 89 85 C8 8B 89 86 86 87 9C C8 8A 8D C8 9A 9D 86 C8 81 86 C8 AC A7 BB C8 85 87 8C 8D C6 }
        $a232 = { BD 81 80 9A C9 99 9B 86 8E 9B 88 84 C9 8A 88 87 87 86 9D C9 8B 8C C9 9B 9C 87 C9 80 87 C9 AD A6 BA C9 84 86 8D 8C C7 }
        $a233 = { BE 82 83 99 CA 9A 98 85 8D 98 8B 87 CA 89 8B 84 84 85 9E CA 88 8F CA 98 9F 84 CA 83 84 CA AE A5 B9 CA 87 85 8E 8F C4 }
        $a234 = { BF 83 82 98 CB 9B 99 84 8C 99 8A 86 CB 88 8A 85 85 84 9F CB 89 8E CB 99 9E 85 CB 82 85 CB AF A4 B8 CB 86 84 8F 8E C5 }
        $a235 = { B8 84 85 9F CC 9C 9E 83 8B 9E 8D 81 CC 8F 8D 82 82 83 98 CC 8E 89 CC 9E 99 82 CC 85 82 CC A8 A3 BF CC 81 83 88 89 C2 }
        $a236 = { B9 85 84 9E CD 9D 9F 82 8A 9F 8C 80 CD 8E 8C 83 83 82 99 CD 8F 88 CD 9F 98 83 CD 84 83 CD A9 A2 BE CD 80 82 89 88 C3 }
        $a237 = { BA 86 87 9D CE 9E 9C 81 89 9C 8F 83 CE 8D 8F 80 80 81 9A CE 8C 8B CE 9C 9B 80 CE 87 80 CE AA A1 BD CE 83 81 8A 8B C0 }
        $a238 = { BB 87 86 9C CF 9F 9D 80 88 9D 8E 82 CF 8C 8E 81 81 80 9B CF 8D 8A CF 9D 9A 81 CF 86 81 CF AB A0 BC CF 82 80 8B 8A C1 }
        $a239 = { A4 98 99 83 D0 80 82 9F 97 82 91 9D D0 93 91 9E 9E 9F 84 D0 92 95 D0 82 85 9E D0 99 9E D0 B4 BF A3 D0 9D 9F 94 95 DE }
        $a240 = { A5 99 98 82 D1 81 83 9E 96 83 90 9C D1 92 90 9F 9F 9E 85 D1 93 94 D1 83 84 9F D1 98 9F D1 B5 BE A2 D1 9C 9E 95 94 DF }
        $a241 = { A6 9A 9B 81 D2 82 80 9D 95 80 93 9F D2 91 93 9C 9C 9D 86 D2 90 97 D2 80 87 9C D2 9B 9C D2 B6 BD A1 D2 9F 9D 96 97 DC }
        $a242 = { A7 9B 9A 80 D3 83 81 9C 94 81 92 9E D3 90 92 9D 9D 9C 87 D3 91 96 D3 81 86 9D D3 9A 9D D3 B7 BC A0 D3 9E 9C 97 96 DD }
        $a243 = { A0 9C 9D 87 D4 84 86 9B 93 86 95 99 D4 97 95 9A 9A 9B 80 D4 96 91 D4 86 81 9A D4 9D 9A D4 B0 BB A7 D4 99 9B 90 91 DA }
        $a244 = { A1 9D 9C 86 D5 85 87 9A 92 87 94 98 D5 96 94 9B 9B 9A 81 D5 97 90 D5 87 80 9B D5 9C 9B D5 B1 BA A6 D5 98 9A 91 90 DB }
        $a245 = { A2 9E 9F 85 D6 86 84 99 91 84 97 9B D6 95 97 98 98 99 82 D6 94 93 D6 84 83 98 D6 9F 98 D6 B2 B9 A5 D6 9B 99 92 93 D8 }
        $a246 = { A3 9F 9E 84 D7 87 85 98 90 85 96 9A D7 94 96 99 99 98 83 D7 95 92 D7 85 82 99 D7 9E 99 D7 B3 B8 A4 D7 9A 98 93 92 D9 }
        $a247 = { AC 90 91 8B D8 88 8A 97 9F 8A 99 95 D8 9B 99 96 96 97 8C D8 9A 9D D8 8A 8D 96 D8 91 96 D8 BC B7 AB D8 95 97 9C 9D D6 }
        $a248 = { AD 91 90 8A D9 89 8B 96 9E 8B 98 94 D9 9A 98 97 97 96 8D D9 9B 9C D9 8B 8C 97 D9 90 97 D9 BD B6 AA D9 94 96 9D 9C D7 }
        $a249 = { AE 92 93 89 DA 8A 88 95 9D 88 9B 97 DA 99 9B 94 94 95 8E DA 98 9F DA 88 8F 94 DA 93 94 DA BE B5 A9 DA 97 95 9E 9F D4 }
        $a250 = { AF 93 92 88 DB 8B 89 94 9C 89 9A 96 DB 98 9A 95 95 94 8F DB 99 9E DB 89 8E 95 DB 92 95 DB BF B4 A8 DB 96 94 9F 9E D5 }
        $a251 = { A8 94 95 8F DC 8C 8E 93 9B 8E 9D 91 DC 9F 9D 92 92 93 88 DC 9E 99 DC 8E 89 92 DC 95 92 DC B8 B3 AF DC 91 93 98 99 D2 }
        $a252 = { A9 95 94 8E DD 8D 8F 92 9A 8F 9C 90 DD 9E 9C 93 93 92 89 DD 9F 98 DD 8F 88 93 DD 94 93 DD B9 B2 AE DD 90 92 99 98 D3 }
        $a253 = { AA 96 97 8D DE 8E 8C 91 99 8C 9F 93 DE 9D 9F 90 90 91 8A DE 9C 9B DE 8C 8B 90 DE 97 90 DE BA B1 AD DE 93 91 9A 9B D0 }

    condition:
        any of them
}

rule Base64d_PE
{
    meta:
        description = "Contains a base64-encoded executable"
        author = "Florian Roth"
        date = "2017-04-21"

    strings:
        $s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
        $s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii

    condition:
        any of them
}

rule Misc_Suspicious_Strings
{
    meta:
        description = "Miscellaneous malware strings"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "backdoor" nocase ascii wide
        $a1 = "virus" nocase ascii wide fullword
        $a2 = "hack" nocase ascii wide fullword
        $a3 = "exploit" nocase ascii wide
        $a4 = "cmd.exe" nocase ascii wide
        $a5 = "CWSandbox" nocase wide ascii // Found in some Zeus/Citadel samples
        $a6 = "System32\\drivers\\etc\\hosts" nocase wide ascii
    condition:
        any of them
}

rule BITS_CLSID
{
    meta:
        description = "References the BITS service."
        author = "Ivan Kwiatkowski (@JusticeRage)"
        // The BITS service seems to be used heavily by EquationGroup.
    strings:
        $uuid_background_copy_manager_1_5 =     { 1F 77 87 F0 4F D7 1A 4C BB 8A E1 6A CA 91 24 EA }
        $uuid_background_copy_manager_2_0 =     { 12 AD 18 6D E3 BD 93 43 B3 11 09 9C 34 6E 6D F9 }
        $uuid_background_copy_manager_2_5 =     { D6 98 CA 03 5D FF B8 49 AB C6 03 DD 84 12 70 20 }
        $uuid_background_copy_manager_3_0 =     { A7 DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_manager_4_0 =     { 6B F5 6D BB CE CA DC 11 99 92 00 19 B9 3A 3A 84 }
        $uuid_background_copy_manager_5_0 =     { 4C A3 CC 1E 8A E8 E3 44 8D 6A 89 21 BD E9 E4 52 }
        $uuid_background_copy_manager =         { 4B D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97 }
        $uuid_ibackground_copy_manager =        { 0D 4C E3 5C C9 0D 1F 4C 89 7C DA A1 B7 8C EE 7C }
        $uuid_background_copy_qmanager =        { 69 AD 4A EE 51 BE 43 9B A9 2C 86 AE 49 0E 8B 30 }
        $uuid_ibits_peer_cache_administration = { AD DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_callback =        { C7 99 EA 97 86 01 D4 4A 8D F9 C5 B4 E0 ED 6B 22 }
    condition:
        any of them
}

rule url 
{
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii
    condition:
        $url_regex
}

rule CRC32
{
  meta:
    description = "Uses constants related to CRC32"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $crc32_table = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 1E E9 D5 E0 88 D9 D2 97 2B 4C B6 09 BD 7C B1 7E 07 2D B8 E7 91 1D BF 90 64 10 B7 1D F2 20 B0 6A 48 71 B9 F3 DE 41 BE 84 7D D4 DA 1A EB E4 DD 6D 51 B5 D4 F4 C7 85 D3 83 56 98 6C 13 C0 A8 6B 64 7A F9 62 FD EC C9 65 8A 4F 5C 01 14 D9 6C 06 63 63 3D 0F FA F5 0D 08 8D C8 20 6E 3B 5E 10 69 4C E4 41 60 D5 72 71 67 A2 D1 E4 03 3C 47 D4 04 4B FD 85 0D D2 6B B5 0A A5 FA A8 B5 35 6C 98 B2 42 D6 C9 BB DB 40 F9 BC AC E3 6C D8 32 75 5C DF 45 CF 0D D6 DC 59 3D D1 AB AC 30 D9 26 3A 00 DE 51 80 51 D7 C8 16 61 D0 BF B5 F4 B4 21 23 C4 B3 56 99 95 BA CF 0F A5 BD B8 9E B8 02 28 08 88 05 5F B2 D9 0C C6 24 E9 0B B1 87 7C 6F 2F 11 4C 68 58 AB 1D 61 C1 3D 2D 66 B6 90 41 DC 76 06 71 DB 01 BC 20 D2 98 2A 10 D5 EF 89 85 B1 71 1F B5 B6 06 A5 E4 BF 9F 33 D4 B8 E8 A2 C9 07 78 34 F9 00 0F 8E A8 09 96 18 98 0E E1 BB 0D 6A 7F 2D 3D 6D 08 97 6C 64 91 01 5C 63 E6 F4 51 6B 6B 62 61 6C 1C D8 30 65 85 4E 00 62 F2 ED 95 06 6C 7B A5 01 1B C1 F4 08 82 57 C4 0F F5 C6 D9 B0 65 50 E9 B7 12 EA B8 BE 8B 7C 88 B9 FC DF 1D DD 62 49 2D DA 15 F3 7C D3 8C 65 4C D4 FB 58 61 B2 4D CE 51 B5 3A 74 00 BC A3 E2 30 BB D4 41 A5 DF 4A D7 95 D8 3D 6D C4 D1 A4 FB F4 D6 D3 6A E9 69 43 FC D9 6E 34 46 88 67 AD D0 B8 60 DA 73 2D 04 44 E5 1D 03 33 5F 4C 0A AA C9 7C 0D DD 3C 71 05 50 AA 41 02 27 10 10 0B BE 86 20 0C C9 25 B5 68 57 B3 85 6F 20 09 D4 66 B9 9F E4 61 CE 0E F9 DE 5E 98 C9 D9 29 22 98 D0 B0 B4 A8 D7 C7 17 3D B3 59 81 0D B4 2E 3B 5C BD B7 AD 6C BA C0 20 83 B8 ED B6 B3 BF 9A 0C E2 B6 03 9A D2 B1 74 39 47 D5 EA AF 77 D2 9D 15 26 DB 04 83 16 DC 73 12 0B 63 E3 84 3B 64 94 3E 6A 6D 0D A8 5A 6A 7A 0B CF 0E E4 9D FF 09 93 27 AE 00 0A B1 9E 07 7D 44 93 0F F0 D2 A3 08 87 68 F2 01 1E FE C2 06 69 5D 57 62 F7 CB 67 65 80 71 36 6C 19 E7 06 6B 6E 76 1B D4 FE E0 2B D3 89 5A 7A DA 10 CC 4A DD 67 6F DF B9 F9 F9 EF BE 8E 43 BE B7 17 D5 8E B0 60 E8 A3 D6 D6 7E 93 D1 A1 C4 C2 D8 38 52 F2 DF 4F F1 67 BB D1 67 57 BC A6 DD 06 B5 3F 4B 36 B2 48 DA 2B 0D D8 4C 1B 0A AF F6 4A 03 36 60 7A 04 41 C3 EF 60 DF 55 DF 67 A8 EF 8E 6E 31 79 BE 69 46 8C B3 61 CB 1A 83 66 BC A0 D2 6F 25 36 E2 68 52 95 77 0C CC 03 47 0B BB B9 16 02 22 2F 26 05 55 BE 3B BA C5 28 0B BD B2 92 5A B4 2B 04 6A B3 5C A7 FF D7 C2 31 CF D0 B5 8B 9E D9 2C 1D AE DE 5B B0 C2 64 9B 26 F2 63 EC 9C A3 6A 75 0A 93 6D 02 A9 06 09 9C 3F 36 0E EB 85 67 07 72 13 57 00 05 82 4A BF 95 14 7A B8 E2 AE 2B B1 7B 38 1B B6 0C 9B 8E D2 92 0D BE D5 E5 B7 EF DC 7C 21 DF DB 0B D4 D2 D3 86 42 E2 D4 F1 F8 B3 DD 68 6E 83 DA 1F CD 16 BE 81 5B 26 B9 F6 E1 77 B0 6F 77 47 B7 18 E6 5A 08 88 70 6A 0F FF CA 3B 06 66 5C 0B 01 11 FF 9E 65 8F 69 AE 62 F8 D3 FF 6B 61 45 CF 6C 16 78 E2 0A A0 EE D2 0D D7 54 83 04 4E C2 B3 03 39 61 26 67 A7 F7 16 60 D0 4D 47 69 49 DB 77 6E 3E 4A 6A D1 AE DC 5A D6 D9 66 0B DF 40 F0 3B D8 37 53 AE BC A9 C5 9E BB DE 7F CF B2 47 E9 FF B5 30 1C F2 BD BD 8A C2 BA CA 30 93 B3 53 A6 A3 B4 24 05 36 D0 BA 93 06 D7 CD 29 57 DE 54 BF 67 D9 23 2E 7A 66 B3 B8 4A 61 C4 02 1B 68 5D 94 2B 6F 2A 37 BE 0B B4 A1 8E 0C C3 1B DF 05 5A 8D EF 02 2D }
  condition:
    any of them
}

rule MD5
{
  meta:
    description = "Uses constants related to MD5"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $pkcs = { 30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 }
    $mac_t0 = { 97 ef 45 ac 29 0f 43 cd 45 7e 1b 55 1c 80 11 34 }
    $mac_t1 = { b1 77 ce 96 2e 72 8e 7c 5f 5a ab 0a 36 43 be 18 }
    $mac_t2 = { 9d 21 b4 21 bc 87 b9 4d a2 9d 27 bd c7 5b d7 c3 }

    $md5_c0 = { 78 A4 6A D7 }
    $md5_c1 = { 56 B7 C7 E8 }
    $md5_c2 = { DB 70 20 24 }
    $md5_c3 = { EE CE BD C1 }
    $md5_c4 = { AF 0F 7C F5 }
    $md5_c5 = { 2A C6 87 47 }
    $md5_c6 = { 13 46 30 A8 }
    $md5_c7 = { 01 95 46 FD }
    $md5_c8 = { D8 98 80 69 }
    $md5_c9 = { AF F7 44 8B }
    $md5_c10 = { B1 5B FF FF }
    $md5_c11 = { BE D7 5C 89 }
    $md5_c12 = { 22 11 90 6B }
    $md5_c13 = { 93 71 98 FD }
    $md5_c14 = { 8E 43 79 A6 }
    $md5_c15 = { 21 08 B4 49 }
    $md5_c16 = { 62 25 1E F6 }
    $md5_c17 = { 40 B3 40 C0 }
    $md5_c18 = { 51 5A 5E 26 }
    $md5_c19 = { AA C7 B6 E9 }
    $md5_c20 = { 5D 10 2F D6 }
    $md5_c21 = { 53 14 44 02 }
    $md5_c22 = { 81 E6 A1 D8 }
    $md5_c23 = { C8 FB D3 E7 }
    $md5_c24 = { E6 CD E1 21 }
    $md5_c25 = { D6 07 37 C3 }
    $md5_c26 = { 87 0D D5 F4 }
    $md5_c27 = { ED 14 5A 45 }
    $md5_c28 = { 05 E9 E3 A9 }
    $md5_c29 = { F8 A3 EF FC }
    $md5_c30 = { D9 02 6F 67 }
    $md5_c31 = { 8A 4C 2A 8D }
    $md5_c32 = { 42 39 FA FF }
    $md5_c33 = { 81 F6 71 87 }
    $md5_c34 = { 22 61 9D 6D }
    $md5_c35 = { 0C 38 E5 FD }
    $md5_c36 = { 44 EA BE A4 }
    $md5_c37 = { A9 CF DE 4B }
    $md5_c38 = { 60 4B BB F6 }
    $md5_c39 = { 70 BC BF BE }
    $md5_c40 = { C6 7E 9B 28 }
    $md5_c41 = { FA 27 A1 EA }
    $md5_c42 = { 85 30 EF D4 }
    $md5_c43 = { 05 1D 88 04 }
    $md5_c44 = { 39 D0 D4 D9 }
    $md5_c45 = { E5 99 DB E6 }
    $md5_c46 = { F8 7C A2 1F }
    $md5_c47 = { 65 56 AC C4 }
    $md5_c48 = { 44 22 29 F4 }
    $md5_c49 = { 97 FF 2A 43 }
    $md5_c50 = { A7 23 94 AB }
    $md5_c51 = { 39 A0 93 FC }
    $md5_c52 = { C3 59 5B 65 }
    $md5_c53 = { 92 CC 0C 8F }
    $md5_c54 = { 7D F4 EF FF }
    $md5_c55 = { D1 5D 84 85 }
    $md5_c56 = { 4F 7E A8 6F }
    $md5_c57 = { E0 E6 2C FE }
    $md5_c58 = { 14 43 01 A3 }
    $md5_c59 = { A1 11 08 4E }
    $md5_c60 = { 82 7E 53 F7 }
    $md5_c61 = { 35 F2 3A BD }
    $md5_c62 = { BB D2 D7 2A }
    $md5_c63 = { 91 D3 86 EB }

  condition:
    $pkcs or any of ($mac_*) or 20 of ($md5_c*)
}

rule SHA1
{
  meta:
    description = "Uses constants related to SHA1"
    author = "Ivan Kwiatkowski (@JusticeRage)"

  strings:
    $sha1_pkcs = { 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }

    $sha1_f1 = { 99 79 82 5A }
    $sha1_f2 = { a1 eb d9 6e }
    $sha1_f3 = { dc bc 1b 8f }
    $sha1_f4 = { d6 c1 62 ca }

  condition:
    $sha1_pkcs or all of ($sha1_f*)
}

rule SHA256
{
  meta:
    description = "Uses constants related to SHA256"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $sha256_pkcs = { 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 }

    $sha256_init0 = { 67 E6 09 6A }
    $sha256_init1 = { 85 AE 67 BB }
    $sha256_init2 = { 72 F3 6E 3C }
    $sha256_init3 = { 3A F5 4F A5 }
    $sha256_init4 = { 7F 52 0E 51 }
    $sha256_init5 = { 8C 68 05 9B }
    $sha256_init6 = { AB D9 83 1F }
    $sha256_init7 = { 19 CD E0 5B }

    $sha256_k0 = { 98 2F 8A 42 }
    $sha256_k1 = { 91 44 37 71 }
    $sha256_k2 = { CF FB C0 B5 }
    $sha256_k3 = { A5 DB B5 E9 }
    $sha256_k4 = { 5B C2 56 39 }
    $sha256_k5 = { F1 11 F1 59 }
    $sha256_k6 = { A4 82 3F 92 }
    $sha256_k7 = { D5 5E 1C AB }
    $sha256_k8 = { 98 AA 07 D8 }
    $sha256_k9 = { 01 5B 83 12 }
    $sha256_k10 = { BE 85 31 24 }
    $sha256_k11 = { C3 7D 0C 55 }
    $sha256_k12 = { 74 5D BE 72 }
    $sha256_k13 = { FE B1 DE 80 }
    $sha256_k14 = { A7 06 DC 9B }
    $sha256_k15 = { 74 F1 9B C1 }
    $sha256_k16 = { C1 69 9B E4 }
    $sha256_k17 = { 86 47 BE EF }
    $sha256_k18 = { C6 9D C1 0F }
    $sha256_k19 = { CC A1 0C 24 }
    $sha256_k20 = { 6F 2C E9 2D }
    $sha256_k21 = { AA 84 74 4A }
    $sha256_k22 = { DC A9 B0 5C }
    $sha256_k23 = { DA 88 F9 76 }
    $sha256_k24 = { 52 51 3E 98 }
    $sha256_k25 = { 6D C6 31 A8 }
    $sha256_k26 = { C8 27 03 B0 }
    $sha256_k27 = { C7 7F 59 BF }
    $sha256_k28 = { F3 0B E0 C6 }
    $sha256_k29 = { 47 91 A7 D5 }
    $sha256_k30 = { 51 63 CA 06 }
    $sha256_k31 = { 67 29 29 14 }
    $sha256_k32 = { 85 0A B7 27 }
    $sha256_k33 = { 38 21 1B 2E }
    $sha256_k34 = { FC 6D 2C 4D }
    $sha256_k35 = { 13 0D 38 53 }
    $sha256_k36 = { 54 73 0A 65 }
    $sha256_k37 = { BB 0A 6A 76 }
    $sha256_k38 = { 2E C9 C2 81 }
    $sha256_k39 = { 85 2C 72 92 }
    $sha256_k40 = { A1 E8 BF A2 }
    $sha256_k41 = { 4B 66 1A A8 }
    $sha256_k42 = { 70 8B 4B C2 }
    $sha256_k43 = { A3 51 6C C7 }
    $sha256_k44 = { 19 E8 92 D1 }
    $sha256_k45 = { 24 06 99 D6 }
    $sha256_k46 = { 85 35 0E F4 }
    $sha256_k47 = { 70 A0 6A 10 }
    $sha256_k48 = { 16 C1 A4 19 }
    $sha256_k49 = { 08 6C 37 1E }
    $sha256_k50 = { 4C 77 48 27 }
    $sha256_k51 = { B5 BC B0 34 }
    $sha256_k52 = { 4A AA D8 4E }
    $sha256_k53 = { 4F CA 9C 5B }
    $sha256_k54 = { F3 6F 2E 68 }
    $sha256_k55 = { EE 82 8F 74 }
    $sha256_k56 = { 6F 63 A5 78 }
    $sha256_k57 = { 14 78 C8 84 }
    $sha256_k58 = { 08 02 C7 8C }
    $sha256_k59 = { FA FF BE 90 }
    $sha256_k60 = { EB 6C 50 A4 }
    $sha256_k61 = { F7 A3 F9 BE }
    $sha256_k62 = { F2 78 71 C6 }

  condition:
    $sha256_pkcs or all of ($sha256_init*) or 20 of ($sha256_k*)
}

rule SHA512
{
  meta:
    description = "Uses constants related to SHA512"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $sha512_pkcs = { 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 }

    $sha512_k1 = { 22 AE 28 D7 98 2F 8A 42 }
    $sha512_k2 = { CD 65 EF 23 91 44 37 71 }
    $sha512_k3 = { 2F 3B 4D EC CF FB C0 B5 }
    $sha512_k4 = { BC DB 89 81 A5 DB B5 E9 }
    $sha512_k5 = { 38 B5 48 F3 5B C2 56 39 }
    $sha512_k6 = { 19 D0 05 B6 F1 11 F1 59 }
    $sha512_k7 = { 9B 4F 19 AF A4 82 3F 92 }
    $sha512_k8 = { 18 81 6D DA D5 5E 1C AB }
    $sha512_k9 = { 42 02 03 A3 98 AA 07 D8 }
    $sha512_k10 = { BE 6F 70 45 01 5B 83 12 }
    $sha512_k11 = { 8C B2 E4 4E BE 85 31 24 }
    $sha512_k12 = { E2 B4 FF D5 C3 7D 0C 55 }
    $sha512_k13 = { 6F 89 7B F2 74 5D BE 72 }
    $sha512_k14 = { B1 96 16 3B FE B1 DE 80 }
    $sha512_k15 = { 35 12 C7 25 A7 06 DC 9B }
    $sha512_k16 = { 94 26 69 CF 74 F1 9B C1 }
    $sha512_k17 = { D2 4A F1 9E C1 69 9B E4 }
    $sha512_k18 = { E3 25 4F 38 86 47 BE EF }
    $sha512_k19 = { B5 D5 8C 8B C6 9D C1 0F }
    $sha512_k20 = { 65 9C AC 77 CC A1 0C 24 }
    $sha512_k21 = { 75 02 2B 59 6F 2C E9 2D }
    $sha512_k22 = { 83 E4 A6 6E AA 84 74 4A }
    $sha512_k23 = { D4 FB 41 BD DC A9 B0 5C }
    $sha512_k24 = { B5 53 11 83 DA 88 F9 76 }
    $sha512_k25 = { AB DF 66 EE 52 51 3E 98 }
    $sha512_k26 = { 10 32 B4 2D 6D C6 31 A8 }
    $sha512_k27 = { 3F 21 FB 98 C8 27 03 B0 }
    $sha512_k28 = { E4 0E EF BE C7 7F 59 BF }
    $sha512_k29 = { C2 8F A8 3D F3 0B E0 C6 }
    $sha512_k30 = { 25 A7 0A 93 47 91 A7 D5 }
    $sha512_k31 = { 6F 82 03 E0 51 63 CA 06 }
    $sha512_k32 = { 70 6E 0E 0A 67 29 29 14 }
    $sha512_k33 = { FC 2F D2 46 85 0A B7 27 }
    $sha512_k34 = { 26 C9 26 5C 38 21 1B 2E }
    $sha512_k35 = { ED 2A C4 5A FC 6D 2C 4D }
    $sha512_k36 = { DF B3 95 9D 13 0D 38 53 }
    $sha512_k37 = { DE 63 AF 8B 54 73 0A 65 }
    $sha512_k38 = { A8 B2 77 3C BB 0A 6A 76 }
    $sha512_k39 = { E6 AE ED 47 2E C9 C2 81 }
    $sha512_k40 = { 3B 35 82 14 85 2C 72 92 }
    $sha512_k41 = { 64 03 F1 4C A1 E8 BF A2 }
    $sha512_k42 = { 01 30 42 BC 4B 66 1A A8 }
    $sha512_k43 = { 91 97 F8 D0 70 8B 4B C2 }
    $sha512_k44 = { 30 BE 54 06 A3 51 6C C7 }
    $sha512_k45 = { 18 52 EF D6 19 E8 92 D1 }
    $sha512_k46 = { 10 A9 65 55 24 06 99 D6 }
    $sha512_k47 = { 2A 20 71 57 85 35 0E F4 }
    $sha512_k48 = { B8 D1 BB 32 70 A0 6A 10 }
    $sha512_k49 = { 53 AB 41 51 08 6C 37 1E }
    $sha512_k50 = { 99 EB 8E DF 4C 77 48 27 }
    $sha512_k51 = { A8 48 9B E1 B5 BC B0 34 }
    $sha512_k52 = { 63 5A C9 C5 B3 0C 1C 39 }
    $sha512_k53 = { CB 8A 41 E3 4A AA D8 4E }
    $sha512_k54 = { 73 E3 63 77 4F CA 9C 5B }
    $sha512_k55 = { A3 B8 B2 D6 F3 6F 2E 68 }
    $sha512_k56 = { FC B2 EF 5D EE 82 8F 74 }
    $sha512_k57 = { 60 2F 17 43 6F 63 A5 78 }
    $sha512_k58 = { 72 AB F0 A1 14 78 C8 84 }
    $sha512_k59 = { EC 39 64 1A 08 02 C7 8C }
    $sha512_k60 = { 28 1E 63 23 FA FF BE 90 }
    $sha512_k61 = { E9 BD 82 DE EB 6C 50 A4 }
    $sha512_k62 = { 15 79 C6 B2 F7 A3 F9 BE }
    $sha512_k63 = { 2B 53 72 E3 F2 78 71 C6 }
    $sha512_k64 = { 9C 61 26 EA CE 3E 27 CA }
    $sha512_k65 = { 07 C2 C0 21 C7 B8 86 D1 }
    $sha512_k66 = { 1E EB E0 CD D6 7D DA EA }
    $sha512_k67 = { 78 D1 6E EE 7F 4F 7D F5 }
    $sha512_k68 = { BA 6F 17 72 AA 67 F0 06 }
    $sha512_k69 = { A6 98 C8 A2 C5 7D 63 0A }
    $sha512_k70 = { AE 0D F9 BE 04 98 3F 11 }
    $sha512_k71 = { 1B 47 1C 13 35 0B 71 1B }
    $sha512_k72 = { 84 7D 04 23 F5 77 DB 28 }
    $sha512_k73 = { 93 24 C7 40 7B AB CA 32 }
    $sha512_k74 = { BC BE C9 15 0A BE 9E 3C }
    $sha512_k75 = { 4C 0D 10 9C C4 67 1D 43 }
    $sha512_k76 = { B6 42 3E CB BE D4 C5 4C }
    $sha512_k77 = { 2A 7E 65 FC 9C 29 7F 59 }
    $sha512_k78 = { EC FA D6 3A AB 6F CB 5F }
    $sha512_k79 = { 17 58 47 4A 8C 19 44 6C }

  condition:
    $sha512_pkcs or 30 of ($sha512_k*)
}

rule AES
{
  meta:
    description = "Uses constants related to AES"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $aes_se = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15 04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75 09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84 53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8 51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2 CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73 60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79 E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08 BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A 70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF 8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16 }
    $aes_sd = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB 7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB 54 7B 94 32 A6 C2 23 3D EE 4C 95 0B 42 FA C3 4E 08 2E A1 66 28 D9 24 B2 76 5B A2 49 6D 8B D1 25 72 F8 F6 64 86 68 98 16 D4 A4 5C CC 5D 65 B6 92 6C 70 48 50 FD ED B9 DA 5E 15 46 57 A7 8D 9D 84 90 D8 AB 00 8C BC D3 0A F7 E4 58 05 B8 B3 45 06 D0 2C 1E 8F CA 3F 0F 02 C1 AF BD 03 01 13 8A 6B 3A 91 11 41 4F 67 DC EA 97 F2 CF CE F0 B4 E6 73 96 AC 74 22 E7 AD 35 85 E2 F9 37 E8 1C 75 DF 6E 47 F1 1A 71 1D 29 C5 89 6F B7 62 0E AA 18 BE 1B FC 56 3E 4B C6 D2 79 20 9A DB C0 FE 78 CD 5A F4 1F DD A8 33 88 07 C7 31 B1 12 10 59 27 80 EC 5F 60 51 7F A9 19 B5 4A 0D 2D E5 7A 9F 93 C9 9C EF A0 E0 3B 4D AE 2A F5 B0 C8 EB BB 3C 83 53 99 61 17 2B 04 7E BA 77 D6 26 E1 69 14 63 55 21 0C 7D }

    $aes_te0 = { a5 63 63 c6 84 7c 7c f8 99 77 77 ee 8d 7b 7b f6 0d f2 f2 ff bd 6b 6b d6 b1 6f 6f de 54 c5 c5 91 50 30 30 60 03 01 01 02 a9 67 67 ce 7d 2b 2b 56 19 fe fe e7 62 d7 d7 b5 e6 ab ab 4d 9a 76 76 ec 45 ca ca 8f 9d 82 82 1f 40 c9 c9 89 87 7d 7d fa 15 fa fa ef eb 59 59 b2 c9 47 47 8e 0b f0 f0 fb ec ad ad 41 67 d4 d4 b3 fd a2 a2 5f ea af af 45 bf 9c 9c 23 f7 a4 a4 53 96 72 72 e4 5b c0 c0 9b c2 b7 b7 75 1c fd fd e1 ae 93 93 3d 6a 26 26 4c 5a 36 36 6c 41 3f 3f 7e 02 f7 f7 f5 4f cc cc 83 5c 34 34 68 f4 a5 a5 51 34 e5 e5 d1 08 f1 f1 f9 93 71 71 e2 73 d8 d8 ab 53 31 31 62 3f 15 15 2a 0c 04 04 08 52 c7 c7 95 65 23 23 46 5e c3 c3 9d 28 18 18 30 a1 96 96 37 0f 05 05 0a b5 9a 9a 2f 09 07 07 0e 36 12 12 24 9b 80 80 1b 3d e2 e2 df 26 eb eb cd 69 27 27 4e cd b2 b2 7f 9f 75 75 ea 1b 09 09 12 9e 83 83 1d 74 2c 2c 58 2e 1a 1a 34 2d 1b 1b 36 b2 6e 6e dc ee 5a 5a b4 fb a0 a0 5b f6 52 52 a4 4d 3b 3b 76 61 d6 d6 b7 ce b3 b3 7d 7b 29 29 52 3e e3 e3 dd 71 2f 2f 5e 97 84 84 13 f5 53 53 a6 68 d1 d1 b9 00 00 00 00 2c ed ed c1 60 20 20 40 1f fc fc e3 c8 b1 b1 79 ed 5b 5b b6 be 6a 6a d4 46 cb cb 8d d9 be be 67 4b 39 39 72 de 4a 4a 94 d4 4c 4c 98 e8 58 58 b0 4a cf cf 85 6b d0 d0 bb 2a ef ef c5 e5 aa aa 4f 16 fb fb ed c5 43 43 86 d7 4d 4d 9a 55 33 33 66 94 85 85 11 cf 45 45 8a 10 f9 f9 e9 06 02 02 04 81 7f 7f fe f0 50 50 a0 44 3c 3c 78 ba 9f 9f 25 e3 a8 a8 4b f3 51 51 a2 fe a3 a3 5d c0 40 40 80 8a 8f 8f 05 ad 92 92 3f bc 9d 9d 21 48 38 38 70 04 f5 f5 f1 df bc bc 63 c1 b6 b6 77 75 da da af 63 21 21 42 30 10 10 20 1a ff ff e5 0e f3 f3 fd 6d d2 d2 bf 4c cd cd 81 14 0c 0c 18 35 13 13 26 2f ec ec c3 e1 5f 5f be a2 97 97 35 cc 44 44 88 39 17 17 2e 57 c4 c4 93 f2 a7 a7 55 82 7e 7e fc 47 3d 3d 7a ac 64 64 c8 e7 5d 5d ba 2b 19 19 32 95 73 73 e6 a0 60 60 c0 98 81 81 19 d1 4f 4f 9e 7f dc dc a3 66 22 22 44 7e 2a 2a 54 ab 90 90 3b 83 88 88 0b ca 46 46 8c 29 ee ee c7 d3 b8 b8 6b 3c 14 14 28 79 de de a7 e2 5e 5e bc 1d 0b 0b 16 76 db db ad 3b e0 e0 db 56 32 32 64 4e 3a 3a 74 1e 0a 0a 14 db 49 49 92 0a 06 06 0c 6c 24 24 48 e4 5c 5c b8 5d c2 c2 9f 6e d3 d3 bd ef ac ac 43 a6 62 62 c4 a8 91 91 39 a4 95 95 31 37 e4 e4 d3 8b 79 79 f2 32 e7 e7 d5 43 c8 c8 8b 59 37 37 6e b7 6d 6d da 8c 8d 8d 01 64 d5 d5 b1 d2 4e 4e 9c e0 a9 a9 49 b4 6c 6c d8 fa 56 56 ac 07 f4 f4 f3 25 ea ea cf af 65 65 ca 8e 7a 7a f4 e9 ae ae 47 18 08 08 10 d5 ba ba 6f 88 78 78 f0 6f 25 25 4a 72 2e 2e 5c 24 1c 1c 38 f1 a6 a6 57 c7 b4 b4 73 51 c6 c6 97 23 e8 e8 cb 7c dd dd a1 9c 74 74 e8 21 1f 1f 3e dd 4b 4b 96 dc bd bd 61 86 8b 8b 0d 85 8a 8a 0f 90 70 70 e0 42 3e 3e 7c c4 b5 b5 71 aa 66 66 cc d8 48 48 90 05 03 03 06 01 f6 f6 f7 12 0e 0e 1c a3 61 61 c2 5f 35 35 6a f9 57 57 ae d0 b9 b9 69 91 86 86 17 58 c1 c1 99 27 1d 1d 3a b9 9e 9e 27 38 e1 e1 d9 13 f8 f8 eb b3 98 98 2b 33 11 11 22 bb 69 69 d2 70 d9 d9 a9 89 8e 8e 07 a7 94 94 33 b6 9b 9b 2d 22 1e 1e 3c 92 87 87 15 20 e9 e9 c9 49 ce ce 87 ff 55 55 aa 78 28 28 50 7a df df a5 8f 8c 8c 03 f8 a1 a1 59 80 89 89 09 17 0d 0d 1a da bf bf 65 31 e6 e6 d7 c6 42 42 84 b8 68 68 d0 c3 41 41 82 b0 99 99 29 77 2d 2d 5a 11 0f 0f 1e cb b0 b0 7b fc 54 54 a8 d6 bb bb 6d 3a 16 16 2c }
    $aes_te1 = { 63 63 c6 a5 7c 7c f8 84 77 77 ee 99 7b 7b f6 8d f2 f2 ff 0d 6b 6b d6 bd 6f 6f de b1 c5 c5 91 54 30 30 60 50 01 01 02 03 67 67 ce a9 2b 2b 56 7d fe fe e7 19 d7 d7 b5 62 ab ab 4d e6 76 76 ec 9a ca ca 8f 45 82 82 1f 9d c9 c9 89 40 7d 7d fa 87 fa fa ef 15 59 59 b2 eb 47 47 8e c9 f0 f0 fb 0b ad ad 41 ec d4 d4 b3 67 a2 a2 5f fd af af 45 ea 9c 9c 23 bf a4 a4 53 f7 72 72 e4 96 c0 c0 9b 5b b7 b7 75 c2 fd fd e1 1c 93 93 3d ae 26 26 4c 6a 36 36 6c 5a 3f 3f 7e 41 f7 f7 f5 02 cc cc 83 4f 34 34 68 5c a5 a5 51 f4 e5 e5 d1 34 f1 f1 f9 08 71 71 e2 93 d8 d8 ab 73 31 31 62 53 15 15 2a 3f 04 04 08 0c c7 c7 95 52 23 23 46 65 c3 c3 9d 5e 18 18 30 28 96 96 37 a1 05 05 0a 0f 9a 9a 2f b5 07 07 0e 09 12 12 24 36 80 80 1b 9b e2 e2 df 3d eb eb cd 26 27 27 4e 69 b2 b2 7f cd 75 75 ea 9f 09 09 12 1b 83 83 1d 9e 2c 2c 58 74 1a 1a 34 2e 1b 1b 36 2d 6e 6e dc b2 5a 5a b4 ee a0 a0 5b fb 52 52 a4 f6 3b 3b 76 4d d6 d6 b7 61 b3 b3 7d ce 29 29 52 7b e3 e3 dd 3e 2f 2f 5e 71 84 84 13 97 53 53 a6 f5 d1 d1 b9 68 00 00 00 00 ed ed c1 2c 20 20 40 60 fc fc e3 1f b1 b1 79 c8 5b 5b b6 ed 6a 6a d4 be cb cb 8d 46 be be 67 d9 39 39 72 4b 4a 4a 94 de 4c 4c 98 d4 58 58 b0 e8 cf cf 85 4a d0 d0 bb 6b ef ef c5 2a aa aa 4f e5 fb fb ed 16 43 43 86 c5 4d 4d 9a d7 33 33 66 55 85 85 11 94 45 45 8a cf f9 f9 e9 10 02 02 04 06 7f 7f fe 81 50 50 a0 f0 3c 3c 78 44 9f 9f 25 ba a8 a8 4b e3 51 51 a2 f3 a3 a3 5d fe 40 40 80 c0 8f 8f 05 8a 92 92 3f ad 9d 9d 21 bc 38 38 70 48 f5 f5 f1 04 bc bc 63 df b6 b6 77 c1 da da af 75 21 21 42 63 10 10 20 30 ff ff e5 1a f3 f3 fd 0e d2 d2 bf 6d cd cd 81 4c 0c 0c 18 14 13 13 26 35 ec ec c3 2f 5f 5f be e1 97 97 35 a2 44 44 88 cc 17 17 2e 39 c4 c4 93 57 a7 a7 55 f2 7e 7e fc 82 3d 3d 7a 47 64 64 c8 ac 5d 5d ba e7 19 19 32 2b 73 73 e6 95 60 60 c0 a0 81 81 19 98 4f 4f 9e d1 dc dc a3 7f 22 22 44 66 2a 2a 54 7e 90 90 3b ab 88 88 0b 83 46 46 8c ca ee ee c7 29 b8 b8 6b d3 14 14 28 3c de de a7 79 5e 5e bc e2 0b 0b 16 1d db db ad 76 e0 e0 db 3b 32 32 64 56 3a 3a 74 4e 0a 0a 14 1e 49 49 92 db 06 06 0c 0a 24 24 48 6c 5c 5c b8 e4 c2 c2 9f 5d d3 d3 bd 6e ac ac 43 ef 62 62 c4 a6 91 91 39 a8 95 95 31 a4 e4 e4 d3 37 79 79 f2 8b e7 e7 d5 32 c8 c8 8b 43 37 37 6e 59 6d 6d da b7 8d 8d 01 8c d5 d5 b1 64 4e 4e 9c d2 a9 a9 49 e0 6c 6c d8 b4 56 56 ac fa f4 f4 f3 07 ea ea cf 25 65 65 ca af 7a 7a f4 8e ae ae 47 e9 08 08 10 18 ba ba 6f d5 78 78 f0 88 25 25 4a 6f 2e 2e 5c 72 1c 1c 38 24 a6 a6 57 f1 b4 b4 73 c7 c6 c6 97 51 e8 e8 cb 23 dd dd a1 7c 74 74 e8 9c 1f 1f 3e 21 4b 4b 96 dd bd bd 61 dc 8b 8b 0d 86 8a 8a 0f 85 70 70 e0 90 3e 3e 7c 42 b5 b5 71 c4 66 66 cc aa 48 48 90 d8 03 03 06 05 f6 f6 f7 01 0e 0e 1c 12 61 61 c2 a3 35 35 6a 5f 57 57 ae f9 b9 b9 69 d0 86 86 17 91 c1 c1 99 58 1d 1d 3a 27 9e 9e 27 b9 e1 e1 d9 38 f8 f8 eb 13 98 98 2b b3 11 11 22 33 69 69 d2 bb d9 d9 a9 70 8e 8e 07 89 94 94 33 a7 9b 9b 2d b6 1e 1e 3c 22 87 87 15 92 e9 e9 c9 20 ce ce 87 49 55 55 aa ff 28 28 50 78 df df a5 7a 8c 8c 03 8f a1 a1 59 f8 89 89 09 80 0d 0d 1a 17 bf bf 65 da e6 e6 d7 31 42 42 84 c6 68 68 d0 b8 41 41 82 c3 99 99 29 b0 2d 2d 5a 77 0f 0f 1e 11 b0 b0 7b cb 54 54 a8 fc bb bb 6d d6 16 16 2c 3a }
    $aes_te2 = { 63 c6 a5 63 7c f8 84 7c 77 ee 99 77 7b f6 8d 7b f2 ff 0d f2 6b d6 bd 6b 6f de b1 6f c5 91 54 c5 30 60 50 30 01 02 03 01 67 ce a9 67 2b 56 7d 2b fe e7 19 fe d7 b5 62 d7 ab 4d e6 ab 76 ec 9a 76 ca 8f 45 ca 82 1f 9d 82 c9 89 40 c9 7d fa 87 7d fa ef 15 fa 59 b2 eb 59 47 8e c9 47 f0 fb 0b f0 ad 41 ec ad d4 b3 67 d4 a2 5f fd a2 af 45 ea af 9c 23 bf 9c a4 53 f7 a4 72 e4 96 72 c0 9b 5b c0 b7 75 c2 b7 fd e1 1c fd 93 3d ae 93 26 4c 6a 26 36 6c 5a 36 3f 7e 41 3f f7 f5 02 f7 cc 83 4f cc 34 68 5c 34 a5 51 f4 a5 e5 d1 34 e5 f1 f9 08 f1 71 e2 93 71 d8 ab 73 d8 31 62 53 31 15 2a 3f 15 04 08 0c 04 c7 95 52 c7 23 46 65 23 c3 9d 5e c3 18 30 28 18 96 37 a1 96 05 0a 0f 05 9a 2f b5 9a 07 0e 09 07 12 24 36 12 80 1b 9b 80 e2 df 3d e2 eb cd 26 eb 27 4e 69 27 b2 7f cd b2 75 ea 9f 75 09 12 1b 09 83 1d 9e 83 2c 58 74 2c 1a 34 2e 1a 1b 36 2d 1b 6e dc b2 6e 5a b4 ee 5a a0 5b fb a0 52 a4 f6 52 3b 76 4d 3b d6 b7 61 d6 b3 7d ce b3 29 52 7b 29 e3 dd 3e e3 2f 5e 71 2f 84 13 97 84 53 a6 f5 53 d1 b9 68 d1 00 00 00 00 ed c1 2c ed 20 40 60 20 fc e3 1f fc b1 79 c8 b1 5b b6 ed 5b 6a d4 be 6a cb 8d 46 cb be 67 d9 be 39 72 4b 39 4a 94 de 4a 4c 98 d4 4c 58 b0 e8 58 cf 85 4a cf d0 bb 6b d0 ef c5 2a ef aa 4f e5 aa fb ed 16 fb 43 86 c5 43 4d 9a d7 4d 33 66 55 33 85 11 94 85 45 8a cf 45 f9 e9 10 f9 02 04 06 02 7f fe 81 7f 50 a0 f0 50 3c 78 44 3c 9f 25 ba 9f a8 4b e3 a8 51 a2 f3 51 a3 5d fe a3 40 80 c0 40 8f 05 8a 8f 92 3f ad 92 9d 21 bc 9d 38 70 48 38 f5 f1 04 f5 bc 63 df bc b6 77 c1 b6 da af 75 da 21 42 63 21 10 20 30 10 ff e5 1a ff f3 fd 0e f3 d2 bf 6d d2 cd 81 4c cd 0c 18 14 0c 13 26 35 13 ec c3 2f ec 5f be e1 5f 97 35 a2 97 44 88 cc 44 17 2e 39 17 c4 93 57 c4 a7 55 f2 a7 7e fc 82 7e 3d 7a 47 3d 64 c8 ac 64 5d ba e7 5d 19 32 2b 19 73 e6 95 73 60 c0 a0 60 81 19 98 81 4f 9e d1 4f dc a3 7f dc 22 44 66 22 2a 54 7e 2a 90 3b ab 90 88 0b 83 88 46 8c ca 46 ee c7 29 ee b8 6b d3 b8 14 28 3c 14 de a7 79 de 5e bc e2 5e 0b 16 1d 0b db ad 76 db e0 db 3b e0 32 64 56 32 3a 74 4e 3a 0a 14 1e 0a 49 92 db 49 06 0c 0a 06 24 48 6c 24 5c b8 e4 5c c2 9f 5d c2 d3 bd 6e d3 ac 43 ef ac 62 c4 a6 62 91 39 a8 91 95 31 a4 95 e4 d3 37 e4 79 f2 8b 79 e7 d5 32 e7 c8 8b 43 c8 37 6e 59 37 6d da b7 6d 8d 01 8c 8d d5 b1 64 d5 4e 9c d2 4e a9 49 e0 a9 6c d8 b4 6c 56 ac fa 56 f4 f3 07 f4 ea cf 25 ea 65 ca af 65 7a f4 8e 7a ae 47 e9 ae 08 10 18 08 ba 6f d5 ba 78 f0 88 78 25 4a 6f 25 2e 5c 72 2e 1c 38 24 1c a6 57 f1 a6 b4 73 c7 b4 c6 97 51 c6 e8 cb 23 e8 dd a1 7c dd 74 e8 9c 74 1f 3e 21 1f 4b 96 dd 4b bd 61 dc bd 8b 0d 86 8b 8a 0f 85 8a 70 e0 90 70 3e 7c 42 3e b5 71 c4 b5 66 cc aa 66 48 90 d8 48 03 06 05 03 f6 f7 01 f6 0e 1c 12 0e 61 c2 a3 61 35 6a 5f 35 57 ae f9 57 b9 69 d0 b9 86 17 91 86 c1 99 58 c1 1d 3a 27 1d 9e 27 b9 9e e1 d9 38 e1 f8 eb 13 f8 98 2b b3 98 11 22 33 11 69 d2 bb 69 d9 a9 70 d9 8e 07 89 8e 94 33 a7 94 9b 2d b6 9b 1e 3c 22 1e 87 15 92 87 e9 c9 20 e9 ce 87 49 ce 55 aa ff 55 28 50 78 28 df a5 7a df 8c 03 8f 8c a1 59 f8 a1 89 09 80 89 0d 1a 17 0d bf 65 da bf e6 d7 31 e6 42 84 c6 42 68 d0 b8 68 41 82 c3 41 99 29 b0 99 2d 5a 77 2d 0f 1e 11 0f b0 7b cb b0 54 a8 fc 54 bb 6d d6 bb 16 2c 3a 16 }
    $aes_te3 = { c6 a5 63 63 f8 84 7c 7c ee 99 77 77 f6 8d 7b 7b ff 0d f2 f2 d6 bd 6b 6b de b1 6f 6f 91 54 c5 c5 60 50 30 30 02 03 01 01 ce a9 67 67 56 7d 2b 2b e7 19 fe fe b5 62 d7 d7 4d e6 ab ab ec 9a 76 76 8f 45 ca ca 1f 9d 82 82 89 40 c9 c9 fa 87 7d 7d ef 15 fa fa b2 eb 59 59 8e c9 47 47 fb 0b f0 f0 41 ec ad ad b3 67 d4 d4 5f fd a2 a2 45 ea af af 23 bf 9c 9c 53 f7 a4 a4 e4 96 72 72 9b 5b c0 c0 75 c2 b7 b7 e1 1c fd fd 3d ae 93 93 4c 6a 26 26 6c 5a 36 36 7e 41 3f 3f f5 02 f7 f7 83 4f cc cc 68 5c 34 34 51 f4 a5 a5 d1 34 e5 e5 f9 08 f1 f1 e2 93 71 71 ab 73 d8 d8 62 53 31 31 2a 3f 15 15 08 0c 04 04 95 52 c7 c7 46 65 23 23 9d 5e c3 c3 30 28 18 18 37 a1 96 96 0a 0f 05 05 2f b5 9a 9a 0e 09 07 07 24 36 12 12 1b 9b 80 80 df 3d e2 e2 cd 26 eb eb 4e 69 27 27 7f cd b2 b2 ea 9f 75 75 12 1b 09 09 1d 9e 83 83 58 74 2c 2c 34 2e 1a 1a 36 2d 1b 1b dc b2 6e 6e b4 ee 5a 5a 5b fb a0 a0 a4 f6 52 52 76 4d 3b 3b b7 61 d6 d6 7d ce b3 b3 52 7b 29 29 dd 3e e3 e3 5e 71 2f 2f 13 97 84 84 a6 f5 53 53 b9 68 d1 d1 00 00 00 00 c1 2c ed ed 40 60 20 20 e3 1f fc fc 79 c8 b1 b1 b6 ed 5b 5b d4 be 6a 6a 8d 46 cb cb 67 d9 be be 72 4b 39 39 94 de 4a 4a 98 d4 4c 4c b0 e8 58 58 85 4a cf cf bb 6b d0 d0 c5 2a ef ef 4f e5 aa aa ed 16 fb fb 86 c5 43 43 9a d7 4d 4d 66 55 33 33 11 94 85 85 8a cf 45 45 e9 10 f9 f9 04 06 02 02 fe 81 7f 7f a0 f0 50 50 78 44 3c 3c 25 ba 9f 9f 4b e3 a8 a8 a2 f3 51 51 5d fe a3 a3 80 c0 40 40 05 8a 8f 8f 3f ad 92 92 21 bc 9d 9d 70 48 38 38 f1 04 f5 f5 63 df bc bc 77 c1 b6 b6 af 75 da da 42 63 21 21 20 30 10 10 e5 1a ff ff fd 0e f3 f3 bf 6d d2 d2 81 4c cd cd 18 14 0c 0c 26 35 13 13 c3 2f ec ec be e1 5f 5f 35 a2 97 97 88 cc 44 44 2e 39 17 17 93 57 c4 c4 55 f2 a7 a7 fc 82 7e 7e 7a 47 3d 3d c8 ac 64 64 ba e7 5d 5d 32 2b 19 19 e6 95 73 73 c0 a0 60 60 19 98 81 81 9e d1 4f 4f a3 7f dc dc 44 66 22 22 54 7e 2a 2a 3b ab 90 90 0b 83 88 88 8c ca 46 46 c7 29 ee ee 6b d3 b8 b8 28 3c 14 14 a7 79 de de bc e2 5e 5e 16 1d 0b 0b ad 76 db db db 3b e0 e0 64 56 32 32 74 4e 3a 3a 14 1e 0a 0a 92 db 49 49 0c 0a 06 06 48 6c 24 24 b8 e4 5c 5c 9f 5d c2 c2 bd 6e d3 d3 43 ef ac ac c4 a6 62 62 39 a8 91 91 31 a4 95 95 d3 37 e4 e4 f2 8b 79 79 d5 32 e7 e7 8b 43 c8 c8 6e 59 37 37 da b7 6d 6d 01 8c 8d 8d b1 64 d5 d5 9c d2 4e 4e 49 e0 a9 a9 d8 b4 6c 6c ac fa 56 56 f3 07 f4 f4 cf 25 ea ea ca af 65 65 f4 8e 7a 7a 47 e9 ae ae 10 18 08 08 6f d5 ba ba f0 88 78 78 4a 6f 25 25 5c 72 2e 2e 38 24 1c 1c 57 f1 a6 a6 73 c7 b4 b4 97 51 c6 c6 cb 23 e8 e8 a1 7c dd dd e8 9c 74 74 3e 21 1f 1f 96 dd 4b 4b 61 dc bd bd 0d 86 8b 8b 0f 85 8a 8a e0 90 70 70 7c 42 3e 3e 71 c4 b5 b5 cc aa 66 66 90 d8 48 48 06 05 03 03 f7 01 f6 f6 1c 12 0e 0e c2 a3 61 61 6a 5f 35 35 ae f9 57 57 69 d0 b9 b9 17 91 86 86 99 58 c1 c1 3a 27 1d 1d 27 b9 9e 9e d9 38 e1 e1 eb 13 f8 f8 2b b3 98 98 22 33 11 11 d2 bb 69 69 a9 70 d9 d9 07 89 8e 8e 33 a7 94 94 2d b6 9b 9b 3c 22 1e 1e 15 92 87 87 c9 20 e9 e9 87 49 ce ce aa ff 55 55 50 78 28 28 a5 7a df df 03 8f 8c 8c 59 f8 a1 a1 09 80 89 89 1a 17 0d 0d 65 da bf bf d7 31 e6 e6 84 c6 42 42 d0 b8 68 68 82 c3 41 41 29 b0 99 99 5a 77 2d 2d 1e 11 0f 0f 7b cb b0 b0 a8 fc 54 54 6d d6 bb bb 2c 3a 16 16 }
    $aes_te4 = { 63 63 63 63 7c 7c 7c 7c 77 77 77 77 7b 7b 7b 7b f2 f2 f2 f2 6b 6b 6b 6b 6f 6f 6f 6f c5 c5 c5 c5 30 30 30 30 01 01 01 01 67 67 67 67 2b 2b 2b 2b fe fe fe fe d7 d7 d7 d7 ab ab ab ab 76 76 76 76 ca ca ca ca 82 82 82 82 c9 c9 c9 c9 7d 7d 7d 7d fa fa fa fa 59 59 59 59 47 47 47 47 f0 f0 f0 f0 ad ad ad ad d4 d4 d4 d4 a2 a2 a2 a2 af af af af 9c 9c 9c 9c a4 a4 a4 a4 72 72 72 72 c0 c0 c0 c0 b7 b7 b7 b7 fd fd fd fd 93 93 93 93 26 26 26 26 36 36 36 36 3f 3f 3f 3f f7 f7 f7 f7 cc cc cc cc 34 34 34 34 a5 a5 a5 a5 e5 e5 e5 e5 f1 f1 f1 f1 71 71 71 71 d8 d8 d8 d8 31 31 31 31 15 15 15 15 04 04 04 04 c7 c7 c7 c7 23 23 23 23 c3 c3 c3 c3 18 18 18 18 96 96 96 96 05 05 05 05 9a 9a 9a 9a 07 07 07 07 12 12 12 12 80 80 80 80 e2 e2 e2 e2 eb eb eb eb 27 27 27 27 b2 b2 b2 b2 75 75 75 75 09 09 09 09 83 83 83 83 2c 2c 2c 2c 1a 1a 1a 1a 1b 1b 1b 1b 6e 6e 6e 6e 5a 5a 5a 5a a0 a0 a0 a0 52 52 52 52 3b 3b 3b 3b d6 d6 d6 d6 b3 b3 b3 b3 29 29 29 29 e3 e3 e3 e3 2f 2f 2f 2f 84 84 84 84 53 53 53 53 d1 d1 d1 d1 00 00 00 00 ed ed ed ed 20 20 20 20 fc fc fc fc b1 b1 b1 b1 5b 5b 5b 5b 6a 6a 6a 6a cb cb cb cb be be be be 39 39 39 39 4a 4a 4a 4a 4c 4c 4c 4c 58 58 58 58 cf cf cf cf d0 d0 d0 d0 ef ef ef ef aa aa aa aa fb fb fb fb 43 43 43 43 4d 4d 4d 4d 33 33 33 33 85 85 85 85 45 45 45 45 f9 f9 f9 f9 02 02 02 02 7f 7f 7f 7f 50 50 50 50 3c 3c 3c 3c 9f 9f 9f 9f a8 a8 a8 a8 51 51 51 51 a3 a3 a3 a3 40 40 40 40 8f 8f 8f 8f 92 92 92 92 9d 9d 9d 9d 38 38 38 38 f5 f5 f5 f5 bc bc bc bc b6 b6 b6 b6 da da da da 21 21 21 21 10 10 10 10 ff ff ff ff f3 f3 f3 f3 d2 d2 d2 d2 cd cd cd cd 0c 0c 0c 0c 13 13 13 13 ec ec ec ec 5f 5f 5f 5f 97 97 97 97 44 44 44 44 17 17 17 17 c4 c4 c4 c4 a7 a7 a7 a7 7e 7e 7e 7e 3d 3d 3d 3d 64 64 64 64 5d 5d 5d 5d 19 19 19 19 73 73 73 73 60 60 60 60 81 81 81 81 4f 4f 4f 4f dc dc dc dc 22 22 22 22 2a 2a 2a 2a 90 90 90 90 88 88 88 88 46 46 46 46 ee ee ee ee b8 b8 b8 b8 14 14 14 14 de de de de 5e 5e 5e 5e 0b 0b 0b 0b db db db db e0 e0 e0 e0 32 32 32 32 3a 3a 3a 3a 0a 0a 0a 0a 49 49 49 49 06 06 06 06 24 24 24 24 5c 5c 5c 5c c2 c2 c2 c2 d3 d3 d3 d3 ac ac ac ac 62 62 62 62 91 91 91 91 95 95 95 95 e4 e4 e4 e4 79 79 79 79 e7 e7 e7 e7 c8 c8 c8 c8 37 37 37 37 6d 6d 6d 6d 8d 8d 8d 8d d5 d5 d5 d5 4e 4e 4e 4e a9 a9 a9 a9 6c 6c 6c 6c 56 56 56 56 f4 f4 f4 f4 ea ea ea ea 65 65 65 65 7a 7a 7a 7a ae ae ae ae 08 08 08 08 ba ba ba ba 78 78 78 78 25 25 25 25 2e 2e 2e 2e 1c 1c 1c 1c a6 a6 a6 a6 b4 b4 b4 b4 c6 c6 c6 c6 e8 e8 e8 e8 dd dd dd dd 74 74 74 74 1f 1f 1f 1f 4b 4b 4b 4b bd bd bd bd 8b 8b 8b 8b 8a 8a 8a 8a 70 70 70 70 3e 3e 3e 3e b5 b5 b5 b5 66 66 66 66 48 48 48 48 03 03 03 03 f6 f6 f6 f6 0e 0e 0e 0e 61 61 61 61 35 35 35 35 57 57 57 57 b9 b9 b9 b9 86 86 86 86 c1 c1 c1 c1 1d 1d 1d 1d 9e 9e 9e 9e e1 e1 e1 e1 f8 f8 f8 f8 98 98 98 98 11 11 11 11 69 69 69 69 d9 d9 d9 d9 8e 8e 8e 8e 94 94 94 94 9b 9b 9b 9b 1e 1e 1e 1e 87 87 87 87 e9 e9 e9 e9 ce ce ce ce 55 55 55 55 28 28 28 28 df df df df 8c 8c 8c 8c a1 a1 a1 a1 89 89 89 89 0d 0d 0d 0d bf bf bf bf e6 e6 e6 e6 42 42 42 42 68 68 68 68 41 41 41 41 99 99 99 99 2d 2d 2d 2d 0f 0f 0f 0f b0 b0 b0 b0 54 54 54 54 bb bb bb bb 16 16 16 16 }

    $aes_td0 = { 50 a7 f4 51 53 65 41 7e c3 a4 17 1a 96 5e 27 3a cb 6b ab 3b f1 45 9d 1f ab 58 fa ac 93 03 e3 4b 55 fa 30 20 f6 6d 76 ad 91 76 cc 88 25 4c 02 f5 fc d7 e5 4f d7 cb 2a c5 80 44 35 26 8f a3 62 b5 49 5a b1 de 67 1b ba 25 98 0e ea 45 e1 c0 fe 5d 02 75 2f c3 12 f0 4c 81 a3 97 46 8d c6 f9 d3 6b e7 5f 8f 03 95 9c 92 15 eb 7a 6d bf da 59 52 95 2d 83 be d4 d3 21 74 58 29 69 e0 49 44 c8 c9 8e 6a 89 c2 75 78 79 8e f4 6b 3e 58 99 dd 71 b9 27 b6 4f e1 be 17 ad 88 f0 66 ac 20 c9 b4 3a ce 7d 18 4a df 63 82 31 1a e5 60 33 51 97 45 7f 53 62 e0 77 64 b1 84 ae 6b bb 1c a0 81 fe 94 2b 08 f9 58 68 48 70 19 fd 45 8f 87 6c de 94 b7 f8 7b 52 23 d3 73 ab e2 02 4b 72 57 8f 1f e3 2a ab 55 66 07 28 eb b2 03 c2 b5 2f 9a 7b c5 86 a5 08 37 d3 f2 87 28 30 b2 a5 bf 23 ba 6a 03 02 5c 82 16 ed 2b 1c cf 8a 92 b4 79 a7 f0 f2 07 f3 a1 e2 69 4e cd f4 da 65 d5 be 05 06 1f 62 34 d1 8a fe a6 c4 9d 53 2e 34 a0 55 f3 a2 32 e1 8a 05 75 eb f6 a4 39 ec 83 0b aa ef 60 40 06 9f 71 5e 51 10 6e bd f9 8a 21 3e 3d 06 dd 96 ae 05 3e dd 46 bd e6 4d b5 8d 54 91 05 5d c4 71 6f d4 06 04 ff 15 50 60 24 fb 98 19 97 e9 bd d6 cc 43 40 89 77 9e d9 67 bd 42 e8 b0 88 8b 89 07 38 5b 19 e7 db ee c8 79 47 0a 7c a1 e9 0f 42 7c c9 1e 84 f8 00 00 00 00 83 86 80 09 48 ed 2b 32 ac 70 11 1e 4e 72 5a 6c fb ff 0e fd 56 38 85 0f 1e d5 ae 3d 27 39 2d 36 64 d9 0f 0a 21 a6 5c 68 d1 54 5b 9b 3a 2e 36 24 b1 67 0a 0c 0f e7 57 93 d2 96 ee b4 9e 91 9b 1b 4f c5 c0 80 a2 20 dc 61 69 4b 77 5a 16 1a 12 1c 0a ba 93 e2 e5 2a a0 c0 43 e0 22 3c 1d 17 1b 12 0b 0d 09 0e ad c7 8b f2 b9 a8 b6 2d c8 a9 1e 14 85 19 f1 57 4c 07 75 af bb dd 99 ee fd 60 7f a3 9f 26 01 f7 bc f5 72 5c c5 3b 66 44 34 7e fb 5b 76 29 43 8b dc c6 23 cb 68 fc ed b6 63 f1 e4 b8 ca dc 31 d7 10 85 63 42 40 22 97 13 20 11 c6 84 7d 24 4a 85 f8 3d bb d2 11 32 f9 ae 6d a1 29 c7 4b 2f 9e 1d f3 30 b2 dc ec 52 86 0d d0 e3 c1 77 6c 16 b3 2b 99 b9 70 a9 fa 48 94 11 22 64 e9 47 c4 8c fc a8 1a 3f f0 a0 d8 2c 7d 56 ef 90 33 22 c7 4e 49 87 c1 d1 38 d9 fe a2 ca 8c 36 0b d4 98 cf 81 f5 a6 28 de 7a a5 26 8e b7 da a4 bf ad 3f e4 9d 3a 2c 0d 92 78 50 9b cc 5f 6a 62 46 7e 54 c2 13 8d f6 e8 b8 d8 90 5e f7 39 2e f5 af c3 82 be 80 5d 9f 7c 93 d0 69 a9 2d d5 6f b3 12 25 cf 3b 99 ac c8 a7 7d 18 10 6e 63 9c e8 7b bb 3b db 09 78 26 cd f4 18 59 6e 01 b7 9a ec a8 9a 4f 83 65 6e 95 e6 7e e6 ff aa 08 cf bc 21 e6 e8 15 ef d9 9b e7 ba ce 36 6f 4a d4 09 9f ea d6 7c b0 29 af b2 a4 31 31 23 3f 2a 30 94 a5 c6 c0 66 a2 35 37 bc 4e 74 a6 ca 82 fc b0 d0 90 e0 15 d8 a7 33 4a 98 04 f1 f7 da ec 41 0e 50 cd 7f 2f f6 91 17 8d d6 4d 76 4d b0 ef 43 54 4d aa cc df 04 96 e4 e3 b5 d1 9e 1b 88 6a 4c b8 1f 2c c1 7f 51 65 46 04 ea 5e 9d 5d 35 8c 01 73 74 87 fa 2e 41 0b fb 5a 1d 67 b3 52 d2 db 92 33 56 10 e9 13 47 d6 6d 8c 61 d7 9a 7a 0c a1 37 8e 14 f8 59 89 3c 13 eb ee 27 a9 ce 35 c9 61 b7 ed e5 1c e1 3c b1 47 7a 59 df d2 9c 3f 73 f2 55 79 ce 14 18 bf 37 c7 73 ea cd f7 53 5b aa fd 5f 14 6f 3d df 86 db 44 78 81 f3 af ca 3e c4 68 b9 2c 34 24 38 5f 40 a3 c2 72 c3 1d 16 0c 25 e2 bc 8b 49 3c 28 41 95 0d ff 71 01 a8 39 de b3 0c 08 9c e4 b4 d8 90 c1 56 64 61 84 cb 7b 70 b6 32 d5 74 5c 6c 48 42 57 b8 d0 }
    $aes_td1 = { a7 f4 51 50 65 41 7e 53 a4 17 1a c3 5e 27 3a 96 6b ab 3b cb 45 9d 1f f1 58 fa ac ab 03 e3 4b 93 fa 30 20 55 6d 76 ad f6 76 cc 88 91 4c 02 f5 25 d7 e5 4f fc cb 2a c5 d7 44 35 26 80 a3 62 b5 8f 5a b1 de 49 1b ba 25 67 0e ea 45 98 c0 fe 5d e1 75 2f c3 02 f0 4c 81 12 97 46 8d a3 f9 d3 6b c6 5f 8f 03 e7 9c 92 15 95 7a 6d bf eb 59 52 95 da 83 be d4 2d 21 74 58 d3 69 e0 49 29 c8 c9 8e 44 89 c2 75 6a 79 8e f4 78 3e 58 99 6b 71 b9 27 dd 4f e1 be b6 ad 88 f0 17 ac 20 c9 66 3a ce 7d b4 4a df 63 18 31 1a e5 82 33 51 97 60 7f 53 62 45 77 64 b1 e0 ae 6b bb 84 a0 81 fe 1c 2b 08 f9 94 68 48 70 58 fd 45 8f 19 6c de 94 87 f8 7b 52 b7 d3 73 ab 23 02 4b 72 e2 8f 1f e3 57 ab 55 66 2a 28 eb b2 07 c2 b5 2f 03 7b c5 86 9a 08 37 d3 a5 87 28 30 f2 a5 bf 23 b2 6a 03 02 ba 82 16 ed 5c 1c cf 8a 2b b4 79 a7 92 f2 07 f3 f0 e2 69 4e a1 f4 da 65 cd be 05 06 d5 62 34 d1 1f fe a6 c4 8a 53 2e 34 9d 55 f3 a2 a0 e1 8a 05 32 eb f6 a4 75 ec 83 0b 39 ef 60 40 aa 9f 71 5e 06 10 6e bd 51 8a 21 3e f9 06 dd 96 3d 05 3e dd ae bd e6 4d 46 8d 54 91 b5 5d c4 71 05 d4 06 04 6f 15 50 60 ff fb 98 19 24 e9 bd d6 97 43 40 89 cc 9e d9 67 77 42 e8 b0 bd 8b 89 07 88 5b 19 e7 38 ee c8 79 db 0a 7c a1 47 0f 42 7c e9 1e 84 f8 c9 00 00 00 00 86 80 09 83 ed 2b 32 48 70 11 1e ac 72 5a 6c 4e ff 0e fd fb 38 85 0f 56 d5 ae 3d 1e 39 2d 36 27 d9 0f 0a 64 a6 5c 68 21 54 5b 9b d1 2e 36 24 3a 67 0a 0c b1 e7 57 93 0f 96 ee b4 d2 91 9b 1b 9e c5 c0 80 4f 20 dc 61 a2 4b 77 5a 69 1a 12 1c 16 ba 93 e2 0a 2a a0 c0 e5 e0 22 3c 43 17 1b 12 1d 0d 09 0e 0b c7 8b f2 ad a8 b6 2d b9 a9 1e 14 c8 19 f1 57 85 07 75 af 4c dd 99 ee bb 60 7f a3 fd 26 01 f7 9f f5 72 5c bc 3b 66 44 c5 7e fb 5b 34 29 43 8b 76 c6 23 cb dc fc ed b6 68 f1 e4 b8 63 dc 31 d7 ca 85 63 42 10 22 97 13 40 11 c6 84 20 24 4a 85 7d 3d bb d2 f8 32 f9 ae 11 a1 29 c7 6d 2f 9e 1d 4b 30 b2 dc f3 52 86 0d ec e3 c1 77 d0 16 b3 2b 6c b9 70 a9 99 48 94 11 fa 64 e9 47 22 8c fc a8 c4 3f f0 a0 1a 2c 7d 56 d8 90 33 22 ef 4e 49 87 c7 d1 38 d9 c1 a2 ca 8c fe 0b d4 98 36 81 f5 a6 cf de 7a a5 28 8e b7 da 26 bf ad 3f a4 9d 3a 2c e4 92 78 50 0d cc 5f 6a 9b 46 7e 54 62 13 8d f6 c2 b8 d8 90 e8 f7 39 2e 5e af c3 82 f5 80 5d 9f be 93 d0 69 7c 2d d5 6f a9 12 25 cf b3 99 ac c8 3b 7d 18 10 a7 63 9c e8 6e bb 3b db 7b 78 26 cd 09 18 59 6e f4 b7 9a ec 01 9a 4f 83 a8 6e 95 e6 65 e6 ff aa 7e cf bc 21 08 e8 15 ef e6 9b e7 ba d9 36 6f 4a ce 09 9f ea d4 7c b0 29 d6 b2 a4 31 af 23 3f 2a 31 94 a5 c6 30 66 a2 35 c0 bc 4e 74 37 ca 82 fc a6 d0 90 e0 b0 d8 a7 33 15 98 04 f1 4a da ec 41 f7 50 cd 7f 0e f6 91 17 2f d6 4d 76 8d b0 ef 43 4d 4d aa cc 54 04 96 e4 df b5 d1 9e e3 88 6a 4c 1b 1f 2c c1 b8 51 65 46 7f ea 5e 9d 04 35 8c 01 5d 74 87 fa 73 41 0b fb 2e 1d 67 b3 5a d2 db 92 52 56 10 e9 33 47 d6 6d 13 61 d7 9a 8c 0c a1 37 7a 14 f8 59 8e 3c 13 eb 89 27 a9 ce ee c9 61 b7 35 e5 1c e1 ed b1 47 7a 3c df d2 9c 59 73 f2 55 3f ce 14 18 79 37 c7 73 bf cd f7 53 ea aa fd 5f 5b 6f 3d df 14 db 44 78 86 f3 af ca 81 c4 68 b9 3e 34 24 38 2c 40 a3 c2 5f c3 1d 16 72 25 e2 bc 0c 49 3c 28 8b 95 0d ff 41 01 a8 39 71 b3 0c 08 de e4 b4 d8 9c c1 56 64 90 84 cb 7b 61 b6 32 d5 70 5c 6c 48 74 57 b8 d0 42 }
    $aes_td2 = { f4 51 50 a7 41 7e 53 65 17 1a c3 a4 27 3a 96 5e ab 3b cb 6b 9d 1f f1 45 fa ac ab 58 e3 4b 93 03 30 20 55 fa 76 ad f6 6d cc 88 91 76 02 f5 25 4c e5 4f fc d7 2a c5 d7 cb 35 26 80 44 62 b5 8f a3 b1 de 49 5a ba 25 67 1b ea 45 98 0e fe 5d e1 c0 2f c3 02 75 4c 81 12 f0 46 8d a3 97 d3 6b c6 f9 8f 03 e7 5f 92 15 95 9c 6d bf eb 7a 52 95 da 59 be d4 2d 83 74 58 d3 21 e0 49 29 69 c9 8e 44 c8 c2 75 6a 89 8e f4 78 79 58 99 6b 3e b9 27 dd 71 e1 be b6 4f 88 f0 17 ad 20 c9 66 ac ce 7d b4 3a df 63 18 4a 1a e5 82 31 51 97 60 33 53 62 45 7f 64 b1 e0 77 6b bb 84 ae 81 fe 1c a0 08 f9 94 2b 48 70 58 68 45 8f 19 fd de 94 87 6c 7b 52 b7 f8 73 ab 23 d3 4b 72 e2 02 1f e3 57 8f 55 66 2a ab eb b2 07 28 b5 2f 03 c2 c5 86 9a 7b 37 d3 a5 08 28 30 f2 87 bf 23 b2 a5 03 02 ba 6a 16 ed 5c 82 cf 8a 2b 1c 79 a7 92 b4 07 f3 f0 f2 69 4e a1 e2 da 65 cd f4 05 06 d5 be 34 d1 1f 62 a6 c4 8a fe 2e 34 9d 53 f3 a2 a0 55 8a 05 32 e1 f6 a4 75 eb 83 0b 39 ec 60 40 aa ef 71 5e 06 9f 6e bd 51 10 21 3e f9 8a dd 96 3d 06 3e dd ae 05 e6 4d 46 bd 54 91 b5 8d c4 71 05 5d 06 04 6f d4 50 60 ff 15 98 19 24 fb bd d6 97 e9 40 89 cc 43 d9 67 77 9e e8 b0 bd 42 89 07 88 8b 19 e7 38 5b c8 79 db ee 7c a1 47 0a 42 7c e9 0f 84 f8 c9 1e 00 00 00 00 80 09 83 86 2b 32 48 ed 11 1e ac 70 5a 6c 4e 72 0e fd fb ff 85 0f 56 38 ae 3d 1e d5 2d 36 27 39 0f 0a 64 d9 5c 68 21 a6 5b 9b d1 54 36 24 3a 2e 0a 0c b1 67 57 93 0f e7 ee b4 d2 96 9b 1b 9e 91 c0 80 4f c5 dc 61 a2 20 77 5a 69 4b 12 1c 16 1a 93 e2 0a ba a0 c0 e5 2a 22 3c 43 e0 1b 12 1d 17 09 0e 0b 0d 8b f2 ad c7 b6 2d b9 a8 1e 14 c8 a9 f1 57 85 19 75 af 4c 07 99 ee bb dd 7f a3 fd 60 01 f7 9f 26 72 5c bc f5 66 44 c5 3b fb 5b 34 7e 43 8b 76 29 23 cb dc c6 ed b6 68 fc e4 b8 63 f1 31 d7 ca dc 63 42 10 85 97 13 40 22 c6 84 20 11 4a 85 7d 24 bb d2 f8 3d f9 ae 11 32 29 c7 6d a1 9e 1d 4b 2f b2 dc f3 30 86 0d ec 52 c1 77 d0 e3 b3 2b 6c 16 70 a9 99 b9 94 11 fa 48 e9 47 22 64 fc a8 c4 8c f0 a0 1a 3f 7d 56 d8 2c 33 22 ef 90 49 87 c7 4e 38 d9 c1 d1 ca 8c fe a2 d4 98 36 0b f5 a6 cf 81 7a a5 28 de b7 da 26 8e ad 3f a4 bf 3a 2c e4 9d 78 50 0d 92 5f 6a 9b cc 7e 54 62 46 8d f6 c2 13 d8 90 e8 b8 39 2e 5e f7 c3 82 f5 af 5d 9f be 80 d0 69 7c 93 d5 6f a9 2d 25 cf b3 12 ac c8 3b 99 18 10 a7 7d 9c e8 6e 63 3b db 7b bb 26 cd 09 78 59 6e f4 18 9a ec 01 b7 4f 83 a8 9a 95 e6 65 6e ff aa 7e e6 bc 21 08 cf 15 ef e6 e8 e7 ba d9 9b 6f 4a ce 36 9f ea d4 09 b0 29 d6 7c a4 31 af b2 3f 2a 31 23 a5 c6 30 94 a2 35 c0 66 4e 74 37 bc 82 fc a6 ca 90 e0 b0 d0 a7 33 15 d8 04 f1 4a 98 ec 41 f7 da cd 7f 0e 50 91 17 2f f6 4d 76 8d d6 ef 43 4d b0 aa cc 54 4d 96 e4 df 04 d1 9e e3 b5 6a 4c 1b 88 2c c1 b8 1f 65 46 7f 51 5e 9d 04 ea 8c 01 5d 35 87 fa 73 74 0b fb 2e 41 67 b3 5a 1d db 92 52 d2 10 e9 33 56 d6 6d 13 47 d7 9a 8c 61 a1 37 7a 0c f8 59 8e 14 13 eb 89 3c a9 ce ee 27 61 b7 35 c9 1c e1 ed e5 47 7a 3c b1 d2 9c 59 df f2 55 3f 73 14 18 79 ce c7 73 bf 37 f7 53 ea cd fd 5f 5b aa 3d df 14 6f 44 78 86 db af ca 81 f3 68 b9 3e c4 24 38 2c 34 a3 c2 5f 40 1d 16 72 c3 e2 bc 0c 25 3c 28 8b 49 0d ff 41 95 a8 39 71 01 0c 08 de b3 b4 d8 9c e4 56 64 90 c1 cb 7b 61 84 32 d5 70 b6 6c 48 74 5c b8 d0 42 57 }
    $aes_td3 = { 51 50 a7 f4 7e 53 65 41 1a c3 a4 17 3a 96 5e 27 3b cb 6b ab 1f f1 45 9d ac ab 58 fa 4b 93 03 e3 20 55 fa 30 ad f6 6d 76 88 91 76 cc f5 25 4c 02 4f fc d7 e5 c5 d7 cb 2a 26 80 44 35 b5 8f a3 62 de 49 5a b1 25 67 1b ba 45 98 0e ea 5d e1 c0 fe c3 02 75 2f 81 12 f0 4c 8d a3 97 46 6b c6 f9 d3 03 e7 5f 8f 15 95 9c 92 bf eb 7a 6d 95 da 59 52 d4 2d 83 be 58 d3 21 74 49 29 69 e0 8e 44 c8 c9 75 6a 89 c2 f4 78 79 8e 99 6b 3e 58 27 dd 71 b9 be b6 4f e1 f0 17 ad 88 c9 66 ac 20 7d b4 3a ce 63 18 4a df e5 82 31 1a 97 60 33 51 62 45 7f 53 b1 e0 77 64 bb 84 ae 6b fe 1c a0 81 f9 94 2b 08 70 58 68 48 8f 19 fd 45 94 87 6c de 52 b7 f8 7b ab 23 d3 73 72 e2 02 4b e3 57 8f 1f 66 2a ab 55 b2 07 28 eb 2f 03 c2 b5 86 9a 7b c5 d3 a5 08 37 30 f2 87 28 23 b2 a5 bf 02 ba 6a 03 ed 5c 82 16 8a 2b 1c cf a7 92 b4 79 f3 f0 f2 07 4e a1 e2 69 65 cd f4 da 06 d5 be 05 d1 1f 62 34 c4 8a fe a6 34 9d 53 2e a2 a0 55 f3 05 32 e1 8a a4 75 eb f6 0b 39 ec 83 40 aa ef 60 5e 06 9f 71 bd 51 10 6e 3e f9 8a 21 96 3d 06 dd dd ae 05 3e 4d 46 bd e6 91 b5 8d 54 71 05 5d c4 04 6f d4 06 60 ff 15 50 19 24 fb 98 d6 97 e9 bd 89 cc 43 40 67 77 9e d9 b0 bd 42 e8 07 88 8b 89 e7 38 5b 19 79 db ee c8 a1 47 0a 7c 7c e9 0f 42 f8 c9 1e 84 00 00 00 00 09 83 86 80 32 48 ed 2b 1e ac 70 11 6c 4e 72 5a fd fb ff 0e 0f 56 38 85 3d 1e d5 ae 36 27 39 2d 0a 64 d9 0f 68 21 a6 5c 9b d1 54 5b 24 3a 2e 36 0c b1 67 0a 93 0f e7 57 b4 d2 96 ee 1b 9e 91 9b 80 4f c5 c0 61 a2 20 dc 5a 69 4b 77 1c 16 1a 12 e2 0a ba 93 c0 e5 2a a0 3c 43 e0 22 12 1d 17 1b 0e 0b 0d 09 f2 ad c7 8b 2d b9 a8 b6 14 c8 a9 1e 57 85 19 f1 af 4c 07 75 ee bb dd 99 a3 fd 60 7f f7 9f 26 01 5c bc f5 72 44 c5 3b 66 5b 34 7e fb 8b 76 29 43 cb dc c6 23 b6 68 fc ed b8 63 f1 e4 d7 ca dc 31 42 10 85 63 13 40 22 97 84 20 11 c6 85 7d 24 4a d2 f8 3d bb ae 11 32 f9 c7 6d a1 29 1d 4b 2f 9e dc f3 30 b2 0d ec 52 86 77 d0 e3 c1 2b 6c 16 b3 a9 99 b9 70 11 fa 48 94 47 22 64 e9 a8 c4 8c fc a0 1a 3f f0 56 d8 2c 7d 22 ef 90 33 87 c7 4e 49 d9 c1 d1 38 8c fe a2 ca 98 36 0b d4 a6 cf 81 f5 a5 28 de 7a da 26 8e b7 3f a4 bf ad 2c e4 9d 3a 50 0d 92 78 6a 9b cc 5f 54 62 46 7e f6 c2 13 8d 90 e8 b8 d8 2e 5e f7 39 82 f5 af c3 9f be 80 5d 69 7c 93 d0 6f a9 2d d5 cf b3 12 25 c8 3b 99 ac 10 a7 7d 18 e8 6e 63 9c db 7b bb 3b cd 09 78 26 6e f4 18 59 ec 01 b7 9a 83 a8 9a 4f e6 65 6e 95 aa 7e e6 ff 21 08 cf bc ef e6 e8 15 ba d9 9b e7 4a ce 36 6f ea d4 09 9f 29 d6 7c b0 31 af b2 a4 2a 31 23 3f c6 30 94 a5 35 c0 66 a2 74 37 bc 4e fc a6 ca 82 e0 b0 d0 90 33 15 d8 a7 f1 4a 98 04 41 f7 da ec 7f 0e 50 cd 17 2f f6 91 76 8d d6 4d 43 4d b0 ef cc 54 4d aa e4 df 04 96 9e e3 b5 d1 4c 1b 88 6a c1 b8 1f 2c 46 7f 51 65 9d 04 ea 5e 01 5d 35 8c fa 73 74 87 fb 2e 41 0b b3 5a 1d 67 92 52 d2 db e9 33 56 10 6d 13 47 d6 9a 8c 61 d7 37 7a 0c a1 59 8e 14 f8 eb 89 3c 13 ce ee 27 a9 b7 35 c9 61 e1 ed e5 1c 7a 3c b1 47 9c 59 df d2 55 3f 73 f2 18 79 ce 14 73 bf 37 c7 53 ea cd f7 5f 5b aa fd df 14 6f 3d 78 86 db 44 ca 81 f3 af b9 3e c4 68 38 2c 34 24 c2 5f 40 a3 16 72 c3 1d bc 0c 25 e2 28 8b 49 3c ff 41 95 0d 39 71 01 a8 08 de b3 0c d8 9c e4 b4 64 90 c1 56 7b 61 84 cb d5 70 b6 32 48 74 5c 6c d0 42 57 b8 }
    $aes_td4 = { 52 52 52 52 09 09 09 09 6a 6a 6a 6a d5 d5 d5 d5 30 30 30 30 36 36 36 36 a5 a5 a5 a5 38 38 38 38 bf bf bf bf 40 40 40 40 a3 a3 a3 a3 9e 9e 9e 9e 81 81 81 81 f3 f3 f3 f3 d7 d7 d7 d7 fb fb fb fb 7c 7c 7c 7c e3 e3 e3 e3 39 39 39 39 82 82 82 82 9b 9b 9b 9b 2f 2f 2f 2f ff ff ff ff 87 87 87 87 34 34 34 34 8e 8e 8e 8e 43 43 43 43 44 44 44 44 c4 c4 c4 c4 de de de de e9 e9 e9 e9 cb cb cb cb 54 54 54 54 7b 7b 7b 7b 94 94 94 94 32 32 32 32 a6 a6 a6 a6 c2 c2 c2 c2 23 23 23 23 3d 3d 3d 3d ee ee ee ee 4c 4c 4c 4c 95 95 95 95 0b 0b 0b 0b 42 42 42 42 fa fa fa fa c3 c3 c3 c3 4e 4e 4e 4e 08 08 08 08 2e 2e 2e 2e a1 a1 a1 a1 66 66 66 66 28 28 28 28 d9 d9 d9 d9 24 24 24 24 b2 b2 b2 b2 76 76 76 76 5b 5b 5b 5b a2 a2 a2 a2 49 49 49 49 6d 6d 6d 6d 8b 8b 8b 8b d1 d1 d1 d1 25 25 25 25 72 72 72 72 f8 f8 f8 f8 f6 f6 f6 f6 64 64 64 64 86 86 86 86 68 68 68 68 98 98 98 98 16 16 16 16 d4 d4 d4 d4 a4 a4 a4 a4 5c 5c 5c 5c cc cc cc cc 5d 5d 5d 5d 65 65 65 65 b6 b6 b6 b6 92 92 92 92 6c 6c 6c 6c 70 70 70 70 48 48 48 48 50 50 50 50 fd fd fd fd ed ed ed ed b9 b9 b9 b9 da da da da 5e 5e 5e 5e 15 15 15 15 46 46 46 46 57 57 57 57 a7 a7 a7 a7 8d 8d 8d 8d 9d 9d 9d 9d 84 84 84 84 90 90 90 90 d8 d8 d8 d8 ab ab ab ab 00 00 00 00 8c 8c 8c 8c bc bc bc bc d3 d3 d3 d3 0a 0a 0a 0a f7 f7 f7 f7 e4 e4 e4 e4 58 58 58 58 05 05 05 05 b8 b8 b8 b8 b3 b3 b3 b3 45 45 45 45 06 06 06 06 d0 d0 d0 d0 2c 2c 2c 2c 1e 1e 1e 1e 8f 8f 8f 8f ca ca ca ca 3f 3f 3f 3f 0f 0f 0f 0f 02 02 02 02 c1 c1 c1 c1 af af af af bd bd bd bd 03 03 03 03 01 01 01 01 13 13 13 13 8a 8a 8a 8a 6b 6b 6b 6b 3a 3a 3a 3a 91 91 91 91 11 11 11 11 41 41 41 41 4f 4f 4f 4f 67 67 67 67 dc dc dc dc ea ea ea ea 97 97 97 97 f2 f2 f2 f2 cf cf cf cf ce ce ce ce f0 f0 f0 f0 b4 b4 b4 b4 e6 e6 e6 e6 73 73 73 73 96 96 96 96 ac ac ac ac 74 74 74 74 22 22 22 22 e7 e7 e7 e7 ad ad ad ad 35 35 35 35 85 85 85 85 e2 e2 e2 e2 f9 f9 f9 f9 37 37 37 37 e8 e8 e8 e8 1c 1c 1c 1c 75 75 75 75 df df df df 6e 6e 6e 6e 47 47 47 47 f1 f1 f1 f1 1a 1a 1a 1a 71 71 71 71 1d 1d 1d 1d 29 29 29 29 c5 c5 c5 c5 89 89 89 89 6f 6f 6f 6f b7 b7 b7 b7 62 62 62 62 0e 0e 0e 0e aa aa aa aa 18 18 18 18 be be be be 1b 1b 1b 1b fc fc fc fc 56 56 56 56 3e 3e 3e 3e 4b 4b 4b 4b c6 c6 c6 c6 d2 d2 d2 d2 79 79 79 79 20 20 20 20 9a 9a 9a 9a db db db db c0 c0 c0 c0 fe fe fe fe 78 78 78 78 cd cd cd cd 5a 5a 5a 5a f4 f4 f4 f4 1f 1f 1f 1f dd dd dd dd a8 a8 a8 a8 33 33 33 33 88 88 88 88 07 07 07 07 c7 c7 c7 c7 31 31 31 31 b1 b1 b1 b1 12 12 12 12 10 10 10 10 59 59 59 59 27 27 27 27 80 80 80 80 ec ec ec ec 5f 5f 5f 5f 60 60 60 60 51 51 51 51 7f 7f 7f 7f a9 a9 a9 a9 19 19 19 19 b5 b5 b5 b5 4a 4a 4a 4a 0d 0d 0d 0d 2d 2d 2d 2d e5 e5 e5 e5 7a 7a 7a 7a 9f 9f 9f 9f 93 93 93 93 c9 c9 c9 c9 9c 9c 9c 9c ef ef ef ef a0 a0 a0 a0 e0 e0 e0 e0 3b 3b 3b 3b 4d 4d 4d 4d ae ae ae ae 2a 2a 2a 2a f5 f5 f5 f5 b0 b0 b0 b0 c8 c8 c8 c8 eb eb eb eb bb bb bb bb 3c 3c 3c 3c 83 83 83 83 53 53 53 53 99 99 99 99 61 61 61 61 17 17 17 17 2b 2b 2b 2b 04 04 04 04 7e 7e 7e 7e ba ba ba ba 77 77 77 77 d6 d6 d6 d6 26 26 26 26 e1 e1 e1 e1 69 69 69 69 14 14 14 14 63 63 63 63 55 55 55 55 21 21 21 21 0c 0c 0c 0c 7d 7d 7d 7d }
  condition:
    any of them
}

rule Blowfish
{
  meta:
    description = "Uses constants related to Blowfish"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $bf_p_init = { 88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03 22 38 09 A4 D0 31 9F 29 98 FA 2E 08 89 6C 4E EC E6 21 28 45 77 13 D0 38 CF 66 54 BE 6C 0C E9 34 B7 29 AC C0 DD 50 7C C9 B5 D5 84 3F 17 09 47 B5 D9 D5 16 92 1B FB 79 89 }
    $bf_s_init = { A6 0B 31 D1 AC B5 DF 98 DB 72 FD 2F B7 DF 1A D0 ED AF E1 B8 96 7E 26 6A 45 90 7C BA 99 7F 2C F1 47 99 A1 24 F7 6C 91 B3 E2 F2 01 08 16 FC 8E 85 D8 20 69 63 69 4E 57 71 A3 FE 58 A4 7E 3D 93 F4 8F 74 95 0D 58 B6 8E 72 58 CD 8B 71 EE 4A 15 82 1D A4 54 7B B5 59 5A C2 39 D5 30 9C 13 60 F2 2A 23 B0 D1 C5 F0 85 60 28 18 79 41 CA EF 38 DB B8 B0 DC 79 8E 0E 18 3A 60 8B 0E 9E 6C 3E 8A 1E B0 C1 77 15 D7 27 4B 31 BD DA 2F AF 78 60 5C 60 55 F3 25 55 E6 94 AB 55 AA 62 98 48 57 40 14 E8 63 6A 39 CA 55 B6 10 AB 2A 34 5C CC B4 CE E8 41 11 AF 86 54 A1 93 E9 72 7C 11 14 EE B3 2A BC 6F 63 5D C5 A9 2B F6 31 18 74 16 3E 5C CE 1E 93 87 9B 33 BA D6 AF 5C CF 24 6C 81 53 32 7A 77 86 95 28 98 48 8F 3B AF B9 4B 6B 1B E8 BF C4 93 21 28 66 CC 09 D8 61 91 A9 21 FB 60 AC 7C 48 32 80 EC 5D 5D 5D 84 EF B1 75 85 E9 02 23 26 DC 88 1B 65 EB 81 3E 89 23 C5 AC 96 D3 F3 6F 6D 0F 39 42 F4 83 82 44 0B 2E 04 20 84 A4 4A F0 C8 69 5E 9B 1F 9E 42 68 C6 21 9A 6C E9 F6 61 9C 0C 67 F0 88 D3 AB D2 A0 51 6A 68 2F 54 D8 28 A7 0F 96 A3 33 51 AB 6C 0B EF 6E E4 3B 7A 13 50 F0 3B BA 98 2A FB 7E 1D 65 F1 A1 76 01 AF 39 3E 59 CA 66 88 0E 43 82 19 86 EE 8C B4 9F 6F 45 C3 A5 84 7D BE 5E 8B 3B D8 75 6F E0 73 20 C1 85 9F 44 1A 40 A6 6A C1 56 62 AA D3 4E 06 77 3F 36 72 DF FE 1B 3D 02 9B 42 24 D7 D0 37 48 12 0A D0 D3 EA 0F DB 9B C0 F1 49 C9 72 53 07 7B 1B 99 80 D8 79 D4 25 F7 DE E8 F6 1A 50 FE E3 3B 4C 79 B6 BD E0 6C 97 BA 06 C0 04 B6 4F A9 C1 C4 60 9F 40 C2 9E 5C 5E 63 24 6A 19 AF 6F FB 68 B5 53 6C 3E EB B2 39 13 6F EC 52 3B 1F 51 FC 6D 2C 95 30 9B 44 45 81 CC 09 BD 5E AF 04 D0 E3 BE FD 4A 33 DE 07 28 0F 66 B3 4B 2E 19 57 A8 CB C0 0F 74 C8 45 39 5F 0B D2 DB FB D3 B9 BD C0 79 55 0A 32 60 1A C6 00 A1 D6 79 72 2C 40 FE 25 9F 67 CC A3 1F FB F8 E9 A5 8E F8 22 32 DB DF 16 75 3C 15 6B 61 FD C8 1E 50 2F AB 52 05 AD FA B5 3D 32 60 87 23 FD 48 7B 31 53 82 DF 00 3E BB 57 5C 9E A0 8C 6F CA 2E 56 87 1A DB 69 17 DF F6 A8 42 D5 C3 FF 7E 28 C6 32 67 AC 73 55 4F 8C B0 27 5B 69 C8 58 CA BB 5D A3 FF E1 A0 11 F0 B8 98 3D FA 10 B8 83 21 FD 6C B5 FC 4A 5B D3 D1 2D 79 E4 53 9A 65 45 F8 B6 BC 49 8E D2 90 97 FB 4B DA F2 DD E1 33 7E CB A4 41 13 FB 62 E8 C6 E4 CE DA CA 20 EF 01 4C 77 36 FE 9E 7E D0 B4 1F F1 2B 4D DA DB 95 98 91 90 AE 71 8E AD EA A0 D5 93 6B D0 D1 8E D0 E0 25 C7 AF 2F 5B 3C 8E B7 94 75 8E FB E2 F6 8F 64 2B 12 F2 12 B8 88 88 1C F0 0D 90 A0 5E AD 4F 1C C3 8F 68 91 F1 CF D1 AD C1 A8 B3 18 22 2F 2F 77 17 0E BE FE 2D 75 EA A1 1F 02 8B 0F CC A0 E5 E8 74 6F B5 D6 F3 AC 18 99 E2 89 CE E0 4F A8 B4 B7 E0 13 FD 81 3B C4 7C D9 A8 AD D2 66 A2 5F 16 05 77 95 80 14 73 CC 93 77 14 1A 21 65 20 AD E6 86 FA B5 77 F5 42 54 C7 CF 35 9D FB 0C AF CD EB A0 89 3E 7B D3 1B 41 D6 49 7E 1E AE 2D 0E 25 00 5E B3 71 20 BB 00 68 22 AF E0 B8 57 9B 36 64 24 1E B9 09 F0 1D 91 63 55 AA A6 DF 59 89 43 C1 78 7F 53 5A D9 A2 5B 7D 20 C5 B9 E5 02 76 03 26 83 A9 CF 95 62 68 19 C8 11 41 4A 73 4E CA 2D 47 B3 4A A9 14 7B 52 00 51 1B 15 29 53 9A 3F 57 0F D6 E4 C6 9B BC 76 A4 60 2B 00 74 E6 81 B5 6F BA 08 1F E9 1B 57 6B EC 96 F2 15 D9 0D 2A 21 65 63 B6 B6 F9 B9 E7 2E 05 34 FF 64 56 85 C5 5D 2D B0 53 A1 8F 9F A9 99 47 BA 08 6A 07 85 6E E9 70 7A 4B 44 29 B3 B5 2E 09 75 DB 23 26 19 C4 B0 A6 6E AD 7D DF A7 49 B8 60 EE 9C 66 B2 ED 8F 71 8C AA EC FF 17 9A 69 6C 52 64 56 E1 9E B1 C2 A5 02 36 19 29 4C 09 75 40 13 59 A0 3E 3A 18 E4 9A 98 54 3F 65 9D 42 5B D6 E4 8F 6B D6 3F F7 99 07 9C D2 A1 F5 30 E8 EF E6 38 2D 4D C1 5D 25 F0 86 20 DD 4C 26 EB 70 84 C6 E9 82 63 5E CC 1E 02 3F 6B 68 09 C9 EF BA 3E 14 18 97 3C A1 70 6A 6B 84 35 7F 68 86 E2 A0 52 05 53 9C B7 37 07 50 AA 1C 84 07 3E 5C AE DE 7F EC 44 7D 8E B8 F2 16 57 37 DA 3A B0 0D 0C 50 F0 04 1F 1C F0 FF B3 00 02 1A F5 0C AE B2 74 B5 3C 58 7A 83 25 BD 21 09 DC F9 13 91 D1 F6 2F A9 7C 73 47 32 94 01 47 F5 22 81 E5 E5 3A 46 61 44 A9 0E 03 D0 0F 3E C7 C8 EC 41 1E 75 A4 99 CD 38 E2 2F 0E EA 3B A1 BB 80 32 31 B3 3E 18 38 8B 54 4E 08 B9 6D 4F 03 0D 42 6F BF 04 0A F6 90 12 B8 2C 79 7C 97 24 72 B0 79 56 AF 89 AF BC 1F 77 9A DE 10 08 93 D9 12 AE 8B B3 2E 3F CF DC 1F 72 12 55 24 71 6B 2E E6 DD 1A 50 87 CD 84 9F 18 47 58 7A 17 DA 08 74 BC 9A 9F BC 8C 7D 4B E9 3A EC 7A EC FA 1D 85 DB 66 43 09 63 D2 C3 64 C4 47 18 1C EF 08 D9 15 32 37 3B 43 DD 16 BA C2 24 43 4D A1 12 51 C4 65 2A 02 00 94 50 DD E4 3A 13 9E F8 DF 71 55 4E 31 10 D6 77 AC 81 9B 19 11 5F F1 56 35 04 6B C7 A3 D7 3B 18 11 3C 09 A5 24 59 ED E6 8F F2 FA FB F1 97 2C BF BA 9E 6E 3C 15 1E 70 45 E3 86 B1 6F E9 EA 0A 5E 0E 86 B3 2A 3E 5A 1C E7 1F 77 FA 06 3D 4E B9 DC 65 29 0F 1D E7 99 D6 89 3E 80 25 C8 66 52 78 C9 4C 2E 6A B3 10 9C BA 0E 15 C6 78 EA E2 94 53 3C FC A5 F4 2D 0A 1E A7 4E F7 F2 3D 2B 1D 36 0F 26 39 19 60 79 C2 19 08 A7 23 52 B6 12 13 F7 6E FE AD EB 66 1F C3 EA 95 45 BC E3 83 C8 7B A6 D1 37 7F B1 28 FF 8C 01 EF DD 32 C3 A5 5A 6C BE 85 21 58 65 02 98 AB 68 0F A5 CE EE 3B 95 2F DB AD 7D EF 2A 84 2F 6E 5B 28 B6 21 15 70 61 07 29 75 47 DD EC 10 15 9F 61 30 A8 CC 13 96 BD 61 EB 1E FE 34 03 CF 63 03 AA 90 5C 73 B5 39 A2 70 4C 0B 9E 9E D5 14 DE AA CB BC 86 CC EE A7 2C 62 60 AB 5C AB 9C 6E 84 F3 B2 AF 1E 8B 64 CA F0 BD 19 B9 69 23 A0 50 BB 5A 65 32 5A 68 40 B3 B4 2A 3C D5 E9 9E 31 F7 B8 21 C0 19 0B 54 9B 99 A0 5F 87 7E 99 F7 95 A8 7D 3D 62 9A 88 37 F8 77 2D E3 97 5F 93 ED 11 81 12 68 16 29 88 35 0E D6 1F E6 C7 A1 DF DE 96 99 BA 58 78 A5 84 F5 57 63 72 22 1B FF C3 83 9B 96 46 C2 1A EB 0A B3 CD 54 30 2E 53 E4 48 D9 8F 28 31 BC 6D EF F2 EB 58 EA FF C6 34 61 ED 28 FE 73 3C 7C EE D9 14 4A 5D E3 B7 64 E8 14 5D 10 42 E0 13 3E 20 B6 E2 EE 45 EA AB AA A3 15 4F 6C DB D0 4F CB FA 42 F4 42 C7 B5 BB 6A EF 1D 3B 4F 65 05 21 CD 41 9E 79 1E D8 C7 4D 85 86 6A 47 4B E4 50 62 81 3D F2 A1 62 CF 46 26 8D 5B A0 83 88 FC A3 B6 C7 C1 C3 24 15 7F 92 74 CB 69 0B 8A 84 47 85 B2 92 56 00 BF 5B 09 9D 48 19 AD 74 B1 62 14 00 0E 82 23 2A 8D 42 58 EA F5 55 0C 3E F4 AD 1D 61 70 3F 23 92 F0 72 33 41 7E 93 8D F1 EC 5F D6 DB 3B 22 6C 59 37 DE 7C 60 74 EE CB A7 F2 85 40 6E 32 77 CE 84 80 07 A6 9E 50 F8 19 55 D8 EF E8 35 97 D9 61 AA A7 69 A9 C2 06 0C C5 FC AB 04 5A DC CA 0B 80 2E 7A 44 9E 84 34 45 C3 05 67 D5 FD C9 9E 1E 0E D3 DB 73 DB CD 88 55 10 79 DA 5F 67 40 43 67 E3 65 34 C4 C5 D8 38 3E 71 9E F8 28 3D 20 FF 6D F1 E7 21 3E 15 4A 3D B0 8F 2B 9F E3 E6 F7 AD 83 DB 68 5A 3D E9 F7 40 81 94 1C 26 4C F6 34 29 69 94 F7 20 15 41 F7 D4 02 76 2E 6B F4 BC 68 00 A2 D4 71 24 08 D4 6A F4 20 33 B7 D4 B7 43 AF 61 00 50 2E F6 39 1E 46 45 24 97 74 4F 21 14 40 88 8B BF 1D FC 95 4D AF 91 B5 96 D3 DD F4 70 45 2F A0 66 EC 09 BC BF 85 97 BD 03 D0 6D AC 7F 04 85 CB 31 B3 27 EB 96 41 39 FD 55 E6 47 25 DA 9A 0A CA AB 25 78 50 28 F4 29 04 53 DA 86 2C 0A FB 6D B6 E9 62 14 DC 68 00 69 48 D7 A4 C0 0E 68 EE 8D A1 27 A2 FE 3F 4F 8C AD 87 E8 06 E0 8C B5 B6 D6 F4 7A 7C 1E CE AA EC 5F 37 D3 99 A3 78 CE 42 2A 6B 40 35 9E FE 20 B9 85 F3 D9 AB D7 39 EE 8B 4E 12 3B F7 FA C9 1D 56 18 6D 4B 31 66 A3 26 B2 97 E3 EA 74 FA 6E 3A 32 43 5B DD F7 E7 41 68 FB 20 78 CA 4E F5 0A FB 97 B3 FE D8 AC 56 40 45 27 95 48 BA 3A 3A 53 55 87 8D 83 20 B7 A9 6B FE 4B 95 96 D0 BC 67 A8 55 58 9A 15 A1 63 29 A9 CC 33 DB E1 99 56 4A 2A A6 F9 25 31 3F 1C 7E F4 5E 7C 31 29 90 02 E8 F8 FD 70 2F 27 04 5C 15 BB 80 E3 2C 28 05 48 15 C1 95 22 6D C6 E4 3F 13 C1 48 DC 86 0F C7 EE C9 F9 07 0F 1F 04 41 A4 79 47 40 17 6E 88 5D EB 51 5F 32 D1 C0 9B D5 8F C1 BC F2 64 35 11 41 34 78 7B 25 60 9C 2A 60 A3 E8 F8 DF 1B 6C 63 1F C2 B4 12 0E 9E 32 E1 02 D1 4F 66 AF 15 81 D1 CA E0 95 23 6B E1 92 3E 33 62 0B 24 3B 22 B9 BE EE 0E A2 B2 85 99 0D BA E6 8C 0C 72 DE 62 08 7D 64 F0 F5 CC E7 6F A3 49 54 FA 48 7D 87 27 FD 9D C3 1E 8D 3E F3 41 63 47 0A 74 FF 2E 99 AB 6E 6F 3A 37 FD F8 F4 60 DC 12 A8 F8 DD EB A1 4C E1 1B 99 0D 6B 6E DB 10 55 7B C6 37 2C 67 6D 3B D4 65 27 04 E8 D0 DC C7 0D 29 F1 A3 FF 00 CC 92 0F 39 B5 0B ED 0F 69 FB 9F 7B 66 9C 7D DB CE 0B CF 91 A0 A3 5E 15 D9 88 2F 13 BB 24 AD 5B 51 BF 79 94 7B EB D6 3B 76 B3 2E 39 37 79 59 11 CC 97 E2 26 80 2D 31 2E F4 A7 AD 42 68 3B 2B 6A C6 CC 4C 75 12 1C F1 2E 78 37 42 12 6A E7 51 92 B7 E6 BB A1 06 50 63 FB 4B 18 10 6B 1A FA ED CA 11 D8 BD 25 3D C9 C3 E1 E2 59 16 42 44 86 13 12 0A 6E EC 0C D9 2A EA AB D5 4E 67 AF 64 5F A8 86 DA 88 E9 BF BE FE C3 E4 64 57 80 BC 9D 86 C0 F7 F0 F8 7B 78 60 4D 60 03 60 46 83 FD D1 B0 1F 38 F6 04 AE 45 77 CC FC 36 D7 33 6B 42 83 71 AB 1E F0 87 41 80 B0 5F 5E 00 3C BE 57 A0 77 24 AE E8 BD 99 42 46 55 61 2E 58 BF 8F F4 58 4E A2 FD DD F2 38 EF 74 F4 C2 BD 89 87 C3 F9 66 53 74 8E B3 C8 55 F2 75 B4 B9 D9 FC 46 61 26 EB 7A 84 DF 1D 8B 79 0E 6A 84 E2 95 5F 91 8E 59 6E 46 70 57 B4 20 91 55 D5 8C 4C DE 02 C9 E1 AC 0B B9 D0 05 82 BB 48 62 A8 11 9E A9 74 75 B6 19 7F B7 09 DC A9 E0 A1 09 2D 66 33 46 32 C4 02 1F 5A E8 8C BE F0 09 25 A0 99 4A 10 FE 6E 1D 1D 3D B9 1A DF A4 A5 0B 0F F2 86 A1 69 F1 68 28 83 DA B7 DC FE 06 39 57 9B CE E2 A1 52 7F CD 4F 01 5E 11 50 FA 83 06 A7 C4 B5 02 A0 27 D0 E6 0D 27 8C F8 9A 41 86 3F 77 06 4C 60 C3 B5 06 A8 61 28 7A 17 F0 E0 86 F5 C0 AA 58 60 00 62 7D DC 30 D7 9E E6 11 63 EA 38 23 94 DD C2 53 34 16 C2 C2 56 EE CB BB DE B6 BC 90 A1 7D FC EB 76 1D 59 CE 09 E4 05 6F 88 01 7C 4B 3D 0A 72 39 24 7C 92 7C 5F 72 E3 86 B9 9D 4D 72 B4 5B C1 1A FC B8 9E D3 78 55 54 ED B5 A5 FC 08 D3 7C 3D D8 C4 0F AD 4D 5E EF 50 1E F8 E6 61 B1 D9 14 85 A2 3C 13 51 6C E7 C7 D5 6F C4 4E E1 56 CE BF 2A 36 37 C8 C6 DD 34 32 9A D7 12 82 63 92 8E FA 0E 67 E0 00 60 40 37 CE 39 3A CF F5 FA D3 37 77 C2 AB 1B 2D C5 5A 9E 67 B0 5C 42 37 A3 4F 40 27 82 D3 BE 9B BC 99 9D 8E 11 D5 15 73 0F BF 7E 1C 2D D6 7B C4 00 C7 6B 1B 8C B7 45 90 A1 21 BE B1 6E B2 B4 6E 36 6A 2F AB 48 57 79 6E 94 BC D2 76 A3 C6 C8 C2 49 65 EE F8 0F 53 7D DE 8D 46 1D 0A 73 D5 C6 4D D0 4C DB BB 39 29 50 46 BA A9 E8 26 95 AC 04 E3 5E BE F0 D5 FA A1 9A 51 2D 6A E2 8C EF 63 22 EE 86 9A B8 C2 89 C0 F6 2E 24 43 AA 03 1E A5 A4 D0 F2 9C BA 61 C0 83 4D 6A E9 9B 50 15 E5 8F D6 5B 64 BA F9 A2 26 28 E1 3A 3A A7 86 95 A9 4B E9 62 55 EF D3 EF 2F C7 DA F7 52 F7 69 6F 04 3F 59 0A FA 77 15 A9 E4 80 01 86 B0 87 AD E6 09 9B 93 E5 3E 3B 5A FD 90 E9 97 D7 34 9E D9 B7 F0 2C 51 8B 2B 02 3A AC D5 96 7D A6 7D 01 D6 3E CF D1 28 2D 7D 7C CF 25 9F 1F 9B B8 F2 AD 72 B4 D6 5A 4C F5 88 5A 71 AC 29 E0 E6 A5 19 E0 FD AC B0 47 9B FA 93 ED 8D C4 D3 E8 CC 57 3B 28 29 66 D5 F8 28 2E 13 79 91 01 5F 78 55 60 75 ED 44 0E 96 F7 8C 5E D3 E3 D4 6D 05 15 BA 6D F4 88 25 61 A1 03 BD F0 64 05 15 9E EB C3 A2 57 90 3C EC 1A 27 97 2A 07 3A A9 9B 6D 3F 1B F5 21 63 1E FB 66 9C F5 19 F3 DC 26 28 D9 33 75 F5 FD 55 B1 82 34 56 03 BB 3C BA 8A 11 77 51 28 F8 D9 0A C2 67 51 CC AB 5F 92 AD CC 51 17 E8 4D 8E DC 30 38 62 58 9D 37 91 F9 20 93 C2 90 7A EA CE 7B 3E FB 64 CE 21 51 32 BE 4F 77 7E E3 B6 A8 46 3D 29 C3 69 53 DE 48 80 E6 13 64 10 08 AE A2 24 B2 6D DD FD 2D 85 69 66 21 07 09 0A 46 9A B3 DD C0 45 64 CF DE 6C 58 AE C8 20 1C DD F7 BE 5B 40 8D 58 1B 7F 01 D2 CC BB E3 B4 6B 7E 6A A2 DD 45 FF 59 3A 44 0A 35 3E D5 CD B4 BC A8 CE EA 72 BB 84 64 FA AE 12 66 8D 47 6F 3C BF 63 E4 9B D2 9E 5D 2F 54 1B 77 C2 AE 70 63 4E F6 8D 0D 0E 74 57 13 5B E7 71 16 72 F8 5D 7D 53 AF 08 CB 40 40 CC E2 B4 4E 6A 46 D2 34 84 AF 15 01 28 04 B0 E1 1D 3A 98 95 B4 9F B8 06 48 A0 6E CE 82 3B 3F 6F 82 AB 20 35 4B 1D 1A 01 F8 27 72 27 B1 60 15 61 DC 3F 93 E7 2B 79 3A BB BD 25 45 34 E1 39 88 A0 7E C8 1C E0 F6 D1 C7 BC C3 11 01 CF C7 AA E8 A1 49 87 90 1A 9A BD 4F D4 CB DE DA D0 38 DA 0A D5 2A C3 39 03 67 36 91 C6 7C 31 F9 8D 4F 2B B1 E0 B7 59 9E F7 3A BB F5 43 FF 19 D5 F2 9C 45 D9 27 2C 22 97 BF 2A FC E6 15 71 FC 91 0F 25 15 94 9B 61 93 E5 FA EB 9C B6 CE 59 64 A8 C2 D1 A8 BA 12 5E 07 C1 B6 0C 6A 05 E3 65 50 D2 10 42 A4 03 CB 0E 6E EC E0 3B DB 98 16 BE A0 98 4C 64 E9 78 32 32 95 1F 9F DF 92 D3 E0 2B 34 A0 D3 1E F2 71 89 41 74 0A 1B 8C 34 A3 4B 20 71 BE C5 D8 32 76 C3 8D 9F 35 DF 2E 2F 99 9B 47 6F 0B E6 1D F1 E3 0F 54 DA 4C E5 91 D8 DA 1E CF 79 62 CE 6F 7E 3E CD 66 B1 18 16 05 1D 2C FD C5 D2 8F 84 99 22 FB F6 57 F3 23 F5 23 76 32 A6 31 35 A8 93 02 CD CC 56 62 81 F0 AC B5 EB 75 5A 97 36 16 6E CC 73 D2 88 92 62 96 DE D0 49 B9 81 1B 90 50 4C 14 56 C6 71 BD C7 C6 E6 0A 14 7A 32 06 D0 E1 45 9A 7B F2 C3 FD 53 AA C9 00 0F A8 62 E2 BF 25 BB F6 D2 BD 35 05 69 12 71 22 02 04 B2 7C CF CB B6 2B 9C 76 CD C0 3E 11 53 D3 E3 40 16 60 BD AB 38 F0 AD 47 25 9C 20 38 BA 76 CE 46 F7 C5 A1 AF 77 60 60 75 20 4E FE CB 85 D8 8D E8 8A B0 F9 AA 7A 7E AA F9 4C 5C C2 48 19 8C 8A FB 02 E4 6A C3 01 F9 E1 EB D6 69 F8 D4 90 A0 DE 5C A6 2D 25 09 3F 9F E6 08 C2 32 61 4E B7 5B E2 77 CE E3 DF 8F 57 E6 72 C3 3A }

  condition:
    any of them
}

rule DES
{
  meta:
    description = "Uses constants related to DES"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $des_spbox1 = { 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 04 04 00 00 00 04 00 01 00 04 00 01 00 04 01 00 00 04 01 00 00 00 01 01 00 00 01 01 04 04 00 01 04 00 01 00 04 00 00 01 04 00 00 01 04 00 01 00 00 00 00 00 04 04 00 00 04 04 01 00 00 00 00 01 00 00 01 00 04 04 01 01 04 00 00 00 00 00 01 01 00 04 01 01 00 00 00 01 00 00 00 01 00 04 00 00 04 00 01 01 00 00 01 00 00 04 01 00 04 00 00 01 00 04 00 00 04 00 00 00 04 04 00 01 04 04 01 00 04 04 01 01 04 00 01 00 00 00 01 01 04 04 00 01 04 00 00 01 04 04 00 00 04 04 01 00 00 04 01 01 04 04 00 00 00 04 00 01 00 04 00 01 00 00 00 00 04 00 01 00 00 04 01 00 00 00 00 00 04 00 01 01 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 04 04 00 00 00 04 00 01 00 04 00 01 00 04 01 00 00 04 01 00 00 00 01 01 00 00 01 01 04 04 00 01 04 00 01 00 04 00 00 01 04 00 00 01 04 00 01 00 00 00 00 00 04 04 00 00 04 04 01 00 00 00 00 01 00 00 01 00 04 04 01 01 04 00 00 00 00 00 01 01 00 04 01 01 00 00 00 01 00 00 00 01 00 04 00 00 04 00 01 01 00 00 01 00 00 04 01 00 04 00 00 01 00 04 00 00 04 00 00 00 04 04 00 01 04 04 01 00 04 04 01 01 04 00 01 00 00 00 01 01 04 04 00 01 04 00 00 01 04 04 00 00 04 04 01 00 00 04 01 01 04 04 00 00 00 04 00 01 00 04 00 01 00 00 00 00 04 00 01 00 00 04 01 00 00 00 00 00 04 00 01 01 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 04 04 00 00 00 04 00 01 00 04 00 01 00 04 01 00 00 04 01 00 00 00 01 01 00 00 01 01 04 04 00 01 04 00 01 00 04 00 00 01 04 00 00 01 04 00 01 00 00 00 00 00 04 04 00 00 04 04 01 00 00 00 00 01 00 00 01 00 04 04 01 01 04 00 00 00 00 00 01 01 00 04 01 01 00 00 00 01 00 00 00 01 00 04 00 00 04 00 01 01 00 00 01 00 00 04 01 00 04 00 00 01 00 04 00 00 04 00 00 00 04 04 00 01 04 04 01 00 04 04 01 01 04 00 01 00 00 00 01 01 04 04 00 01 04 00 00 01 04 04 00 00 04 04 01 00 00 04 01 01 04 04 00 00 00 04 00 01 00 04 00 01 00 00 00 00 04 00 01 00 00 04 01 00 00 00 00 00 04 00 01 01 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 04 04 00 00 00 04 00 01 00 04 00 01 00 04 01 00 00 04 01 00 00 00 01 01 00 00 01 01 04 04 00 01 04 00 01 00 04 00 00 01 04 00 00 01 04 00 01 00 00 00 00 00 04 04 00 00 04 04 01 00 00 00 00 01 00 00 01 00 04 04 01 01 04 00 00 00 00 00 01 01 00 04 01 01 00 00 00 01 00 00 00 01 00 04 00 00 04 00 01 01 00 00 01 00 00 04 01 00 04 00 00 01 00 04 00 00 04 00 00 00 04 04 00 01 04 04 01 00 04 04 01 01 04 00 01 00 00 00 01 01 04 04 00 01 04 00 00 01 04 04 00 00 04 04 01 00 00 04 01 01 04 04 00 00 00 04 00 01 00 04 00 01 00 00 00 00 04 00 01 00 00 04 01 00 00 00 00 00 04 00 01 01 }
    $des_spbox2 = { 20 80 10 80 00 80 00 80 00 80 00 00 20 80 10 00 00 00 10 00 20 00 00 00 20 00 10 80 20 80 00 80 20 00 00 80 20 80 10 80 00 80 10 80 00 00 00 80 00 80 00 80 00 00 10 00 20 00 00 00 20 00 10 80 00 80 10 00 20 00 10 00 20 80 00 80 00 00 00 00 00 00 00 80 00 80 00 00 20 80 10 00 00 00 10 80 20 00 10 00 20 00 00 80 00 00 00 00 00 80 10 00 20 80 00 00 00 80 10 80 00 00 10 80 20 80 00 00 00 00 00 00 20 80 10 00 20 00 10 80 00 00 10 00 20 80 00 80 00 00 10 80 00 80 10 80 00 80 00 00 00 00 10 80 00 80 00 80 20 00 00 00 20 80 10 80 20 80 10 00 20 00 00 00 00 80 00 00 00 00 00 80 20 80 00 00 00 80 10 80 00 00 10 00 20 00 00 80 20 00 10 00 20 80 00 80 20 00 00 80 20 00 10 00 00 80 10 00 00 00 00 00 00 80 00 80 20 80 00 00 00 00 00 80 20 00 10 80 20 80 10 80 00 80 10 00 20 80 10 80 00 80 00 80 00 80 00 00 20 80 10 00 00 00 10 00 20 00 00 00 20 00 10 80 20 80 00 80 20 00 00 80 20 80 10 80 00 80 10 80 00 00 00 80 00 80 00 80 00 00 10 00 20 00 00 00 20 00 10 80 00 80 10 00 20 00 10 00 20 80 00 80 00 00 00 00 00 00 00 80 00 80 00 00 20 80 10 00 00 00 10 80 20 00 10 00 20 00 00 80 00 00 00 00 00 80 10 00 20 80 00 00 00 80 10 80 00 00 10 80 20 80 00 00 00 00 00 00 20 80 10 00 20 00 10 80 00 00 10 00 20 80 00 80 00 00 10 80 00 80 10 80 00 80 00 00 00 00 10 80 00 80 00 80 20 00 00 00 20 80 10 80 20 80 10 00 20 00 00 00 00 80 00 00 00 00 00 80 20 80 00 00 00 80 10 80 00 00 10 00 20 00 00 80 20 00 10 00 20 80 00 80 20 00 00 80 20 00 10 00 00 80 10 00 00 00 00 00 00 80 00 80 20 80 00 00 00 00 00 80 20 00 10 80 20 80 10 80 00 80 10 00 20 80 10 80 00 80 00 80 00 80 00 00 20 80 10 00 00 00 10 00 20 00 00 00 20 00 10 80 20 80 00 80 20 00 00 80 20 80 10 80 00 80 10 80 00 00 00 80 00 80 00 80 00 00 10 00 20 00 00 00 20 00 10 80 00 80 10 00 20 00 10 00 20 80 00 80 00 00 00 00 00 00 00 80 00 80 00 00 20 80 10 00 00 00 10 80 20 00 10 00 20 00 00 80 00 00 00 00 00 80 10 00 20 80 00 00 00 80 10 80 00 00 10 80 20 80 00 00 00 00 00 00 20 80 10 00 20 00 10 80 00 00 10 00 20 80 00 80 00 00 10 80 00 80 10 80 00 80 00 00 00 00 10 80 00 80 00 80 20 00 00 00 20 80 10 80 20 80 10 00 20 00 00 00 00 80 00 00 00 00 00 80 20 80 00 00 00 80 10 80 00 00 10 00 20 00 00 80 20 00 10 00 20 80 00 80 20 00 00 80 20 00 10 00 00 80 10 00 00 00 00 00 00 80 00 80 20 80 00 00 00 00 00 80 20 00 10 80 20 80 10 80 00 80 10 00 20 80 10 80 00 80 00 80 00 80 00 00 20 80 10 00 00 00 10 00 20 00 00 00 20 00 10 80 20 80 00 80 20 00 00 80 20 80 10 80 00 80 10 80 00 00 00 80 00 80 00 80 00 00 10 00 20 00 00 00 20 00 10 80 00 80 10 00 20 00 10 00 20 80 00 80 00 00 00 00 00 00 00 80 00 80 00 00 20 80 10 00 00 00 10 80 20 00 10 00 20 00 00 80 00 00 00 00 00 80 10 00 20 80 00 00 00 80 10 80 00 00 10 80 20 80 00 00 00 00 00 00 20 80 10 00 20 00 10 80 00 00 10 00 20 80 00 80 00 00 10 80 00 80 10 80 00 80 00 00 00 00 10 80 00 80 00 80 20 00 00 00 20 80 10 80 20 80 10 00 20 00 00 00 00 80 00 00 00 00 00 80 20 80 00 00 00 80 10 80 00 00 10 00 20 00 00 80 20 00 10 00 20 80 00 80 20 00 00 80 20 00 10 00 00 80 10 00 00 00 00 00 00 80 00 80 20 80 00 00 00 00 00 80 20 00 10 80 20 80 10 80 00 80 10 00 }
    $des_spbox3 = { 08 02 00 00 00 02 02 08 00 00 00 00 08 00 02 08 00 02 00 08 00 00 00 00 08 02 02 00 00 02 00 08 08 00 02 00 08 00 00 08 08 00 00 08 00 00 02 00 08 02 02 08 08 00 02 00 00 00 02 08 08 02 00 00 00 00 00 08 08 00 00 00 00 02 02 08 00 02 00 00 00 02 02 00 00 00 02 08 08 00 02 08 08 02 02 00 08 02 00 08 00 02 02 00 00 00 02 00 08 02 00 08 08 00 00 00 08 02 02 08 00 02 00 00 00 00 00 08 00 02 02 08 00 00 00 08 08 00 02 00 08 02 00 00 00 00 02 00 00 02 02 08 00 02 00 08 00 00 00 00 00 02 00 00 08 00 02 00 08 02 02 08 00 02 00 08 08 00 00 08 00 02 00 00 00 00 00 00 08 00 02 08 08 02 00 08 00 00 02 00 00 00 00 08 08 02 02 08 08 00 00 00 08 02 02 00 00 02 02 00 08 00 00 08 00 00 02 08 08 02 00 08 08 02 00 00 00 00 02 08 08 02 02 00 08 00 00 00 08 00 02 08 00 02 02 00 08 02 00 00 00 02 02 08 00 00 00 00 08 00 02 08 00 02 00 08 00 00 00 00 08 02 02 00 00 02 00 08 08 00 02 00 08 00 00 08 08 00 00 08 00 00 02 00 08 02 02 08 08 00 02 00 00 00 02 08 08 02 00 00 00 00 00 08 08 00 00 00 00 02 02 08 00 02 00 00 00 02 02 00 00 00 02 08 08 00 02 08 08 02 02 00 08 02 00 08 00 02 02 00 00 00 02 00 08 02 00 08 08 00 00 00 08 02 02 08 00 02 00 00 00 00 00 08 00 02 02 08 00 00 00 08 08 00 02 00 08 02 00 00 00 00 02 00 00 02 02 08 00 02 00 08 00 00 00 00 00 02 00 00 08 00 02 00 08 02 02 08 00 02 00 08 08 00 00 08 00 02 00 00 00 00 00 00 08 00 02 08 08 02 00 08 00 00 02 00 00 00 00 08 08 02 02 08 08 00 00 00 08 02 02 00 00 02 02 00 08 00 00 08 00 00 02 08 08 02 00 08 08 02 00 00 00 00 02 08 08 02 02 00 08 00 00 00 08 00 02 08 00 02 02 00 08 02 00 00 00 02 02 08 00 00 00 00 08 00 02 08 00 02 00 08 00 00 00 00 08 02 02 00 00 02 00 08 08 00 02 00 08 00 00 08 08 00 00 08 00 00 02 00 08 02 02 08 08 00 02 00 00 00 02 08 08 02 00 00 00 00 00 08 08 00 00 00 00 02 02 08 00 02 00 00 00 02 02 00 00 00 02 08 08 00 02 08 08 02 02 00 08 02 00 08 00 02 02 00 00 00 02 00 08 02 00 08 08 00 00 00 08 02 02 08 00 02 00 00 00 00 00 08 00 02 02 08 00 00 00 08 08 00 02 00 08 02 00 00 00 00 02 00 00 02 02 08 00 02 00 08 00 00 00 00 00 02 00 00 08 00 02 00 08 02 02 08 00 02 00 08 08 00 00 08 00 02 00 00 00 00 00 00 08 00 02 08 08 02 00 08 00 00 02 00 00 00 00 08 08 02 02 08 08 00 00 00 08 02 02 00 00 02 02 00 08 00 00 08 00 00 02 08 08 02 00 08 08 02 00 00 00 00 02 08 08 02 02 00 08 00 00 00 08 00 02 08 00 02 02 00 08 02 00 00 00 02 02 08 00 00 00 00 08 00 02 08 00 02 00 08 00 00 00 00 08 02 02 00 00 02 00 08 08 00 02 00 08 00 00 08 08 00 00 08 00 00 02 00 08 02 02 08 08 00 02 00 00 00 02 08 08 02 00 00 00 00 00 08 08 00 00 00 00 02 02 08 00 02 00 00 00 02 02 00 00 00 02 08 08 00 02 08 08 02 02 00 08 02 00 08 00 02 02 00 00 00 02 00 08 02 00 08 08 00 00 00 08 02 02 08 00 02 00 00 00 00 00 08 00 02 02 08 00 00 00 08 08 00 02 00 08 02 00 00 00 00 02 00 00 02 02 08 00 02 00 08 00 00 00 00 00 02 00 00 08 00 02 00 08 02 02 08 00 02 00 08 08 00 00 08 00 02 00 00 00 00 00 00 08 00 02 08 08 02 00 08 00 00 02 00 00 00 00 08 08 02 02 08 08 00 00 00 08 02 02 00 00 02 02 00 08 00 00 08 00 00 02 08 08 02 00 08 08 02 00 00 00 00 02 08 08 02 02 00 08 00 00 00 08 00 02 08 00 02 02 00 }
    $des_spbox4 = { 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 80 20 80 00 81 00 80 00 01 00 80 00 01 20 00 00 00 00 00 00 00 20 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 80 00 80 00 01 00 80 00 01 00 00 00 00 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 01 20 00 00 80 20 00 00 81 00 80 00 01 00 00 00 80 20 00 00 80 00 80 00 00 20 00 00 80 20 80 00 81 20 80 00 81 00 00 00 80 00 80 00 01 00 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 00 00 00 00 00 20 80 00 80 20 00 00 80 00 80 00 81 00 80 00 01 00 00 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 81 20 80 00 81 00 00 00 01 00 00 00 00 20 00 00 01 00 80 00 01 20 00 00 80 20 80 00 81 00 80 00 01 20 00 00 80 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 00 20 00 00 80 20 80 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 80 20 80 00 81 00 80 00 01 00 80 00 01 20 00 00 00 00 00 00 00 20 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 80 00 80 00 01 00 80 00 01 00 00 00 00 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 01 20 00 00 80 20 00 00 81 00 80 00 01 00 00 00 80 20 00 00 80 00 80 00 00 20 00 00 80 20 80 00 81 20 80 00 81 00 00 00 80 00 80 00 01 00 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 00 00 00 00 00 20 80 00 80 20 00 00 80 00 80 00 81 00 80 00 01 00 00 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 81 20 80 00 81 00 00 00 01 00 00 00 00 20 00 00 01 00 80 00 01 20 00 00 80 20 80 00 81 00 80 00 01 20 00 00 80 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 00 20 00 00 80 20 80 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 80 20 80 00 81 00 80 00 01 00 80 00 01 20 00 00 00 00 00 00 00 20 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 80 00 80 00 01 00 80 00 01 00 00 00 00 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 01 20 00 00 80 20 00 00 81 00 80 00 01 00 00 00 80 20 00 00 80 00 80 00 00 20 00 00 80 20 80 00 81 20 80 00 81 00 00 00 80 00 80 00 01 00 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 00 00 00 00 00 20 80 00 80 20 00 00 80 00 80 00 81 00 80 00 01 00 00 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 81 20 80 00 81 00 00 00 01 00 00 00 00 20 00 00 01 00 80 00 01 20 00 00 80 20 80 00 81 00 80 00 01 20 00 00 80 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 00 20 00 00 80 20 80 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 80 20 80 00 81 00 80 00 01 00 80 00 01 20 00 00 00 00 00 00 00 20 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 80 00 80 00 01 00 80 00 01 00 00 00 00 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 01 20 00 00 80 20 00 00 81 00 80 00 01 00 00 00 80 20 00 00 80 00 80 00 00 20 00 00 80 20 80 00 81 20 80 00 81 00 00 00 80 00 80 00 01 00 80 00 00 20 80 00 81 20 80 00 81 00 00 00 00 00 00 00 00 00 00 00 00 20 80 00 80 20 00 00 80 00 80 00 81 00 80 00 01 00 00 00 01 20 80 00 81 20 00 00 81 20 00 00 80 00 00 00 81 20 80 00 81 00 00 00 01 00 00 00 00 20 00 00 01 00 80 00 01 20 00 00 80 20 80 00 81 00 80 00 01 20 00 00 80 20 00 00 00 00 80 00 01 20 80 00 80 00 00 00 00 00 80 00 00 20 00 00 80 20 80 00 }
    $des_spbox5 = { 00 01 00 00 00 01 08 02 00 00 08 02 00 01 00 42 00 00 08 00 00 01 00 00 00 00 00 40 00 00 08 02 00 01 08 40 00 00 08 00 00 01 00 02 00 01 08 40 00 01 00 42 00 00 08 42 00 01 08 00 00 00 00 40 00 00 00 02 00 00 08 40 00 00 08 40 00 00 00 00 00 01 00 40 00 01 08 42 00 01 08 42 00 01 00 02 00 00 08 42 00 01 00 40 00 00 00 00 00 00 00 42 00 01 08 02 00 00 00 02 00 00 00 42 00 01 08 00 00 00 08 00 00 01 00 42 00 01 00 00 00 00 00 02 00 00 00 40 00 00 08 02 00 01 00 42 00 01 08 40 00 01 00 02 00 00 00 40 00 00 08 42 00 01 08 02 00 01 08 40 00 01 00 00 00 00 00 02 00 00 08 42 00 01 08 42 00 01 08 00 00 00 00 42 00 01 08 42 00 00 08 02 00 00 00 00 00 00 08 40 00 00 00 42 00 01 08 00 00 01 00 02 00 01 00 40 00 00 08 00 00 00 00 00 00 00 08 40 00 01 08 02 00 01 00 40 00 01 00 00 00 01 08 02 00 00 08 02 00 01 00 42 00 00 08 00 00 01 00 00 00 00 00 40 00 00 08 02 00 01 08 40 00 00 08 00 00 01 00 02 00 01 08 40 00 01 00 42 00 00 08 42 00 01 08 00 00 00 00 40 00 00 00 02 00 00 08 40 00 00 08 40 00 00 00 00 00 01 00 40 00 01 08 42 00 01 08 42 00 01 00 02 00 00 08 42 00 01 00 40 00 00 00 00 00 00 00 42 00 01 08 02 00 00 00 02 00 00 00 42 00 01 08 00 00 00 08 00 00 01 00 42 00 01 00 00 00 00 00 02 00 00 00 40 00 00 08 02 00 01 00 42 00 01 08 40 00 01 00 02 00 00 00 40 00 00 08 42 00 01 08 02 00 01 08 40 00 01 00 00 00 00 00 02 00 00 08 42 00 01 08 42 00 01 08 00 00 00 00 42 00 01 08 42 00 00 08 02 00 00 00 00 00 00 08 40 00 00 00 42 00 01 08 00 00 01 00 02 00 01 00 40 00 00 08 00 00 00 00 00 00 00 08 40 00 01 08 02 00 01 00 40 00 01 00 00 00 01 08 02 00 00 08 02 00 01 00 42 00 00 08 00 00 01 00 00 00 00 00 40 00 00 08 02 00 01 08 40 00 00 08 00 00 01 00 02 00 01 08 40 00 01 00 42 00 00 08 42 00 01 08 00 00 00 00 40 00 00 00 02 00 00 08 40 00 00 08 40 00 00 00 00 00 01 00 40 00 01 08 42 00 01 08 42 00 01 00 02 00 00 08 42 00 01 00 40 00 00 00 00 00 00 00 42 00 01 08 02 00 00 00 02 00 00 00 42 00 01 08 00 00 00 08 00 00 01 00 42 00 01 00 00 00 00 00 02 00 00 00 40 00 00 08 02 00 01 00 42 00 01 08 40 00 01 00 02 00 00 00 40 00 00 08 42 00 01 08 02 00 01 08 40 00 01 00 00 00 00 00 02 00 00 08 42 00 01 08 42 00 01 08 00 00 00 00 42 00 01 08 42 00 00 08 02 00 00 00 00 00 00 08 40 00 00 00 42 00 01 08 00 00 01 00 02 00 01 00 40 00 00 08 00 00 00 00 00 00 00 08 40 00 01 08 02 00 01 00 40 00 01 00 00 00 01 08 02 00 00 08 02 00 01 00 42 00 00 08 00 00 01 00 00 00 00 00 40 00 00 08 02 00 01 08 40 00 00 08 00 00 01 00 02 00 01 08 40 00 01 00 42 00 00 08 42 00 01 08 00 00 00 00 40 00 00 00 02 00 00 08 40 00 00 08 40 00 00 00 00 00 01 00 40 00 01 08 42 00 01 08 42 00 01 00 02 00 00 08 42 00 01 00 40 00 00 00 00 00 00 00 42 00 01 08 02 00 00 00 02 00 00 00 42 00 01 08 00 00 00 08 00 00 01 00 42 00 01 00 00 00 00 00 02 00 00 00 40 00 00 08 02 00 01 00 42 00 01 08 40 00 01 00 02 00 00 00 40 00 00 08 42 00 01 08 02 00 01 08 40 00 01 00 00 00 00 00 02 00 00 08 42 00 01 08 42 00 01 08 00 00 00 00 42 00 01 08 42 00 00 08 02 00 00 00 00 00 00 08 40 00 00 00 42 00 01 08 00 00 01 00 02 00 01 00 40 00 00 08 00 00 00 00 00 00 00 08 40 00 01 08 02 00 01 00 40 }
    $des_spbox6 = { 10 00 00 20 00 00 40 20 00 40 00 00 10 40 40 20 00 00 40 20 10 00 00 00 10 40 40 20 00 00 40 00 00 40 00 20 10 40 40 00 00 00 40 00 10 00 00 20 10 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 00 00 00 00 10 00 40 00 10 40 00 20 00 40 00 00 00 40 40 00 10 40 00 20 10 00 00 00 10 00 40 20 10 00 40 20 00 00 00 00 10 40 40 00 00 40 40 20 10 40 00 00 00 40 40 00 00 40 40 20 00 00 00 20 00 40 00 20 10 00 00 00 10 00 40 20 00 40 40 00 10 40 40 20 00 00 40 00 10 40 00 00 10 00 00 20 00 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 10 00 00 20 10 40 40 20 00 40 40 00 00 00 40 20 10 40 40 00 00 40 40 20 00 00 00 00 10 00 40 20 10 00 00 00 00 40 00 00 00 00 40 20 10 40 40 00 00 40 00 00 10 00 40 00 10 40 00 20 00 00 00 00 00 40 40 20 00 00 00 20 10 00 40 00 10 40 00 20 10 00 00 20 00 00 40 20 00 40 00 00 10 40 40 20 00 00 40 20 10 00 00 00 10 40 40 20 00 00 40 00 00 40 00 20 10 40 40 00 00 00 40 00 10 00 00 20 10 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 00 00 00 00 10 00 40 00 10 40 00 20 00 40 00 00 00 40 40 00 10 40 00 20 10 00 00 00 10 00 40 20 10 00 40 20 00 00 00 00 10 40 40 00 00 40 40 20 10 40 00 00 00 40 40 00 00 40 40 20 00 00 00 20 00 40 00 20 10 00 00 00 10 00 40 20 00 40 40 00 10 40 40 20 00 00 40 00 10 40 00 00 10 00 00 20 00 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 10 00 00 20 10 40 40 20 00 40 40 00 00 00 40 20 10 40 40 00 00 40 40 20 00 00 00 00 10 00 40 20 10 00 00 00 00 40 00 00 00 00 40 20 10 40 40 00 00 40 00 00 10 00 40 00 10 40 00 20 00 00 00 00 00 40 40 20 00 00 00 20 10 00 40 00 10 40 00 20 10 00 00 20 00 00 40 20 00 40 00 00 10 40 40 20 00 00 40 20 10 00 00 00 10 40 40 20 00 00 40 00 00 40 00 20 10 40 40 00 00 00 40 00 10 00 00 20 10 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 00 00 00 00 10 00 40 00 10 40 00 20 00 40 00 00 00 40 40 00 10 40 00 20 10 00 00 00 10 00 40 20 10 00 40 20 00 00 00 00 10 40 40 00 00 40 40 20 10 40 00 00 00 40 40 00 00 40 40 20 00 00 00 20 00 40 00 20 10 00 00 00 10 00 40 20 00 40 40 00 10 40 40 20 00 00 40 00 10 40 00 00 10 00 00 20 00 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 10 00 00 20 10 40 40 20 00 40 40 00 00 00 40 20 10 40 40 00 00 40 40 20 00 00 00 00 10 00 40 20 10 00 00 00 00 40 00 00 00 00 40 20 10 40 40 00 00 40 00 00 10 00 40 00 10 40 00 20 00 00 00 00 00 40 40 20 00 00 00 20 10 00 40 00 10 40 00 20 10 00 00 20 00 00 40 20 00 40 00 00 10 40 40 20 00 00 40 20 10 00 00 00 10 40 40 20 00 00 40 00 00 40 00 20 10 40 40 00 00 00 40 00 10 00 00 20 10 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 00 00 00 00 10 00 40 00 10 40 00 20 00 40 00 00 00 40 40 00 10 40 00 20 10 00 00 00 10 00 40 20 10 00 40 20 00 00 00 00 10 40 40 00 00 40 40 20 10 40 00 00 00 40 40 00 00 40 40 20 00 00 00 20 00 40 00 20 10 00 00 00 10 00 40 20 00 40 40 00 10 40 40 20 00 00 40 00 10 40 00 00 10 00 00 20 00 00 40 00 00 40 00 20 00 00 00 20 10 40 00 00 10 00 00 20 10 40 40 20 00 40 40 00 00 00 40 20 10 40 40 00 00 40 40 20 00 00 00 00 10 00 40 20 10 00 00 00 00 40 00 00 00 00 40 20 10 40 40 00 00 40 00 00 10 00 40 00 10 40 00 20 00 00 00 00 00 40 40 20 00 00 00 20 10 00 40 00 10 40 00 20 }
    $des_spbox7 = { 00 00 20 00 02 00 20 04 02 08 00 04 00 00 00 00 00 08 00 00 02 08 00 04 02 08 20 00 00 08 20 04 02 08 20 04 00 00 20 00 00 00 00 00 02 00 00 04 02 00 00 00 00 00 00 04 02 00 20 04 02 08 00 00 00 08 00 04 02 08 20 00 02 00 20 00 00 08 00 04 02 00 00 04 00 00 20 04 00 08 20 04 02 00 20 00 00 00 20 04 00 08 00 00 02 08 00 00 02 08 20 04 00 08 20 00 02 00 00 00 00 00 00 04 00 08 20 00 00 00 00 04 00 08 20 00 00 00 20 00 02 08 00 04 02 08 00 04 02 00 20 04 02 00 20 04 02 00 00 00 02 00 20 00 00 00 00 04 00 08 00 04 00 00 20 00 00 08 20 04 02 08 00 00 02 08 20 00 00 08 20 04 02 08 00 00 02 00 00 04 02 08 20 04 00 00 20 04 00 08 20 00 00 00 00 00 02 00 00 00 02 08 20 04 00 00 00 00 02 08 20 00 00 00 20 04 00 08 00 00 02 00 00 04 00 08 00 04 00 08 00 00 02 00 20 00 00 00 20 00 02 00 20 04 02 08 00 04 00 00 00 00 00 08 00 00 02 08 00 04 02 08 20 00 00 08 20 04 02 08 20 04 00 00 20 00 00 00 00 00 02 00 00 04 02 00 00 00 00 00 00 04 02 00 20 04 02 08 00 00 00 08 00 04 02 08 20 00 02 00 20 00 00 08 00 04 02 00 00 04 00 00 20 04 00 08 20 04 02 00 20 00 00 00 20 04 00 08 00 00 02 08 00 00 02 08 20 04 00 08 20 00 02 00 00 00 00 00 00 04 00 08 20 00 00 00 00 04 00 08 20 00 00 00 20 00 02 08 00 04 02 08 00 04 02 00 20 04 02 00 20 04 02 00 00 00 02 00 20 00 00 00 00 04 00 08 00 04 00 00 20 00 00 08 20 04 02 08 00 00 02 08 20 00 00 08 20 04 02 08 00 00 02 00 00 04 02 08 20 04 00 00 20 04 00 08 20 00 00 00 00 00 02 00 00 00 02 08 20 04 00 00 00 00 02 08 20 00 00 00 20 04 00 08 00 00 02 00 00 04 00 08 00 04 00 08 00 00 02 00 20 00 00 00 20 00 02 00 20 04 02 08 00 04 00 00 00 00 00 08 00 00 02 08 00 04 02 08 20 00 00 08 20 04 02 08 20 04 00 00 20 00 00 00 00 00 02 00 00 04 02 00 00 00 00 00 00 04 02 00 20 04 02 08 00 00 00 08 00 04 02 08 20 00 02 00 20 00 00 08 00 04 02 00 00 04 00 00 20 04 00 08 20 04 02 00 20 00 00 00 20 04 00 08 00 00 02 08 00 00 02 08 20 04 00 08 20 00 02 00 00 00 00 00 00 04 00 08 20 00 00 00 00 04 00 08 20 00 00 00 20 00 02 08 00 04 02 08 00 04 02 00 20 04 02 00 20 04 02 00 00 00 02 00 20 00 00 00 00 04 00 08 00 04 00 00 20 00 00 08 20 04 02 08 00 00 02 08 20 00 00 08 20 04 02 08 00 00 02 00 00 04 02 08 20 04 00 00 20 04 00 08 20 00 00 00 00 00 02 00 00 00 02 08 20 04 00 00 00 00 02 08 20 00 00 00 20 04 00 08 00 00 02 00 00 04 00 08 00 04 00 08 00 00 02 00 20 00 00 00 20 00 02 00 20 04 02 08 00 04 00 00 00 00 00 08 00 00 02 08 00 04 02 08 20 00 00 08 20 04 02 08 20 04 00 00 20 00 00 00 00 00 02 00 00 04 02 00 00 00 00 00 00 04 02 00 20 04 02 08 00 00 00 08 00 04 02 08 20 00 02 00 20 00 00 08 00 04 02 00 00 04 00 00 20 04 00 08 20 04 02 00 20 00 00 00 20 04 00 08 00 00 02 08 00 00 02 08 20 04 00 08 20 00 02 00 00 00 00 00 00 04 00 08 20 00 00 00 00 04 00 08 20 00 00 00 20 00 02 08 00 04 02 08 00 04 02 00 20 04 02 00 20 04 02 00 00 00 02 00 20 00 00 00 00 04 00 08 00 04 00 00 20 00 00 08 20 04 02 08 00 00 02 08 20 00 00 08 20 04 02 08 00 00 02 00 00 04 02 08 20 04 00 00 20 04 00 08 20 00 00 00 00 00 02 00 00 00 02 08 20 04 00 00 00 00 02 08 20 00 00 00 20 04 00 08 00 00 02 00 00 04 00 08 00 04 00 08 00 00 02 00 20 00 }
    $des_spbox8 = { 40 10 00 10 00 10 00 00 00 00 04 00 40 10 04 10 00 00 00 10 40 10 00 10 40 00 00 00 00 00 00 10 40 00 04 00 00 00 04 10 40 10 04 10 00 10 04 00 00 10 04 10 40 10 04 00 00 10 00 00 40 00 00 00 00 00 04 10 40 00 00 10 00 10 00 10 40 10 00 00 00 10 04 00 40 00 04 00 40 00 04 10 00 10 04 10 40 10 00 00 00 00 00 00 00 00 00 00 40 00 04 10 40 00 00 10 00 10 00 10 40 10 04 00 00 00 04 00 40 10 04 00 00 00 04 00 00 10 04 10 00 10 00 00 40 00 00 00 40 00 04 10 00 10 00 00 40 10 04 00 00 10 00 10 40 00 00 00 40 00 00 10 00 00 04 10 40 00 04 10 00 00 00 10 00 00 04 00 40 10 00 10 00 00 00 00 40 10 04 10 40 00 04 00 40 00 00 10 00 00 04 10 00 10 00 10 40 10 00 10 00 00 00 00 40 10 04 10 00 10 04 00 00 10 04 00 40 10 00 00 40 10 00 00 40 00 04 00 00 00 00 10 00 10 04 10 40 10 00 10 00 10 00 00 00 00 04 00 40 10 04 10 00 00 00 10 40 10 00 10 40 00 00 00 00 00 00 10 40 00 04 00 00 00 04 10 40 10 04 10 00 10 04 00 00 10 04 10 40 10 04 00 00 10 00 00 40 00 00 00 00 00 04 10 40 00 00 10 00 10 00 10 40 10 00 00 00 10 04 00 40 00 04 00 40 00 04 10 00 10 04 10 40 10 00 00 00 00 00 00 00 00 00 00 40 00 04 10 40 00 00 10 00 10 00 10 40 10 04 00 00 00 04 00 40 10 04 00 00 00 04 00 00 10 04 10 00 10 00 00 40 00 00 00 40 00 04 10 00 10 00 00 40 10 04 00 00 10 00 10 40 00 00 00 40 00 00 10 00 00 04 10 40 00 04 10 00 00 00 10 00 00 04 00 40 10 00 10 00 00 00 00 40 10 04 10 40 00 04 00 40 00 00 10 00 00 04 10 00 10 00 10 40 10 00 10 00 00 00 00 40 10 04 10 00 10 04 00 00 10 04 00 40 10 00 00 40 10 00 00 40 00 04 00 00 00 00 10 00 10 04 10 40 10 00 10 00 10 00 00 00 00 04 00 40 10 04 10 00 00 00 10 40 10 00 10 40 00 00 00 00 00 00 10 40 00 04 00 00 00 04 10 40 10 04 10 00 10 04 00 00 10 04 10 40 10 04 00 00 10 00 00 40 00 00 00 00 00 04 10 40 00 00 10 00 10 00 10 40 10 00 00 00 10 04 00 40 00 04 00 40 00 04 10 00 10 04 10 40 10 00 00 00 00 00 00 00 00 00 00 40 00 04 10 40 00 00 10 00 10 00 10 40 10 04 00 00 00 04 00 40 10 04 00 00 00 04 00 00 10 04 10 00 10 00 00 40 00 00 00 40 00 04 10 00 10 00 00 40 10 04 00 00 10 00 10 40 00 00 00 40 00 00 10 00 00 04 10 40 00 04 10 00 00 00 10 00 00 04 00 40 10 00 10 00 00 00 00 40 10 04 10 40 00 04 00 40 00 00 10 00 00 04 10 00 10 00 10 40 10 00 10 00 00 00 00 40 10 04 10 00 10 04 00 00 10 04 00 40 10 00 00 40 10 00 00 40 00 04 00 00 00 00 10 00 10 04 10 40 10 00 10 00 10 00 00 00 00 04 00 40 10 04 10 00 00 00 10 40 10 00 10 40 00 00 00 00 00 00 10 40 00 04 00 00 00 04 10 40 10 04 10 00 10 04 00 00 10 04 10 40 10 04 00 00 10 00 00 40 00 00 00 00 00 04 10 40 00 00 10 00 10 00 10 40 10 00 00 00 10 04 00 40 00 04 00 40 00 04 10 00 10 04 10 40 10 00 00 00 00 00 00 00 00 00 00 40 00 04 10 40 00 00 10 00 10 00 10 40 10 04 00 00 00 04 00 40 10 04 00 00 00 04 00 00 10 04 10 00 10 00 00 40 00 00 00 40 00 04 10 00 10 00 00 40 10 04 00 00 10 00 10 40 00 00 00 40 00 00 10 00 00 04 10 40 00 04 10 00 00 00 10 00 00 04 00 40 10 00 10 00 00 00 00 40 10 04 10 40 00 04 00 40 00 00 10 00 00 04 10 00 10 00 10 40 10 00 10 00 00 00 00 40 10 04 10 00 10 04 00 00 10 04 00 40 10 00 00 40 10 00 00 40 00 04 00 00 00 00 10 00 10 04 10 }
    $des_ip = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08 39 31 29 21 19 11 09 01 3B 33 2B 23 1B 13 0B 03 3D 35 2D 25 1D 15 0D 05 3F 37 2F 27 1F 17 0F 07 }
    $des_fp = { 28 08 30 10 38 18 40 20 27 07 2F 0F 37 17 3F 1F 26 06 2E 0E 36 16 3E 1E 25 05 2D 0D 35 15 3D 1D 24 04 2C 0C 34 14 3C 1C 23 03 2B 0B 33 13 3B 1B 22 02 2A 0A 32 12 3A 1A 21 01 29 09 31 11 39 19 }
  condition:
    any of them
}

rule RC56
{
  meta:
    author = "Ivan Kwiatkowski (@JusticeRage)"
    description = "Uses constants related to RC5 or RC6"
  strings:
    $rc6_p32 = { 63 51 E1 B7 }
    $rc6_q32 = { B9 79 37 9E }
    $rc6_p64 = { 6B 2A ED 8A 62 51 E1 B7 }
    $rc6_q64 = { 15 7C 4A 7F B9 79 37 9E }
  condition:
    2 of them
}

rule Twofish
{
  meta:
    description = "Uses constants related to Twofish"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $tf_q0 = { A9 67 B3 E8 04 FD A3 76 9A 92 80 78 E4 DD D1 38 0D C6 35 98 18 F7 EC 6C 43 75 37 26 FA 13 94 48 F2 D0 8B 30 84 54 DF 23 19 5B 3D 59 F3 AE A2 82 63 01 83 2E D9 51 9B 7C A6 EB A5 BE 16 0C E3 61 C0 8C 3A F5 73 2C 25 0B BB 4E 89 6B 53 6A B4 F1 E1 E6 BD 45 E2 F4 B6 66 CC 95 03 56 D4 1C 1E D7 FB C3 8E B5 E9 CF BF BA EA 77 39 AF 33 C9 62 71 81 79 09 AD 24 CD F9 D8 E5 C5 B9 4D 44 08 86 E7 A1 1D AA ED 06 70 B2 D2 41 7B A0 11 31 C2 27 90 20 F6 60 FF 96 5C B1 AB 9E 9C 52 1B 5F 93 0A EF 91 85 49 EE 2D 4F 8F 3B 47 87 6D 46 D6 3E 69 64 2A CE CB 2F FC 97 05 7A AC 7F D5 1A 4B 0E A7 5A 28 14 3F 29 88 3C 4C 02 B8 DA B0 17 55 1F 8A 7D 57 C7 8D 74 B7 C4 9F 72 7E 15 22 12 58 07 99 34 6E 50 DE 68 65 BC DB F8 C8 A8 2B 40 DC FE 32 A4 CA 10 21 F0 D3 5D 0F 00 6F 9D 36 42 4A 5E C1 E0 }
    $tf_q1 = { 75 F3 C6 F4 DB 7B FB C8 4A D3 E6 6B 45 7D E8 4B D6 32 D8 FD 37 71 F1 E1 30 0F F8 1B 87 FA 06 3F 5E BA AE 5B 8A 00 BC 9D 6D C1 B1 0E 80 5D D2 D5 A0 84 07 14 B5 90 2C A3 B2 73 4C 54 92 74 36 51 38 B0 BD 5A FC 60 62 96 6C 42 F7 10 7C 28 27 8C 13 95 9C C7 24 46 3B 70 CA E3 85 CB 11 D0 93 B8 A6 83 20 FF 9F 77 C3 CC 03 6F 08 BF 40 E7 2B E2 79 0C AA 82 41 3A EA B9 E4 9A A4 97 7E DA 7A 17 66 94 A1 1D 3D F0 DE B3 0B 72 A7 1C EF D1 53 3E 8F 33 26 5F EC 76 2A 49 81 88 EE 21 C4 1A EB D9 C5 39 99 CD AD 31 8B 01 18 23 DD 1F 4E 2D F9 48 4F F2 65 8E 78 5C 58 19 8D E5 98 57 67 7F 05 64 AF 63 B6 FE F5 B7 3C A5 CE E9 68 44 E0 4D 43 69 29 2E AC 15 59 A8 0A 9E 6E 47 DF 34 35 6A CF DC 22 C9 C0 9B 89 D4 ED AB 12 A2 0D 52 BB 02 2F A9 D7 61 1E B4 50 04 F6 C2 16 25 86 56 55 09 BE 91 }
    $tf_rs = { 01 A4 02 A4 A4 56 A1 55 55 82 FC 8787 F3 C1 5A 5A 1E 47 58 58 C6 AE DB DB 68 3D 9E 9E E5 19 03 }
    $tf_exp2poly = { 01 02 04 08 10 20 40 80 4D 9A 79 F2 A9 1F 3E 7C F8 BD 37 6E DC F5 A7 03 06 0C 18 30 60 C0 CD D7 E3 8B 5B B6 21 42 84 45 8A 59 B2 29 52 A4 05 0A 14 28 50 A0 0D 1A 34 68 D0 ED 97 63 C6 C1 CF D3 EB 9B 7B F6 A1 0F 1E 3C 78 F0 AD 17 2E 5C B8 3D 7A F4 A5 07 0E 1C 38 70 E0 8D 57 AE 11 22 44 88 5D BA 39 72 E4 85 47 8E 51 A2 09 12 24 48 90 6D DA F9 BF 33 66 CC D5 E7 83 4B 96 61 C2 C9 DF F3 AB 1B 36 6C D8 FD B7 23 46 8C 55 AA 19 32 64 C8 DD F7 A3 0B 16 2C 58 B0 2D 5A B4 25 4A 94 65 CA D9 FF B3 2B 56 AC 15 2A 54 A8 1D 3A 74 E8 9D 77 EE 91 6F DE F1 AF 13 26 4C 98 7D FA B9 3F 7E FC B5 27 4E 9C 75 EA 99 7F FE B1 2F 5E BC 35 6A D4 E5 87 43 86 41 82 49 92 69 D2 E9 9F 73 E6 81 4F 9E 71 E2 89 5F BE 31 62 C4 C5 C7 C3 CB DB FB BB 3B 76 EC 95 67 CE D1 EF 93 6B D6 E1 8F 53 A6 }
    $tf_poly2exp = { 00 01 17 02 2E 18 53 03 6A 2F 93 19 34 54 45 04 5C 6B B6 30 A6 94 4B 1A 8C 35 81 55 AA 46 0D 05 24 5D 87 6C 9B B7 C1 31 2B A7 A3 95 98 4C CA 1B E6 8D 73 36 CD 82 12 56 62 AB F0 47 4F 0E BD 06 D4 25 D2 5E 27 88 66 6D D6 9C 79 B8 08 C2 DF 32 68 2C FD A8 8A A4 5A 96 29 99 22 4D 60 CB E4 1C 7B E7 3B 8E 9E 74 F4 37 D8 CE F9 83 6F 13 B2 57 E1 63 DC AC C4 F1 AF 48 0A 50 42 0F BA BE C7 07 DE D5 78 26 65 D3 D1 5F E3 28 21 89 59 67 FC 6E B1 D7 F8 9D F3 7A 3A B9 C6 09 41 C3 AE E0 DB 33 44 69 92 2D 52 FE 16 A9 0C 8B 80 A5 4A 5B B5 97 C9 2A A2 9A C0 23 86 4E BC 61 EF CC 11 E5 72 1D 3D 7C EB E8 E9 3C EA 8F 7D 9F EC 75 1E F5 3E 38 F6 D9 3F CF 76 FA 1F 84 A0 70 ED 14 90 B3 7E 58 FB E2 20 64 D0 DD 77 AD DA C5 40 F2 39 B0 F7 49 B4 0B 7F 51 15 43 91 10 71 BB EE BF 85 C8 A1 }

  condition:
    any of them
}

rule Chacha_128_constant 
{
    meta:
        author = "spelissier"
        description = "Look for 128-bit key Chacha stream cipher constant"
        date = "2019-12"
        reference = "https://www.ecrypt.eu.org/stream/salsa20pf.html"
    strings:
        $c0 = "expand 16-byte k"
    condition:
        $c0
}

rule Chacha_256_constant {
    meta:
        author = "spelissier"
        description = "Look for 256-bit key Chacha stream cipher constant"
        date = "2019-12"
        reference = "https://tools.ietf.org/html/rfc8439#page-8"
    strings:
        $c0 = "expand 32-byte k"
        $split1 = "expand 3"
        $split2 = "2-byte k"
    condition:
        $c0 or ( $split1 and $split2 )
}

rule ecc_order
{
    meta:
        author = "spelissier"
        description = "Look for known Elliptic curve orders"
        date = "2021-07"
        version = "0.2"
    strings:
        $secp192k1 = { FF FF FF FF FF FF FF FF FF FF FF FE 26 F2 FC 17 0F 69 46 6A 74 DE FD 8D}
        $secp192r1 = { FF FF FF FF FF FF FF FF FF FF FF FF 99 DE F8 36 14 6B C9 B1 B4 D2 28 31}
        $secp224k1 = { 01 00 00 00 00 00 00 00 00 00 00 00 00 00 01 DC E8 D2 EC 61 84 CA F0 A9 71 76 9F B1 F7}
        $secp224r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF 16 A2 E0 B8 F0 3E 13 DD 29 45 5C 5C 2A 3D}
        $secp256k1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE BA AE DC E6 AF 48 A0 3B BF D2 5E 8C D0 36 41 41 }
        $prime256v1 = { FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF BC E6 FA AD A7 17 9E 84 F3 B9 CA C2 FC 63 25 51 }
        $secp384r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF C7 63 4D 81 F4 37 2D DF 58 1A 0D B2 48 B0 A7 7A EC EC 19 6A CC C5 29 73 }
        $bls12_381_r = { 01 00 00 00 FF FF FF FF FE 5B FE FF 02 A4 BD 53 05 D8 A1 09 08 D8 39 33 48 7D 9D 29 53 A7 ED 73}
    condition:
        any of them
}

rule SHA3_constants 
{
    meta:
        author = "spelissier"
        description = "SHA-3 (Keccak) round constants"
        date = "2020-04"
        version = "0.1"
    strings:
        $c0  = { 0080008000000080 }
        $c1  = { 0a00008000000080 }
        $c2  = { 8080000000000080 }
        $c3  = { 8b00000000000080 }
        $c4  = { 8280000000000000 }
        $c5  = { 8980000000000080 }
        $c6  = { 0880008000000080 }
        $c7  = { 0980008000000000 }
        $c8  = { 0280000000000080 }
        $c9  = { 0a00008000000000 }
        $c10 = { 0380000000000080 }
        $c11 = { 8b80000000000000 }
        $c12 = { 0100008000000000 }
        $c13 = { 0a80000000000000 }
        $c14 = { 0980000000000080 }
        $c15 = { 8000000000000080 }
        $c16 = { 8800000000000000 }
        $c17 = { 8b80008000000000 }
        $c18 = { 8a00000000000000 }
        $c19 = { 8180008000000080 }
        $c20 = { 0100000000000000 }
        $c21 = { 8a80000000000080 }
    condition:
        10 of them
}

rule SHA3_interleaved
{
    meta:
        author = "spelissier"
        description = "SHA-3 (Keccak) interleaved round constants"
        date = "2020-04"
        version = "0.1"
    strings:
        $c0  = { 010000008b800000 }
        $c1  = { 0000000081000080 }
        $c2  = { 0000000088000080 }
        $c3  = { 000000000b000000 }
        $c4  = { 0100000000800000 }
        $c5  = { 010000008b000000 }
        $c6  = { 0100000082800000 }
        $c7  = { 0000000003800000 }
        $c8  = { 010000008a000080 }
        $c9  = { 0000000082800080 }
        $c10 = { 0000000003800080 }
        $c11 = { 000000008b000080 }
        $c12 = { 0000000083000000 }
        $c13 = { 000000000a000000 }
        $c14 = { 0000000080800080 }
        $c15 = { 0100000082000080 }
        $c16 = { 010000000b000080 }
        $c17 = { 0100000088800080 }
        $c18 = { 0000000008000080 }
        $c19 = { 0100000000000000 }
        $c20 = { 0000000089000000 }
        $c21 = { 0100000081000080 }
    condition:
        10 of them
}

rule SipHash_big_endian_constants
{
    meta:
        author = "spelissier"
        description = "Look for SipHash constants in big endian"
        date = "2020-07"
        reference = "https://131002.net/siphash/siphash.pdf#page=6"
    strings:
        $c0 = "uespemos"
        $c1 = "modnarod"
        $c2 = "arenegyl"
        $c3 = "setybdet"
    condition:
        2 of them
}
