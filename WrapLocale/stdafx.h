#pragma once

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>

#include <imm.h>
#include <DSound.h>
#include <shlwapi.h>

#pragma comment(lib, "Imm32.lib")
#pragma comment(lib, "Dsound.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shlwapi.lib")

#define MAP_CODEPAGE_TO_CHARSET(codePage, charSet) \
    { \
        switch (codePage) { \
            case 932:  /* Japanese */ \
                charSet = SHIFTJIS_CHARSET; \
                break; \
            case 936:  /* Simplified Chinese */ \
                charSet = GB2312_CHARSET; \
                break; \
            case 949:  /* Korean */ \
                charSet = HANGUL_CHARSET; \
                break; \
            case 950:  /* Traditional Chinese */ \
                charSet = CHINESEBIG5_CHARSET; \
                break; \
            case 1250: /* Central European */ \
                charSet = EASTEUROPE_CHARSET; \
                break; \
            case 1251: /* Cyrillic */ \
                charSet = RUSSIAN_CHARSET; \
                break; \
            case 1252: /* Western European */ \
                charSet = ANSI_CHARSET; \
                break; \
            case 1253: /* Greek */ \
                charSet = GREEK_CHARSET; \
                break; \
            case 1254: /* Turkish */ \
                charSet = TURKISH_CHARSET; \
                break; \
            case 1255: /* Hebrew */ \
                charSet = HEBREW_CHARSET; \
                break; \
            case 1256: /* Arabic */ \
                charSet = ARABIC_CHARSET; \
                break; \
            case 1257: /* Baltic */ \
                charSet = BALTIC_CHARSET; \
                break; \
            case 1258: /* Vietnamese */ \
                charSet = VIETNAMESE_CHARSET; \
                break; \
            default: \
                /* Keep original charset if no mapping exists */ \
                break; \
        } \
    }