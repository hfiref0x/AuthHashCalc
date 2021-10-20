/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.00
*
*  DATE:        01 Oct 2021
*
*  Common include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#include <Windows.h>
#include <Windowsx.h>
#include <strsafe.h>
#include <bcrypt.h>
#include <intrin.h>
#include <commctrl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <VersionHelpers.h>
#include "ntos.h"
#include "sup.h"
#include "resource.h"

typedef struct _CNG_CTX {
    PVOID Hash;
    PVOID HashObject;
    ULONG HashSize;
    ULONG HashObjectSize;
    BCRYPT_ALG_HANDLE AlgHandle;
    BCRYPT_HASH_HANDLE HashHandle;
} CNG_CTX, * PCNG_CTX;

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Comctl32.lib")
