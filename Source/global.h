/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.03
*
*  DATE:        26 Oct 2021
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

#pragma warning(disable: 4005)

#include <Windows.h>
#include <Windowsx.h>
#include <strsafe.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <VersionHelpers.h>
#include <ntstatus.h>
#include "ntos.h"
#include "resource.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Comctl32.lib")

typedef struct _CNG_CTX {
    PVOID Hash;
    PVOID HashObject;
    ULONG HashSize;
    ULONG HashObjectSize;
    BCRYPT_ALG_HANDLE AlgHandle;
    BCRYPT_HASH_HANDLE HashHandle;
    HANDLE HeapHandle;
} CNG_CTX, * PCNG_CTX;

typedef struct _FILE_EXCLUDE_DATA {
    ULONG ChecksumOffset;
    ULONG SecurityOffset;
    PIMAGE_DATA_DIRECTORY SecurityDirectory;
} FILE_EXCLUDE_DATA, * PFILE_EXCLUDE_DATA;

typedef struct _FILE_VIEW_INFO {
    DWORD LastError;
    LPCWSTR FileName;
    HANDLE FileHandle;
    HANDLE SectionHandle;
    PVOID ViewBase;
    SIZE_T ViewSize;
    LARGE_INTEGER FileSize;
    PIMAGE_NT_HEADERS NtHeaders;
    FILE_EXCLUDE_DATA ExcludeData;
} FILE_VIEW_INFO, * PFILE_VIEW_INFO;

#include "sup.h"
#include "hash.h"
