/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       SUP.H
*
*  VERSION:     1.03
*
*  DATE:        26 Oct 2021
*
*  Support routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define IMAGE_VERIFY_OK                                 0
#define IMAGE_VERIFY_BAD_NTSIGNATURE                    1
#define IMAGE_VERIFY_BAD_OPTIONAL_HEADER                2
#define IMAGE_VERIFY_BAD_OPTIONAL_HEADER_MAGIC          3
#define IMAGE_VERIFY_BAD_FILE_HEADER_MAGIC              4
#define IMAGE_VERIFY_BAD_FILE_HEADER_CHARACTERISTICS    5
#define IMAGE_VERIFY_BAD_FILE_HEADER_MACHINE            6
#define IMAGE_VERIFY_BAD_NTHEADERS                      7
#define IMAGE_VERIFY_BAD_FILE_ALIGNMENT                 8
#define IMAGE_VERIFY_BAD_SECTION_ALIGNMENT              9
#define IMAGE_VERIFY_BAD_SIZEOFHEADERS                  10
#define IMAGE_VERIFY_BAD_SIZEOFIMAGE                    11
#define IMAGE_VERIFY_BAD_NEWEXE                         12
#define IMAGE_VERIFY_BAD_DOSMAGIC                       13
#define IMAGE_VERIFY_EXCEPTION_IN_PROCESS               14
#define IMAGE_VERIFY_BAD_SECTION_COUNT                  15
#define IMAGE_VERIFY_BAD_SECURITY_DIRECTORY_VA          16
#define IMAGE_VERIFY_BAD_SECURITY_DIRECTORY_SIZE        17

#define IMAGE_VERIFY_UNKNOWN_ERROR                      0xff

VOID supDestroyFileViewInfo(
    _In_ PFILE_VIEW_INFO ViewInformation);

PVOID supHeapAlloc(
    _In_ SIZE_T Size);

BOOL supHeapFree(
    _In_ PVOID Memory);

VOID supClipboardCopy(
    _In_ LPCWSTR lpText,
    _In_ SIZE_T cbText);

NTSTATUS supMapInputFileForRead(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap);

BOOL supOpenDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR OpenFileName,
    _In_ LPCWSTR lpDialogFilter);

BOOL supDragAndDropResolveTarget(
    _In_ HWND hwnd,
    _In_ LPWSTR lpszLinkFile,
    _In_ LPWSTR lpszLinkTarget,
    _In_ SIZE_T cchLinkTarget);

BOOLEAN supIsValidImage(
    _In_ PFILE_VIEW_INFO ViewInformation);

LPWSTR supPrintHash(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex);

wchar_t* supGetFileExt(
    _In_ const wchar_t* f);

LPCWSTR supImageVerifyErrorToString(
    _In_ DWORD LastError);
