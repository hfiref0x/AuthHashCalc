/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       SUP.H
*
*  VERSION:     1.00
*
*  DATE:        01 Oct 2021
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

PVOID supHeapAlloc(
    _In_ SIZE_T Size);

BOOL supHeapFree(
    _In_ PVOID Memory);

VOID supClipboardCopy(
    _In_ LPCWSTR lpText,
    _In_ SIZE_T cbText);

VOID supUnmapFileSection(
    _In_ PVOID MappedSection);

PVOID supMapInputFileForRead(
    _In_ LPCWSTR lpFileName,
    _Out_opt_ PSIZE_T lpFileSize);

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
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize);

LPWSTR supPrintHash(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex);

wchar_t* supGetFileExt(
    _In_ const wchar_t* f);
