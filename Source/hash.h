/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       HASH.H
*
*  VERSION:     1.03
*
*  DATE:        26 Oct 2021
*
*  Hash support routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

NTSTATUS CreateHashContext(
    _In_ HANDLE HeapHandle,
    _In_ PCWSTR AlgId,
    _Out_ PCNG_CTX* Context);

VOID DestroyHashContext(
    _In_ PCNG_CTX Context);

BOOLEAN CalculateFirstPageHash(
    _In_ ULONG PageSize,
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ PCNG_CTX HashContext);

BOOLEAN CalculateAuthenticodeHash(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ PCNG_CTX HashContext);

NTSTATUS HashLoadFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap);

FORCEINLINE VOID HashUnloadFile(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    supDestroyFileViewInfo(ViewInformation);
}
