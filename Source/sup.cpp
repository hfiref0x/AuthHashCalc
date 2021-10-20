/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Oct 2021
*
*  Program global support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

__inline WCHAR nibbletoh(BYTE c, BOOLEAN upcase)
{
    if (c < 10)
        return L'0' + c;

    c -= 10;

    if (upcase)
        return L'A' + c;

    return L'a' + c;
}

/*
* supPrintHash
*
* Purpose:
*
* Output hash.
* Returned buffer must be freed with supHeapFree when no longer needed.
*
*/
LPWSTR supPrintHash(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex
)
{
    ULONG   c;
    PWCHAR  lpText;
    BYTE    x;

    lpText = (LPWSTR)supHeapAlloc(sizeof(WCHAR) + ((SIZE_T)Length * 2 * sizeof(WCHAR)));
    if (lpText) {

        for (c = 0; c < Length; ++c) {
            x = Buffer[c];

            lpText[c * 2] = nibbletoh(x >> 4, UpcaseHex);
            lpText[c * 2 + 1] = nibbletoh(x & 15, UpcaseHex);
        }

        lpText[Length * 2] = 0;
    }

    return lpText;
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap.
*
*/
PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap.
*
*/
BOOL supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

/*
* supClipboardCopy
*
* Purpose:
*
* Copy text to the clipboard.
*
*/
VOID supClipboardCopy(
    _In_ LPCWSTR lpText,
    _In_ SIZE_T cbText
)
{
    LPWSTR  lptstrCopy;
    HGLOBAL hglbCopy;
    SIZE_T  dwSize;

    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        dwSize = cbText + sizeof(UNICODE_NULL);
        hglbCopy = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, dwSize);
        if (hglbCopy != NULL) {
            lptstrCopy = (LPWSTR)GlobalLock(hglbCopy);
            if (lptstrCopy) {
                StringCbCopy(lptstrCopy, dwSize, lpText);
            }
            GlobalUnlock(hglbCopy);
            if (!SetClipboardData(CF_UNICODETEXT, hglbCopy))
                GlobalFree(hglbCopy);
        }
        CloseClipboard();
    }
}

/*
* supUnmapFileSection
*
* Purpose:
*
* Unmap previously mapped file section.
*
*/
VOID supUnmapFileSection(
    _In_ PVOID MappedSection
)
{
    NTSTATUS ntStatus = NtUnmapViewOfSection(NtCurrentProcess(),
        MappedSection);

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
}

/*
* supMapInputFileForRead
*
* Purpose:
*
* Create mapped section from input file.
*
*/
PVOID supMapInputFileForRead(
    _In_ LPCWSTR lpFileName,
    _Out_opt_ PSIZE_T lpFileSize
)
{
    HANDLE fileHandle, sectionHandle = NULL;
    PVOID pvImageBase = NULL;
    LARGE_INTEGER fileSize;
    SIZE_T viewSize;

    if (lpFileSize)
        *lpFileSize = 0;

    fileHandle = CreateFile(lpFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
        return NULL;

    do {

        fileSize.QuadPart = 0;
        if (!GetFileSizeEx(fileHandle, &fileSize))
            break;

        NTSTATUS ntStatus = NtCreateSection(
            &sectionHandle,
            SECTION_QUERY | SECTION_MAP_READ,
            NULL,
            &fileSize,
            PAGE_READONLY,
            SEC_COMMIT,
            fileHandle);

        if (!NT_SUCCESS(ntStatus)) {
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
            break;
        }

        viewSize = (SIZE_T)fileSize.QuadPart;

        ntStatus = NtMapViewOfSection(sectionHandle,
            NtCurrentProcess(),
            &pvImageBase,
            0,
            PAGE_SIZE,
            NULL,
            &viewSize,
            ViewUnmap,
            0,
            PAGE_READONLY);

        if (!NT_SUCCESS(ntStatus)) {
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
            break;
        }

        if (lpFileSize)
            *lpFileSize = (SIZE_T)fileSize.QuadPart;

    } while (FALSE);

    if (fileHandle != INVALID_HANDLE_VALUE)
        CloseHandle(fileHandle);

    if (sectionHandle != NULL)
        NtClose(sectionHandle);

    return pvImageBase;
}

/*
* supOpenDialogExecute
*
* Purpose:
*
* Display OpenDialog
*
*/
BOOL supOpenDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR OpenFileName,
    _In_ LPCWSTR lpDialogFilter
)
{
    OPENFILENAME tag1;

    RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAME));

    tag1.lStructSize = sizeof(OPENFILENAME);
    tag1.hwndOwner = OwnerWindow;
    tag1.lpstrFilter = lpDialogFilter;
    tag1.lpstrFile = OpenFileName;
    tag1.nMaxFile = MAX_PATH;
    tag1.lpstrInitialDir = NULL;
    tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    return GetOpenFileName(&tag1);
}

/*
* supDragAndDropResolveTarget
*
* Purpose:
*
* Resolve link target of drag & drop operation.
*
*/
BOOL supDragAndDropResolveTarget(
    _In_ HWND hwnd,
    _In_ LPWSTR lpszLinkFile,
    _In_ LPWSTR lpszLinkTarget,
    _In_ SIZE_T cchLinkTarget
)
{
    BOOL bResult = FALSE;
    IShellLink* psl = NULL;
    IPersistFile* ppf = NULL;
    WCHAR szGotPath[MAX_PATH + 1];

    if (FAILED(CoInitialize(NULL)))
        return FALSE;

    do {

        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IShellLink,
            (LPVOID*)&psl)))
        {
            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {

                if (SUCCEEDED(ppf->Load(lpszLinkFile, STGM_READ))) {

                    if (SUCCEEDED(psl->Resolve(hwnd, 0))) {

                        RtlSecureZeroMemory(szGotPath, sizeof(szGotPath));
                        if (SUCCEEDED(psl->GetPath(szGotPath,
                            ARRAYSIZE(szGotPath),
                            NULL,
                            SLGP_RAWPATH)))
                        {
                            StringCchCopy(lpszLinkTarget, cchLinkTarget, szGotPath);
                            bResult = TRUE;
                        }

                    }
                }
                ppf->Release();
            }
            psl->Release();
        }

    } while (FALSE);

    CoUninitialize();
    return bResult;
}

#define RTL_MEG                   (1024UL * 1024UL)
#define RTLP_IMAGE_MAX_DOS_HEADER (256UL * RTL_MEG)

/*
* supIsValidImage
*
* Purpose:
*
* Check whatever image is in valid PE format.
*
*/
BOOLEAN supIsValidImage(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    WORD wMachine, wMagic;

    __try {

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }

        if (dosHeader->e_lfanew == 0 ||
            (SIZE_T)dosHeader->e_lfanew > ImageSize ||
            dosHeader->e_lfanew >= RTLP_IMAGE_MAX_DOS_HEADER)
        {
            SetLastError(ERROR_BAD_FORMAT);
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return FALSE;
        }

        wMachine = ntHeaders->FileHeader.Machine;

        if ((wMachine != IMAGE_FILE_MACHINE_AMD64) &&
            (wMachine != IMAGE_FILE_MACHINE_I386))
        {
            SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
            return FALSE;
        }

        wMagic = ntHeaders->OptionalHeader.Magic;

        if (wMachine == IMAGE_FILE_MACHINE_I386) {
            if (wMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
                return FALSE;
            }
        }
        else {
            if (wMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
                return FALSE;
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

/*
* supGetFileExt
*
* Purpose:
*
* Return pointer to file extension in given path string.
*
*/
wchar_t* supGetFileExt(
    _In_ const wchar_t* f
)
{
    wchar_t* p = 0;

    if (f == 0)
        return 0;

    while (*f != (wchar_t)0) {
        if (*f == '.')
            p = (wchar_t*)f;
        f++;
    }

    if (p == 0)
        p = (wchar_t*)f;

    return p;
}
