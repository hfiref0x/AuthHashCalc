/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.03
*
*  DATE:        21 Oct 2021
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

#define RTL_MEG                   (1024UL * 1024UL)
#define RTLP_IMAGE_MAX_DOS_HEADER (256UL * RTL_MEG)


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

VOID supDestroyFileViewInfo(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    if (ViewInformation->FileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(ViewInformation->FileHandle);
        ViewInformation->FileHandle = INVALID_HANDLE_VALUE;
    }
    if (ViewInformation->SectionHandle) {
        NtClose(ViewInformation->SectionHandle);
        ViewInformation->SectionHandle = NULL;
    }
    if (ViewInformation->ViewBase) {
        if (NT_SUCCESS(NtUnmapViewOfSection(NtCurrentProcess(),
            ViewInformation->ViewBase)))
        {
            ViewInformation->ViewBase = NULL;
            ViewInformation->ViewSize = 0;
        }
    }

    ViewInformation->NtHeaders = NULL;
    ViewInformation->FileSize.QuadPart = 0;
}

/*
* supxInitializeFileViewInfo
*
* Purpose:
*
* Open file for mapping, create section, remember file size.
*
*/
NTSTATUS supxInitializeFileViewInfo(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    HANDLE fileHandle, sectionHandle = NULL;
    LARGE_INTEGER fileSize;

    fileSize.QuadPart = 0;
    fileHandle = CreateFile(ViewInformation->FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_SUPPORTS_BLOCK_REFCOUNTING | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (fileHandle != INVALID_HANDLE_VALUE) {

        if (!GetFileSizeEx(fileHandle, &fileSize)) {
            CloseHandle(fileHandle);
            fileHandle = INVALID_HANDLE_VALUE;
            ntStatus = STATUS_FILE_INVALID;
        }
        else {

            ntStatus = NtCreateSection(
                &sectionHandle,
                SECTION_QUERY | SECTION_MAP_READ,
                NULL,
                &fileSize,
                PAGE_READONLY,
                SEC_COMMIT,
                fileHandle);

            if (!NT_SUCCESS(ntStatus)) {
                CloseHandle(fileHandle);
                fileHandle = INVALID_HANDLE_VALUE;
            }

        }

    }
    else {
        ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;
    }

    ViewInformation->FileHandle = fileHandle;
    ViewInformation->FileSize = fileSize;
    ViewInformation->SectionHandle = sectionHandle;

    return ntStatus;
}

/*
* supMapInputFileForRead
*
* Purpose:
*
* Create mapped section from input file.
*
*/
NTSTATUS supMapInputFileForRead(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap
)
{
    NTSTATUS ntStatus;
    SIZE_T viewSize;

    do {

        ntStatus = supxInitializeFileViewInfo(ViewInformation);
        if (!NT_SUCCESS(ntStatus))
            break;

        if (PartialMap) {

            if (ViewInformation->FileSize.QuadPart < RTL_MEG)
                viewSize = (SIZE_T)ViewInformation->FileSize.QuadPart;
            else
                viewSize = (SIZE_T)RTL_MEG;

        }
        else {

            viewSize = (SIZE_T)ViewInformation->FileSize.QuadPart;

        }

        ntStatus = NtMapViewOfSection(ViewInformation->SectionHandle,
            NtCurrentProcess(),
            &ViewInformation->ViewBase,
            0,
            0,
            NULL,
            &viewSize,
            ViewShare,
            0,
            PAGE_READONLY);

        if (NT_SUCCESS(ntStatus))
            ViewInformation->ViewSize = viewSize;


    } while (FALSE);

    return ntStatus;
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

//
// Major copy-paste.
//
#define MM_SIZE_OF_LARGEST_IMAGE ((ULONG)0x77000000)
#define MM_MAXIMUM_IMAGE_HEADER (2 * PAGE_SIZE)
#define MM_MAXIMUM_IMAGE_SECTIONS                       \
     ((MM_MAXIMUM_IMAGE_HEADER - (PAGE_SIZE + sizeof(IMAGE_NT_HEADERS))) /  \
            sizeof(IMAGE_SECTION_HEADER))

#define VALIDATE_NTHEADER(Hdr) {                                    \
    if (((((Hdr)->OptionalHeader).FileAlignment & 511) != 0) &&     \
        (((Hdr)->OptionalHeader).FileAlignment !=                   \
         ((Hdr)->OptionalHeader).SectionAlignment)) {               \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((Hdr)->OptionalHeader).FileAlignment == 0) {               \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((((Hdr)->OptionalHeader).SectionAlignment - 1) &           \
          ((Hdr)->OptionalHeader).SectionAlignment) != 0) {         \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((((Hdr)->OptionalHeader).FileAlignment - 1) &              \
          ((Hdr)->OptionalHeader).FileAlignment) != 0) {            \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((Hdr)->OptionalHeader).SectionAlignment < ((Hdr)->OptionalHeader).FileAlignment) { \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((Hdr)->OptionalHeader).SizeOfImage > MM_SIZE_OF_LARGEST_IMAGE) { \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if ((Hdr)->FileHeader.NumberOfSections > MM_MAXIMUM_IMAGE_SECTIONS) { \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((Hdr)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) && \
        !((Hdr)->FileHeader.Machine == IMAGE_FILE_MACHINE_I386))  { \
        return FALSE;                                               \
    }                                                               \
                                                                    \
    if (((Hdr)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) && \
        !(((Hdr)->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64) || \
          ((Hdr)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64))) { \
        return FALSE;                                               \
    }                                                               \
}

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
    _In_ LARGE_INTEGER EndOfFile
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    SetLastError(ERROR_BAD_EXE_FORMAT);

    __try {

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        if (dosHeader->e_lfanew == 0 ||
            (ULONG)dosHeader->e_lfanew > EndOfFile.LowPart ||
            dosHeader->e_lfanew >= RTLP_IMAGE_MAX_DOS_HEADER)
        {
            return FALSE;
        }

        if (((ULONG)dosHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS) +
            (16 * sizeof(IMAGE_SECTION_HEADER))) <= (ULONG)dosHeader->e_lfanew)
        {
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->FileHeader.SizeOfOptionalHeader == 0 ||
            ntHeaders->FileHeader.SizeOfOptionalHeader & (sizeof(ULONG_PTR) - 1))
        {
            return FALSE;
        }

        if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
            return FALSE;
        }

        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
            ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        {
            SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
            return FALSE;
        }

        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            VALIDATE_NTHEADER((PIMAGE_NT_HEADERS32)ntHeaders);
        }
        else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            VALIDATE_NTHEADER((PIMAGE_NT_HEADERS64)ntHeaders);
        }
        else
            return FALSE;

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
