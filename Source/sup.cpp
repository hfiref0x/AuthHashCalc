/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.03
*
*  DATE:        26 Oct 2021
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

#define PE_SIGNATURE_SIZE 4
//
// Major copy-paste.
//
#define MM_SIZE_OF_LARGEST_IMAGE ((ULONG)0x77000000)
#define MM_MAXIMUM_IMAGE_HEADER (2 * PAGE_SIZE)
#define MM_MAXIMUM_IMAGE_SECTIONS                       \
     ((MM_MAXIMUM_IMAGE_HEADER - (PAGE_SIZE + sizeof(IMAGE_NT_HEADERS))) /  \
            sizeof(IMAGE_SECTION_HEADER))

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

    ViewInformation->LastError = IMAGE_VERIFY_OK;
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

    ntStatus = supxInitializeFileViewInfo(ViewInformation);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

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

    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
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

#pragma warning(push)
#pragma warning(disable: 4319)

/*
* supxValidateNtHeader
*
* Purpose:
*
* Common validation for file image header.
*
*/
BOOLEAN supxValidateNtHeader(
    _In_ PIMAGE_NT_HEADERS Header,
    _Out_ PDWORD ErrorCode
)
{
    INT i;
    ULONG64 lastSectionVA;
    PIMAGE_NT_HEADERS32 pHdr32;
    PIMAGE_NT_HEADERS64 pHdr64;
    PIMAGE_SECTION_HEADER pSection;

    if (Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

        pHdr64 = PIMAGE_NT_HEADERS64(Header);

        if (((pHdr64->OptionalHeader.FileAlignment & 511) != 0) &&
            (pHdr64->OptionalHeader.FileAlignment != pHdr64->OptionalHeader.SectionAlignment))
        {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_ALIGNMENT;
            return FALSE;
        }

        if (pHdr64->OptionalHeader.FileAlignment == 0) {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_ALIGNMENT;
            return FALSE;
        }

        if (((pHdr64->OptionalHeader.SectionAlignment - 1) &
            pHdr64->OptionalHeader.SectionAlignment) != 0)
        {
            *ErrorCode = IMAGE_VERIFY_BAD_SECTION_ALIGNMENT;
            return FALSE;
        }

        if (((pHdr64->OptionalHeader.FileAlignment - 1) &
            pHdr64->OptionalHeader.FileAlignment) != 0)
        {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_ALIGNMENT;
            return FALSE;
        }

        if (pHdr64->OptionalHeader.SectionAlignment < pHdr64->OptionalHeader.FileAlignment) {
            *ErrorCode = IMAGE_VERIFY_BAD_SECTION_ALIGNMENT;
            return FALSE;
        }

        if (pHdr64->OptionalHeader.SizeOfImage > MM_SIZE_OF_LARGEST_IMAGE) {
            *ErrorCode = IMAGE_VERIFY_BAD_SIZEOFIMAGE;
            return FALSE;
        }

        if (pHdr64->FileHeader.NumberOfSections > MM_MAXIMUM_IMAGE_SECTIONS) {
            *ErrorCode = IMAGE_VERIFY_BAD_SECTION_COUNT;
            return FALSE;
        }

        if (pHdr64->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 &&
            pHdr64->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
            pHdr64->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64)
        {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_HEADER_MACHINE;
            return FALSE;
        }

    }
    else if (Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

        pHdr32 = PIMAGE_NT_HEADERS32(Header);

        if (((pHdr32->OptionalHeader.FileAlignment & 511) != 0) &&
            (pHdr32->OptionalHeader.FileAlignment != pHdr32->OptionalHeader.SectionAlignment))
        {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_ALIGNMENT;
            return FALSE;
        }

        if (pHdr32->OptionalHeader.FileAlignment == 0) {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_ALIGNMENT;
            return FALSE;
        }

        if (((pHdr32->OptionalHeader.SectionAlignment - 1) &
            pHdr32->OptionalHeader.SectionAlignment) != 0)
        {
            *ErrorCode = IMAGE_VERIFY_BAD_SECTION_ALIGNMENT;
            return FALSE;
        }

        if (((pHdr32->OptionalHeader.FileAlignment - 1) &
            pHdr32->OptionalHeader.FileAlignment) != 0)
        {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_ALIGNMENT;
            return FALSE;
        }

        if (pHdr32->OptionalHeader.SectionAlignment < pHdr32->OptionalHeader.FileAlignment) {
            *ErrorCode = IMAGE_VERIFY_BAD_SECTION_ALIGNMENT;
            return FALSE;
        }

        if (pHdr32->OptionalHeader.SizeOfImage > MM_SIZE_OF_LARGEST_IMAGE) {
            *ErrorCode = IMAGE_VERIFY_BAD_SIZEOFIMAGE;
            return FALSE;
        }

        if (pHdr32->FileHeader.NumberOfSections > MM_MAXIMUM_IMAGE_SECTIONS) {
            *ErrorCode = IMAGE_VERIFY_BAD_SECTION_COUNT;
            return FALSE;
        }

        if (pHdr32->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 &&
            pHdr32->FileHeader.Machine != IMAGE_FILE_MACHINE_ARMNT)
        {
            *ErrorCode = IMAGE_VERIFY_BAD_FILE_HEADER_MACHINE;
            return FALSE;
        }

    }
    else {
        *ErrorCode = IMAGE_VERIFY_BAD_OPTIONAL_HEADER_MAGIC;
        return FALSE;
    }

    pSection = IMAGE_FIRST_SECTION(Header);

    lastSectionVA = (ULONG64)pSection->VirtualAddress;

    for (i = 0; i < Header->FileHeader.NumberOfSections; i++, pSection++) {

        if (pSection->VirtualAddress != lastSectionVA) {
            *ErrorCode = IMAGE_VERIFY_BAD_NTHEADERS;
            return FALSE;
        }

        lastSectionVA += ALIGN_UP_BY(pSection->Misc.VirtualSize,
            Header->OptionalHeader.SectionAlignment);

    }

    if (lastSectionVA != Header->OptionalHeader.SizeOfImage) {
        *ErrorCode = IMAGE_VERIFY_BAD_NTHEADERS;
        return FALSE;
    }

    *ErrorCode = IMAGE_VERIFY_OK;
    return TRUE;
}

#pragma warning(pop)

/*
* supIsValidImage
*
* Purpose:
*
* Check whatever image is in valid PE format.
*
*/
BOOLEAN supIsValidImage(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ViewInformation->ViewBase;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    ViewInformation->LastError = IMAGE_VERIFY_UNKNOWN_ERROR;

    __try {

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_DOSMAGIC;
            return FALSE;
        }

        if (dosHeader->e_lfanew == 0 ||
            (ULONG)dosHeader->e_lfanew > ViewInformation->FileSize.LowPart ||
            (((ULONG)dosHeader->e_lfanew + PE_SIGNATURE_SIZE +
                (ULONG)sizeof(IMAGE_FILE_HEADER)) >= ViewInformation->FileSize.LowPart) ||
            dosHeader->e_lfanew >= RTLP_IMAGE_MAX_DOS_HEADER)
        {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_NEWEXE;
            return FALSE;
        }

        if (((ULONG)dosHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS) +
            (16 * sizeof(IMAGE_SECTION_HEADER))) <= (ULONG)dosHeader->e_lfanew)
        {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_NEWEXE;
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ViewInformation->ViewBase + (ULONG)dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_NTSIGNATURE;
            return FALSE;
        }

        if ((ULONG)dosHeader->e_lfanew >= ntHeaders->OptionalHeader.SizeOfImage) {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_NEWEXE;
            return FALSE;
        }

        if (ntHeaders->FileHeader.SizeOfOptionalHeader == 0 ||
            ntHeaders->FileHeader.SizeOfOptionalHeader & (sizeof(ULONG_PTR) - 1))
        {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_OPTIONAL_HEADER;
            return FALSE;
        }

        if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_FILE_HEADER_CHARACTERISTICS;
            return FALSE;
        }

        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
            ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 &&
            ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 &&
            ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 &&
            ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_ARMNT)
        {
            ViewInformation->LastError = IMAGE_VERIFY_BAD_FILE_HEADER_MACHINE;
            return FALSE;
        }

        return supxValidateNtHeader(ntHeaders, &ViewInformation->LastError);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ViewInformation->LastError = IMAGE_VERIFY_EXCEPTION_IN_PROCESS;
        return FALSE;
    }
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

LPCWSTR supImageVerifyErrorToString(
    _In_ DWORD LastError
)
{
    switch (LastError) {
    case IMAGE_VERIFY_OK:
        return TEXT("OK");
    case IMAGE_VERIFY_BAD_NTSIGNATURE:
        return TEXT("Bad NT signature value");
    case IMAGE_VERIFY_BAD_OPTIONAL_HEADER:
        return TEXT("Bad optional header");
    case IMAGE_VERIFY_BAD_OPTIONAL_HEADER_MAGIC:
        return TEXT("Bad optional header magic value");
    case IMAGE_VERIFY_BAD_FILE_HEADER_MAGIC:
        return TEXT("Bad file header magic value");
    case IMAGE_VERIFY_BAD_FILE_HEADER_CHARACTERISTICS:
        return TEXT("Bad file header characteristics value");
    case IMAGE_VERIFY_BAD_FILE_HEADER_MACHINE:
        return TEXT("Bad file header machine value");
    case IMAGE_VERIFY_BAD_NTHEADERS:
        return TEXT("Bad NtHeaders");
    case IMAGE_VERIFY_BAD_FILE_ALIGNMENT:
        return TEXT("Bad file alignment");
    case IMAGE_VERIFY_BAD_SECTION_ALIGNMENT:
        return TEXT("Bad section alignment");
    case IMAGE_VERIFY_BAD_SIZEOFHEADERS:
        return TEXT("Bad SizeOfHeaders");
    case IMAGE_VERIFY_BAD_SIZEOFIMAGE:
        return TEXT("Bad SizeOfImage");
    case IMAGE_VERIFY_BAD_NEWEXE:
        return TEXT("Bad NewExe value");
    case IMAGE_VERIFY_BAD_DOSMAGIC:
        return TEXT("Bad DOS magic value");
    case IMAGE_VERIFY_EXCEPTION_IN_PROCESS:
        return TEXT("Exception while processing input file");
    case IMAGE_VERIFY_BAD_SECTION_COUNT:
        return TEXT("Bad number of sections in file");
    case IMAGE_VERIFY_BAD_SECURITY_DIRECTORY_VA:
        return TEXT("Invalid security directory virtual address");
    case IMAGE_VERIFY_BAD_SECURITY_DIRECTORY_SIZE:
        return TEXT("Invalid security directory size");

    default:
        return TEXT("Unknown Error");
    }
}
