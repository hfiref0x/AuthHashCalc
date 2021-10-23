/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.03
*
*  DATE:        21 Oct 2021
*
*  AuthHashCalc main logic and entrypoint.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef struct _DLG_HASH_CTRL {
    HWND EditControl;
    HWND CheckBoxControl;
    UINT EditControlId;
    UINT CheckBoxControlId;
    UINT CopyControlId;
} DLG_HASH_CTRL, * PDLG_HASH_CTRL;

static DLG_HASH_CTRL g_UserHashControls[] = {
    { NULL, NULL, IDC_EDIT_MD5, IDC_CHECKMD5, IDC_BUTTON_COPY_MD5 },
    { NULL, NULL, IDC_EDIT_SHA1, IDC_CHECKSHA1, IDC_BUTTON_COPY_SHA1 },
    { NULL, NULL, IDC_EDIT_SHA256, IDC_CHECKSHA256, IDC_BUTTON_COPY_SHA256 },
    { NULL, NULL, IDC_EDIT_SHA384, IDC_CHECKSHA384, IDC_BUTTON_COPY_SHA384 },
    { NULL, NULL, IDC_EDIT_SHA512, IDC_CHECKSHA512, IDC_BUTTON_COPY_SHA512 },
    { NULL, NULL, IDC_EDIT_PH_SHA1, IDC_CHECKPH_SHA1, IDC_BUTTON_COPY_PHSHA1 },
    { NULL, NULL, IDC_EDIT_PH_SHA256, IDC_CHECKPH_SHA256, IDC_BUTTON_COPY_PHSHA256 }
};

#define UserHashControlsCount RTL_NUMBER_OF(g_UserHashControls)
#define UserHashControlPageHashSha256 (UserHashControlsCount - 1)
#define UserHashControlPageHashSha1 (UserHashControlsCount - 2)

#define PROGRAM_VERSION_MAJOR       1
#define PROGRAM_VERSION_MINOR       0
#define PROGRAM_VERSION_REVISION    1
#define PROGRAM_VERSION_BUILD       3

static HANDLE g_Heap;
static HINSTANCE g_hInstance;
static SYSTEM_INFO g_SystemInfo;

#define T_EMPTY_STRING TEXT("")

VOID OnBrowseClick(
    _In_ HWND hwndDlg);

VOID OnCalculateClick(
    _In_ HWND hwndDlg);

#define HashUnloadFile(ViewInformation) supDestroyFileViewInfo(ViewInformation)

/*
* HashLoadFile
*
* Purpose:
*
* Load PE file in memory and validate it structure
*
*/
BOOLEAN HashLoadFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap
)
{
    NTSTATUS ntStatus;
    DWORD lastError;

    ntStatus = supMapInputFileForRead(ViewInformation, PartialMap);
    if (!NT_SUCCESS(ntStatus)) {
        supDestroyFileViewInfo(ViewInformation);
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return FALSE;
    }

    if (!supIsValidImage(
        ViewInformation->ViewBase,
        ViewInformation->FileSize))
    {
        lastError = GetLastError();
        supDestroyFileViewInfo(ViewInformation);
        SetLastError(lastError);
        return FALSE;
    }

    ViewInformation->NtHeaders = RtlImageNtHeader(ViewInformation->ViewBase);
    if (ViewInformation->NtHeaders == NULL) {
        SetLastError(ERROR_BAD_FORMAT);
        supDestroyFileViewInfo(ViewInformation);
        return FALSE;
    }

    return TRUE;
}

/*
* HashGetExcludeRange
*
* Purpose:
*
* Retrieve data and offsets to be skipped during hash calculation
*
*/
BOOLEAN HashGetExcludeRange(
    _In_ PIMAGE_DOS_HEADER DosHeader,
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _Out_ PULONG ChecksumOffset,
    _Out_ PULONG SecurityDirectoryOffset,
    _Out_opt_ PIMAGE_DATA_DIRECTORY* DataDirectory
)
{
    BOOLEAN bResult = TRUE;
    ULONG securityOffset = 0, checksumOffset = 0;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;

    PIMAGE_OPTIONAL_HEADER64 opt64 = NULL;
    PIMAGE_OPTIONAL_HEADER32 opt32 = NULL;

    switch (NtHeaders->OptionalHeader.Magic) {

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

        checksumOffset = DosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.CheckSum);
        securityOffset = DosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        opt64 = (PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader;
        dataDirectory = &opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

        break;

    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

        checksumOffset = DosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.CheckSum);
        securityOffset = DosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        opt32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader;
        dataDirectory = &opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

        break;

    default:
        break;
    }

    *ChecksumOffset = checksumOffset;
    *SecurityDirectoryOffset = securityOffset;

    if (DataDirectory)
        *DataDirectory = dataDirectory;

    return bResult;
}

/*
* HashGetSizeOfHeaders
*
* Purpose:
*
* Return PE OptionalHeader size of headers
*
*/
DWORD HashGetSizeOfHeaders(
    _In_ PIMAGE_NT_HEADERS NtHeaders
)
{
    PIMAGE_OPTIONAL_HEADER64 opt64;
    PIMAGE_OPTIONAL_HEADER32 opt32;

    switch (NtHeaders->OptionalHeader.Magic) {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        opt64 = (PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader;
        return opt64->SizeOfHeaders;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        opt32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader;
        return opt32->SizeOfHeaders;
    }

    return 0;
}

/*
* CreateHashContext
*
* Purpose:
*
* Allocate CNG context for given algorithm
*
*/
PCNG_CTX CreateHashContext(
    _In_ PCWSTR lpAlgId
)
{
    ULONG cbResult = 0;
    PCNG_CTX context;

    context = (PCNG_CTX)HeapAlloc(g_Heap,
        HEAP_ZERO_MEMORY, sizeof(CNG_CTX));

    if (context == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    do {

        NTSTATUS ntStatus;

        ntStatus = BCryptOpenAlgorithmProvider(&context->AlgHandle,
            lpAlgId,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus)) {
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
            break;
        }

        ntStatus = BCryptGetProperty(context->AlgHandle,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&context->HashObjectSize,
            sizeof(ULONG),
            &cbResult,
            0);

        if (!NT_SUCCESS(ntStatus)) {
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
            break;
        }

        ntStatus = BCryptGetProperty(context->AlgHandle,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&context->HashSize,
            sizeof(ULONG),
            &cbResult,
            0);

        if (!NT_SUCCESS(ntStatus)) {
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
            break;
        }

        context->HashObject = (PVOID)HeapAlloc(g_Heap,
            HEAP_ZERO_MEMORY,
            context->HashObjectSize);

        if (context->HashObject == NULL) {
            SetLastError(ERROR_OUTOFMEMORY);
            break;
        }

        context->Hash = (PVOID)HeapAlloc(g_Heap,
            HEAP_ZERO_MEMORY,
            context->HashSize);

        if (context->Hash == NULL) {
            SetLastError(ERROR_OUTOFMEMORY);
            break;
        }

        ntStatus = BCryptCreateHash(context->AlgHandle,
            &context->HashHandle,
            (PUCHAR)context->HashObject,
            context->HashObjectSize,
            NULL,
            0,
            0);

        if (!NT_SUCCESS(ntStatus)) {
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
            break;
        }

        return context;

    } while (FALSE);

    if (context->Hash) HeapFree(g_Heap, 0, context->Hash);
    if (context->HashObject) HeapFree(g_Heap, 0, context->HashObject);
    HeapFree(g_Heap, 0, context);

    return NULL;
}

/*
* DestroyHashContext
*
* Purpose:
*
* Release all resources allocated for CNG context
*
*/
VOID DestroyHashContext(
    _In_ PCNG_CTX Context
)
{
    BCryptCloseAlgorithmProvider(Context->AlgHandle, 0);

    if (Context->HashHandle)
        BCryptDestroyHash(Context->HashHandle);
    if (Context->Hash)
        HeapFree(g_Heap, 0, Context->Hash);
    if (Context->HashObject)
        HeapFree(g_Heap, 0, Context->HashObject);

    HeapFree(g_Heap, 0, Context);
}

/*
* CalculateFirstPageHash
*
* Purpose:
*
* Compute page hash for PE headers (WDAC compliant)
*
*/
BOOLEAN CalculateFirstPageHash(
    _In_ PVOID ImageBase,
    _In_ LARGE_INTEGER EndOfFile,
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ DWORD SizeOfHeaders,
    _In_ PCNG_CTX HashContext
)
{
    ULONG securityOffset, checksumOffset, cbInput;
    ULONG fileOffset = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BOOLEAN bOk = FALSE;

    SetLastError(ERROR_BAD_FORMAT);

    if (!HashGetExcludeRange((PIMAGE_DOS_HEADER)ImageBase,
        NtHeaders,
        &checksumOffset,
        &securityOffset,
        NULL))
    {
        return FALSE;
    }

    __try {

        //
        // Handle checksum offset.
        //
        cbInput = checksumOffset;

        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)ImageBase, cbInput, 0);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        //
        // Handle security offset.
        //
        fileOffset = checksumOffset +
            RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER, CheckSum);

        cbInput = securityOffset - fileOffset;

        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), cbInput, 0);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        fileOffset = securityOffset +
            sizeof(IMAGE_DATA_DIRECTORY);

        cbInput = SizeOfHeaders - fileOffset;

        //
        // Handle rest of the headers.
        //
        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), cbInput, 0);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        fileOffset = SizeOfHeaders;
        cbInput = EndOfFile.LowPart - fileOffset;

        //
        // Handle rest of the buffer.
        //
        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), cbInput, 0);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        ntStatus = BCryptFinishHash(HashContext->HashHandle,
            (PUCHAR)HashContext->Hash,
            HashContext->HashSize,
            0);

        bOk = NT_SUCCESS(ntStatus);
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }
    __finally {

        if (AbnormalTermination())
            return FALSE;

    }

    return bOk;
}

/*
* CalculateAuthenticodeHash
*
* Purpose:
*
* Compute authenticode hash for image file
*
*/
BOOLEAN CalculateAuthenticodeHash(
    _In_ PVOID ImageBase,
    _In_ LARGE_INTEGER EndOfFile,
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ PCNG_CTX HashContext
)
{
    ULONG securityOffset, checksumOffset;
    ULONG fileOffset = 0;
    PIMAGE_DATA_DIRECTORY dataDirectory;
    BOOLEAN bOk = FALSE;
    NTSTATUS ntStatus;

    SetLastError(ERROR_BAD_FORMAT);

    if (!HashGetExcludeRange((PIMAGE_DOS_HEADER)ImageBase,
        NtHeaders,
        &checksumOffset,
        &securityOffset,
        &dataDirectory))
    {
        return FALSE;
    }

    __try {

        while (fileOffset < checksumOffset) {

            ntStatus = BCryptHashData(HashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), sizeof(BYTE), 0);

            if (!NT_SUCCESS(ntStatus))
                __leave;

            fileOffset++;
        }


        fileOffset += RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER, CheckSum);

        while (fileOffset < securityOffset) {

            ntStatus = BCryptHashData(HashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), sizeof(BYTE), 0);

            if (!NT_SUCCESS(ntStatus))
                __leave;

            fileOffset++;
        }

        fileOffset += sizeof(IMAGE_DATA_DIRECTORY);

        while (fileOffset < dataDirectory->VirtualAddress) {

            ntStatus = BCryptHashData(HashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), sizeof(BYTE), 0);

            if (!NT_SUCCESS(ntStatus))
                __leave;

            fileOffset++;
        }

        fileOffset += dataDirectory->Size;

        while (fileOffset < EndOfFile.LowPart) {

            ntStatus = BCryptHashData(HashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(ImageBase, fileOffset), sizeof(BYTE), 0);

            if (!NT_SUCCESS(ntStatus))
                __leave;

            fileOffset++;
        }

        ntStatus = BCryptFinishHash(HashContext->HashHandle,
            (PUCHAR)HashContext->Hash,
            HashContext->HashSize,
            0);

        bOk = NT_SUCCESS(ntStatus);
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));

    }
    __finally {

        if (AbnormalTermination())
            return FALSE;

    }

    return bOk;
}

LPWSTR ComputeAuthenticodeHashForFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ LPCWSTR lpAlgId
)
{
    PCNG_CTX hashContext;
    LPWSTR lpszHash = NULL;

    hashContext = CreateHashContext(lpAlgId);
    if (hashContext) {

        if (CalculateAuthenticodeHash(
            ViewInformation->ViewBase,
            ViewInformation->FileSize,
            ViewInformation->NtHeaders,
            hashContext))
        {
            lpszHash = (LPWSTR)supPrintHash((PUCHAR)hashContext->Hash,
                hashContext->HashSize,
                TRUE);
        }

        DestroyHashContext(hashContext);
    }

    return lpszHash;
}

LPWSTR ComputeHeaderPageHashForFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ LPCWSTR lpAlgId
)
{
    PCNG_CTX hashContext;
    LPWSTR lpszHash = NULL;
    UCHAR* buffer;
    LARGE_INTEGER fsz;
    DWORD sizeOfHeaders;

    sizeOfHeaders = HashGetSizeOfHeaders(ViewInformation->NtHeaders);
    if (sizeOfHeaders == 0 || sizeOfHeaders > g_SystemInfo.dwPageSize)
        return NULL;

    hashContext = CreateHashContext(lpAlgId);
    if (hashContext) {

        fsz.LowPart = g_SystemInfo.dwPageSize;
        buffer = (UCHAR*)supHeapAlloc(fsz.LowPart);
        if (buffer) {

            //
            // Copy headers only, leave rest with zeroes.
            //
            RtlCopyMemory(buffer,
                ViewInformation->ViewBase,
                sizeOfHeaders);

            if (CalculateFirstPageHash(
                buffer,
                fsz,
                ViewInformation->NtHeaders,
                sizeOfHeaders,
                hashContext))
            {
                lpszHash = (LPWSTR)supPrintHash((PUCHAR)hashContext->Hash,
                    hashContext->HashSize,
                    TRUE);
            }

            supHeapFree(buffer);
        }

        DestroyHashContext(hashContext);
    }

    return lpszHash;
}

VOID ResetUserHashControls()
{
    for (UINT i = 0; i < UserHashControlsCount; i++)
        SetWindowText(g_UserHashControls[i].EditControl, T_EMPTY_STRING);
}

VOID OnBrowseClick(
    _In_ HWND hwndDlg
)
{
    WCHAR szFileName[MAX_PATH + 1];
    LPCWSTR lpOpenDialogFilter =
        TEXT("Image files (*.exe; *.dll; *.sys)\0*.exe;*.dll;*.sys\0All files (*.*)\0*.*\0\0");

    RtlSecureZeroMemory(szFileName, sizeof(szFileName));
    if (supOpenDialogExecute(hwndDlg,
        szFileName,
        (LPCWSTR)lpOpenDialogFilter))
    {
        SetDlgItemText(hwndDlg, IDC_EDIT_FILE, szFileName);
        OnCalculateClick(hwndDlg);
    }
}

VOID ProcessFile(
    _In_ HWND hwndDlg,
    _In_ LPCWSTR lpFileName
)
{
    LPWSTR lpszHash;

    LPCWSTR cryptAlgoIdRef[] = {
        BCRYPT_MD5_ALGORITHM,
        BCRYPT_SHA1_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA384_ALGORITHM,
        BCRYPT_SHA512_ALGORITHM
    };

    FILE_VIEW_INFO fvi;

    //
    // Disable controls.
    //
    __try {
        EnableWindow(GetDlgItem(hwndDlg, IDC_BROWSE), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDOK), FALSE);

        RtlSecureZeroMemory(&fvi, sizeof(fvi));

        fvi.FileName = lpFileName;

        if (HashLoadFile(&fvi, FALSE)) {

            for (UINT i = 0; i < UserHashControlPageHashSha1; i++) {
                if (Button_GetCheck(g_UserHashControls[i].CheckBoxControl)) {
                    lpszHash = ComputeAuthenticodeHashForFile(&fvi, cryptAlgoIdRef[i]);
                    if (lpszHash) {
                        SetWindowText(g_UserHashControls[i].EditControl, lpszHash);
                        supHeapFree(lpszHash);
                    }
                    else {
                        SetWindowText(g_UserHashControls[i].EditControl, T_EMPTY_STRING);
                    }
                }
            }


            //
            // Page hashes (WDAC compliant, header only hash).
            //

            if (Button_GetCheck(g_UserHashControls[UserHashControlPageHashSha1].CheckBoxControl)) {

                lpszHash = ComputeHeaderPageHashForFile(&fvi, BCRYPT_SHA1_ALGORITHM);
                if (lpszHash) {

                    SetWindowText(g_UserHashControls[UserHashControlPageHashSha1].EditControl,
                        lpszHash);

                    supHeapFree(lpszHash);
                }

            }

            if (Button_GetCheck(g_UserHashControls[UserHashControlPageHashSha256].CheckBoxControl)) {

                lpszHash = ComputeHeaderPageHashForFile(&fvi, BCRYPT_SHA256_ALGORITHM);
                if (lpszHash) {

                    SetWindowText(g_UserHashControls[UserHashControlPageHashSha256].EditControl,
                        lpszHash);

                    supHeapFree(lpszHash);
                }

            }

            HashUnloadFile(&fvi);
        }

    }
    __finally {

        //
        // Re-enable controls.
        //
        EnableWindow(GetDlgItem(hwndDlg, IDC_BROWSE), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDOK), TRUE);
    }
}

VOID OnCalculateClick(
    _In_ HWND hwndDlg
)
{
    WCHAR szFileName[MAX_PATH + 1];

    RtlSecureZeroMemory(szFileName, sizeof(szFileName));
    if (!GetDlgItemText(hwndDlg, IDC_EDIT_FILE, szFileName, RTL_NUMBER_OF(szFileName))) {
        OnBrowseClick(hwndDlg);
        return;
    }

    ResetUserHashControls();
    ProcessFile(hwndDlg, szFileName);
}

/*
* OnDragAndDrop
*
* Purpose:
*
* WM_DROPFILES handler
*
*/
VOID OnDragAndDrop(
    _In_ HWND hwndDlg,
    _In_ HDROP fDrop
)
{
    WCHAR szFileName[MAX_PATH + 1];
    WCHAR szTargetName[MAX_PATH + 1];
    WCHAR* pszExt;

    RtlSecureZeroMemory(szFileName, sizeof(szFileName));
    if (DragQueryFile(fDrop, 0, szFileName, MAX_PATH)) {

        pszExt = supGetFileExt(szFileName);
        if (pszExt) {

            if (_wcsicmp(pszExt, TEXT(".lnk")) == 0) {

                szTargetName[0] = 0;
                if (supDragAndDropResolveTarget(hwndDlg,
                    szFileName,
                    szTargetName,
                    MAX_PATH))
                {
                    SetDlgItemText(hwndDlg, IDC_EDIT_FILE, szTargetName);
                    ProcessFile(hwndDlg, szTargetName);
                    goto DoFinish;
                }
            }
        }

        SetDlgItemText(hwndDlg, IDC_EDIT_FILE, szFileName);
        ProcessFile(hwndDlg, szFileName);
    }

DoFinish:
    DragFinish(fDrop);
}

/*
* OnCopyHashText
*
* Purpose:
*
* WM_COMMAND -> IDC_BUTTON_COPY_* shared handler
*
*/
VOID OnCopyHashText(
    _In_ UINT uidControl
)
{
    for (UINT i = 0; i < UserHashControlsCount; i++) {
        if (g_UserHashControls[i].CopyControlId == uidControl) {

            INT cch = GetWindowTextLength(g_UserHashControls[i].EditControl);

            if (cch) {

                LPWSTR lpText = (LPWSTR)supHeapAlloc((1 + (SIZE_T)cch) * sizeof(WCHAR));
                if (lpText) {
                    if (GetWindowText(g_UserHashControls[i].EditControl, lpText, 1 + cch))
                    {
                        supClipboardCopy(lpText, (cch * sizeof(WCHAR)));
                    }
                    supHeapFree(lpText);
                }

            }

            break;
        }
    }
}

/*
* OnInitDialog
*
* Purpose:
*
* WM_INITDIALOG handler
*
*/
VOID OnInitDialog(
    _In_ HWND hwndDlg
)
{
    SendMessage(GetDlgItem(hwndDlg, IDC_EDIT_FILE), EM_SETLIMITTEXT, MAX_PATH, 0);
    DragAcceptFiles(hwndDlg, TRUE);
    SetFocus(GetDlgItem(hwndDlg, IDOK));

    for (UINT i = 0; i < UserHashControlsCount; i++) {

        g_UserHashControls[i].EditControl =
            GetDlgItem(hwndDlg, g_UserHashControls[i].EditControlId);

        g_UserHashControls[i].CheckBoxControl =
            GetDlgItem(hwndDlg, g_UserHashControls[i].CheckBoxControlId);

        Button_SetCheck(g_UserHashControls[i].CheckBoxControl, TRUE);
    }

    HICON hIcon = (HICON)LoadImage(g_hInstance,
        MAKEINTRESOURCE(IDI_ICONMAIN),
        IMAGE_ICON,
        32, 32,
        0);

    if (hIcon) {
        SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
        SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
    }

}

/*
* OnShowWindow
*
* Purpose:
*
* WM_SHOWWINDOW handler
*
*/
VOID OnShowWindow(
    _In_ HWND hwndDlg
)
{
    SetFocus(GetDlgItem(hwndDlg, IDOK));
}

INT_PTR CALLBACK MainWindowProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:

        OnInitDialog(hwndDlg);
        break;

    case WM_SHOWWINDOW:
        if (wParam)
            OnShowWindow(hwndDlg);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case IDOK:
            OnCalculateClick(hwndDlg);
            break;

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case IDC_BROWSE:
            OnBrowseClick(hwndDlg);
            break;

        case IDC_BUTTON_COPY_MD5:
        case IDC_BUTTON_COPY_SHA1:
        case IDC_BUTTON_COPY_SHA256:
        case IDC_BUTTON_COPY_SHA384:
        case IDC_BUTTON_COPY_SHA512:
        case IDC_BUTTON_COPY_PHSHA1:
        case IDC_BUTTON_COPY_PHSHA256:
            OnCopyHashText(LOWORD(wParam));
            break;

        default:
            break;
        }
        break;

    case WM_DROPFILES:
        OnDragAndDrop(hwndDlg, (HDROP)wParam);
        break;

    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    default:
        return FALSE;

    }

    return TRUE;
}

/*
* RunGUI
*
* Purpose:
*
* GUI version launch handler.
*
*/
UINT RunGUI(
    _In_ HINSTANCE hInstance
)
{
    BOOL rv;
    UINT uResult = ERROR_SUCCESS;
    INITCOMMONCONTROLSEX ccex;
    MSG msg;
    HWND hwndDlg;

    ccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    ccex.dwICC = ICC_STANDARD_CLASSES;

    if (!InitCommonControlsEx(&ccex)) {
        return GetLastError();
    }

    hwndDlg = CreateDialogParam(hInstance,
        MAKEINTRESOURCE(IDD_MAINDLG),
        NULL,
        MainWindowProc,
        0);

    if (hwndDlg) {

        do {
            rv = GetMessage(&msg, NULL, 0, 0);

            if (rv == -1)
                break;

            if (!IsDialogMessage(hwndDlg, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

        } while (rv != 0);

    }
    else {
        uResult = GetLastError();
    }

    return uResult;
}

UINT ProcessFileCLI(
    _In_ LPCWSTR lpFileName,
    _In_ FILE* lpOutStream
)
{
    UINT uResult = ERROR_SUCCESS;
    LPWSTR lpszHash;
    LPCWSTR cryptAlgoIdRef[] = {
        BCRYPT_MD5_ALGORITHM,
        BCRYPT_SHA1_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA384_ALGORITHM,
        BCRYPT_SHA512_ALGORITHM
    };

    FILE_VIEW_INFO fvi;

    RtlSecureZeroMemory(&fvi, sizeof(fvi));

    fvi.FileName = lpFileName;

    if (HashLoadFile(&fvi, FALSE)) {

        //
        // Authenticode
        //

        fprintf_s(lpOutStream, "File: %ws\n\nAuthenticode hashes:\n", lpFileName);

        for (UINT i = 0; i < ARRAYSIZE(cryptAlgoIdRef); i++) {
            lpszHash = ComputeAuthenticodeHashForFile(&fvi, cryptAlgoIdRef[i]);
            if (lpszHash) {
                fprintf_s(lpOutStream, "%ws:\t%ws\n", cryptAlgoIdRef[i], lpszHash);
                supHeapFree(lpszHash);
            }
            else {
                fprintf_s(lpOutStream, "Error: empty hash %ws value\n", cryptAlgoIdRef[i]);
            }
        }

        //
        // Page hash
        //

        fprintf_s(lpOutStream, "\nFirst page hash:\n");

        LPCWSTR lpAlgId = BCRYPT_SHA1_ALGORITHM;

        lpszHash = ComputeHeaderPageHashForFile(&fvi, lpAlgId);
        if (lpszHash) {
            fprintf_s(lpOutStream, "%ws:\t%ws\n", lpAlgId, lpszHash);
            supHeapFree(lpszHash);
        }
        else {
            fprintf_s(lpOutStream, "Error: empty page hash %ws value\n", lpAlgId);
        }

        lpAlgId = BCRYPT_SHA256_ALGORITHM;

        lpszHash = ComputeHeaderPageHashForFile(&fvi, lpAlgId);
        if (lpszHash) {
            fprintf_s(lpOutStream, "%ws:\t%ws\n", lpAlgId, lpszHash);
            supHeapFree(lpszHash);
        }
        else {
            fprintf_s(lpOutStream, "Error: empty page hash %ws value\n", lpAlgId);
        }

        HashUnloadFile(&fvi);

    }

    return uResult;
}

/*
* RunCLI
*
* Purpose:
*
* CLI version launch handler.
*
*/
UINT RunCLI(
    _In_ LPCWSTR lpFileName,
    _In_opt_ LPCWSTR lpLogFileName
)
{
    UINT uResult;

#ifdef _DEBUG
    if (!AllocConsole()) {
        return GetLastError();
    }
#else
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        return GetLastError();
    }
#endif

    FILE* outStream;
    errno_t err;

    if (lpLogFileName) {
        err = _wfopen_s(&outStream, lpLogFileName, L"wt");
    }
    else {
        err = freopen_s(&outStream, "CONOUT$", "w", stdout);
    }

    if (err != 0 || outStream == NULL) {
        return (UINT)-3;
    }

    if (lpLogFileName) {
        uResult = ProcessFileCLI(lpFileName, outStream);
        fclose(outStream);
        return uResult;
    }

    fflush(stdout);

    fprintf_s(stdout, "\nAuthHashCalc v%u.%u.%u.%u built at %s\n\n",
        PROGRAM_VERSION_MAJOR,
        PROGRAM_VERSION_MINOR,
        PROGRAM_VERSION_REVISION,
        PROGRAM_VERSION_BUILD,
        __TIMESTAMP__);

    uResult = ProcessFileCLI(lpFileName, stdout);

    fprintf_s(stdout, "\nCompleted.");

    FreeConsole();
    return uResult;
}

BOOLEAN InitializeGlobals(
    _In_ HINSTANCE hInstance
)
{
    g_hInstance = hInstance;

    HeapSetInformation(GetProcessHeap(), HeapEnableTerminationOnCorruption, NULL, 0);

    g_Heap = HeapCreate(0, 0, 0);
    if (g_Heap == NULL)
        return FALSE;

    HeapSetInformation(g_Heap, HeapEnableTerminationOnCorruption, NULL, 0);

    RtlSecureZeroMemory(&g_SystemInfo, sizeof(g_SystemInfo));
    GetSystemInfo(&g_SystemInfo);

    return TRUE;
}

/*
* WinMain
*
* Purpose:
*
* Program entry point.
*
*/
int CALLBACK WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
)
{
    LPWSTR* szArglist;
    INT nArgs = 0;
    ULONG nRet = 0;
    LPCWSTR lpLogFile = NULL;

    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);


    if (!InitializeGlobals(hInstance)) {
        nRet = GetLastError();
        goto ExitProgram;
    }

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {

        if (nArgs > 1) {

            if (nArgs > 2)
                lpLogFile = szArglist[2];

            nRet = RunCLI(szArglist[1], lpLogFile);

        }
        else {

            nRet = RunGUI(hInstance);

        }

        LocalFree(szArglist);
    }
    else {

        nRet = RunGUI(hInstance);
    }

    HeapDestroy(g_Heap);

ExitProgram:
    ExitProcess(nRet);
}
