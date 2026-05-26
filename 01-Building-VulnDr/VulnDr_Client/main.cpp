#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string.h>

#include "public.h"

static void PrintLastError(const wchar_t* Message)
{
    wprintf(L"[-] %ls failed. GetLastError()=%lu\n", Message, GetLastError());
}

static void PrintIoctlResult(
    const wchar_t* Name,
    BOOL Ok,
    DWORD BytesReturned
)
{
    if (Ok)
    {
        wprintf(L"[+] %ls succeeded. BytesReturned=%lu\n", Name, BytesReturned);
    }
    else
    {
        wprintf(
            L"[-] %ls failed safely. GetLastError()=%lu BytesReturned=%lu\n",
            Name,
            GetLastError(),
            BytesReturned
        );
    }
}

static void PrintBytesAsText(const unsigned char* Buffer, DWORD Size)
{
    for (DWORD i = 0; i < Size; i++)
    {
        unsigned char c = Buffer[i];

        if (c >= 0x20 && c <= 0x7E)
        {
            putchar(c);
        }
        else
        {
            putchar('.');
        }
    }

    putchar('\n');
}

static void TestFakeRegionReadWrite(HANDLE hDevice)
{
    BOOL ok;
    DWORD bytesReturned;
    VULNDR_FAKE_RW_REQUEST request;

    ZeroMemory(&request, sizeof(request));

    //
    // 1. Read first 48 bytes from fake kernel region
    //
    request.Offset = 0;
    request.Size = 48;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_SAFE_READ_FAKE_REGION,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!ok)
    {
        printf("[!] SAFE_READ_FAKE_REGION failed. GetLastError=%lu\n", GetLastError());
    }
    else
    {
        printf("[+] SAFE_READ_FAKE_REGION succeeded. BytesReturned=%lu\n", bytesReturned);
        printf("[+] Data: ");
        PrintBytesAsText(request.Data, request.Size);
    }

    //
    // 2. Write controlled data into fake kernel region
    //
    ZeroMemory(&request, sizeof(request));

    request.Offset = 0x20;
    request.Size = (ULONG)strlen("HELLO_FROM_USERMODE");

    memcpy(
        request.Data,
        "HELLO_FROM_USERMODE",
        request.Size
    );

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_SAFE_WRITE_FAKE_REGION,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!ok)
    {
        printf("[!] SAFE_WRITE_FAKE_REGION failed. GetLastError=%lu\n", GetLastError());
    }
    else
    {
        printf("[+] SAFE_WRITE_FAKE_REGION succeeded. BytesReturned=%lu\n", bytesReturned);
    }

    //
    // 3. Read back from same offset to confirm write worked
    //
    ZeroMemory(&request, sizeof(request));

    request.Offset = 0x20;
    request.Size = 32;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_SAFE_READ_FAKE_REGION,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!ok)
    {
        printf("[!] SAFE_READ_FAKE_REGION read-back failed. GetLastError=%lu\n", GetLastError());
    }
    else
    {
        printf("[+] SAFE_READ_FAKE_REGION read-back succeeded. BytesReturned=%lu\n", bytesReturned);
        printf("[+] Data: ");
        PrintBytesAsText(request.Data, request.Size);
    }
}

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
        PrintLastError(L"CreateFileW");
        return 1;
    }

    wprintf(L"[+] Driver handle opened successfully\n");

    DWORD bytesReturned = 0;

    VULNDR_VERSION_INFO versionInfo = { 0 };

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_GET_VERSION,
        nullptr,
        0,
        &versionInfo,
        sizeof(versionInfo),
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintLastError(L"DeviceIoControl(IOCTL_VULNDR_GET_VERSION)");
    }
    else
    {
        wprintf(L"\n[+] IOCTL_VULNDR_GET_VERSION succeeded\n");
        wprintf(L"    Version: %lu.%lu.%lu\n", versionInfo.Major, versionInfo.Minor, versionInfo.Build);
        wprintf(L"    Message: %ls\n", versionInfo.Message);
        wprintf(L"    Bytes returned: %lu\n", bytesReturned);
    }

    VULNDR_ECHO_REQUEST echoRequest = { 0 };

    const char* message = "Hello, World!";

    echoRequest.InputLength = (unsigned long)strlen(message);

    strcpy_s(
        echoRequest.Input,
        sizeof(echoRequest.Input),
        message
    );

    bytesReturned = 0;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_ECHO,
        &echoRequest,
        sizeof(echoRequest),
        &echoRequest,
        sizeof(echoRequest),
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintLastError(L"DeviceIoControl(IOCTL_VULNDR_ECHO)");
    }
    else
    {
        wprintf(L"\n[+] IOCTL_VULNDR_ECHO succeeded\n");
        printf("    Echo: %s\n", echoRequest.Input);
        wprintf(L"    InputLength: %lu\n", echoRequest.InputLength);
        wprintf(L"    Bytes returned: %lu\n", bytesReturned);
    }

    VULNDR_STATS stats = { 0 };
    bytesReturned = 0;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_GET_STATS,
        nullptr,
        0,
        &stats,
        sizeof(stats),
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintLastError(L"DeviceIoControl(IOCTL_VULNDR_GET_STATS)");
    }
    else
    {
        wprintf(L"\n[+] IOCTL_VULNDR_GET_STATS succeeded\n");
        wprintf(L"    Total IOCTLs handled: %ld\n", stats.TotalIoctlsHandled);
        wprintf(L"    Bytes returned: %lu\n", bytesReturned);
    }

    TestFakeRegionReadWrite(hDevice);

    CloseHandle(hDevice);

    wprintf(L"\n[+] Driver handle closed\n");

    return 0;
}